/**
 * GitLab CI layer analyzer (0034, offline).
 *
 * Emits the same provider-agnostic graph nodes as the GitHub analyzer — a `ci-job`
 * (tagged `provider: 'gitlab'`), a secret sink per credential-looking CI/CD variable
 * a job references, and a fork/untrusted `entry` for a job triggerable by a merge
 * request. The cross-layer install-script path (a dependency `runs-in` a job) is the
 * engine's job, so a Gemfile.lock/requirements.txt diff composes with a GitLab
 * `bundle install` / `pip install` job exactly as it does on GitHub.
 *
 * GitLab's model differs from GitHub's in ways that matter:
 * - **Triggers** come from `rules:` / `only:` — a job gated on
 *   `$CI_PIPELINE_SOURCE == "merge_request_event"` (or `only: [merge_requests]`) can
 *   be triggered by an MR, potentially from a fork (the untrusted analog of
 *   `pull_request_target`).
 * - **Secrets** are CI/CD variables (defined in project/group settings, not the
 *   file) referenced as `$VAR`. GitLab's *protected* variables are withheld from
 *   fork-MR pipelines, which is real protection — so this is modeled as the
 *   reachable shape a reviewer must confirm, and the finding names the variable.
 */

import { parse } from 'yaml';
import type { AttackNode } from '../../graph/types';
import { isInstallCommand } from '../ci/parse';
import { type AnalyzerResult, emptyResult } from '../types';

export interface GitlabCiInputs {
  /** `.gitlab-ci.yml` contents. */
  content: string;
}

/** Top-level keys that are configuration, not jobs. */
const RESERVED = new Set([
  'stages',
  'variables',
  'default',
  'workflow',
  'include',
  'image',
  'services',
  'before_script',
  'after_script',
  'cache',
]);

const CREDENTIAL_HINT = /(AWS|TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i;

function sinkKindFor(name: string): 'secret' | 'credential' {
  return CREDENTIAL_HINT.test(name) ? 'credential' : 'secret';
}

/** Flatten a `script` / `before_script` field (string or array) into command lines. */
function scriptLines(job: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['before_script', 'script', 'after_script']) {
    const v = job[key];
    if (typeof v === 'string') {
      out.push(v);
    } else if (Array.isArray(v)) {
      out.push(...v.filter((x): x is string => typeof x === 'string'));
    }
  }
  return out;
}

/**
 * Credential-looking CI/CD variables a job references (`$VAR` / `${VAR}`) in its
 * scripts or `variables:`. GitLab predefined `CI_*` variables are excluded — a
 * project's own secret is not named `CI_...`; this keeps CI_PIPELINE_SOURCE and
 * friends from being read as secrets.
 */
function referencedSecretVars(job: Record<string, unknown>): string[] {
  const names = new Set<string>();
  const haystack = [...scriptLines(job)];
  const vars = job.variables;
  if (vars && typeof vars === 'object') {
    for (const val of Object.values(vars as Record<string, unknown>)) {
      if (typeof val === 'string') {
        haystack.push(val);
      }
    }
  }
  const re = /\$\{?([A-Z_][A-Z0-9_]*)\}?/g;
  for (const line of haystack) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      const name = m[1]!;
      if (!name.startsWith('CI_') && CREDENTIAL_HINT.test(name)) {
        names.add(name);
      }
    }
  }
  return [...names];
}

/** True if the job is triggerable by a merge request (the fork-untrusted analog). */
function isMergeRequestTriggerable(job: Record<string, unknown>): boolean {
  const only = job.only;
  if (typeof only === 'string' && /merge_request/.test(only)) {
    return true;
  }
  if (Array.isArray(only) && only.some((o) => typeof o === 'string' && /merge_request/.test(o))) {
    return true;
  }
  const rules = job.rules;
  if (Array.isArray(rules)) {
    for (const rule of rules) {
      if (rule && typeof rule === 'object') {
        const cond = (rule as { if?: unknown }).if;
        if (typeof cond === 'string' && /merge_request/.test(cond)) {
          return true;
        }
      }
    }
  }
  return false;
}

/** True if any script line runs a dependency install (for the cross-layer edge). */
function runsInstall(job: Record<string, unknown>): boolean {
  return scriptLines(job).some(isInstallCommand);
}

export function analyzeGitlabCi(inputs: GitlabCiInputs): AnalyzerResult {
  const result = emptyResult();

  let doc: Record<string, unknown>;
  try {
    doc = (parse(inputs.content) ?? {}) as Record<string, unknown>;
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse .gitlab-ci.yml: ${(err as Error).message}`,
    });
    return result;
  }

  for (const [name, val] of Object.entries(doc)) {
    if (RESERVED.has(name) || name.startsWith('.') || !val || typeof val !== 'object') {
      continue; // config key, hidden/template job, or non-map
    }
    const job = val as Record<string, unknown>;
    if (!('script' in job)) {
      continue; // a GitLab job needs a script (trigger/bridge jobs are out of scope for v1)
    }

    const mrTriggerable = isMergeRequestTriggerable(job);
    const secretVars = referencedSecretVars(job);
    const jobNodeId = `job:.gitlab-ci.yml#${name}`;

    result.nodes.push({
      id: jobNodeId,
      kind: 'ci-job',
      provider: 'gitlab',
      workflow: '.gitlab-ci.yml',
      job: name,
      triggers: mrTriggerable ? ['merge_request_event'] : ['push'],
      secrets: secretVars,
      forkTriggerable: mrTriggerable,
      runsInstall: runsInstall(job),
    } as AttackNode);

    for (const secret of secretVars) {
      const sinkId = `sink:secret:${secret}`;
      result.nodes.push({
        id: sinkId,
        kind: 'sink',
        sinkKind: sinkKindFor(secret),
        identity: secret,
      });
      result.edges.push({ from: jobNodeId, to: sinkId, edge: { kind: 'holds' } });
    }

    if (mrTriggerable) {
      const entryId = `entry:fork-mr:.gitlab-ci.yml#${name}`;
      result.nodes.push({
        id: entryId,
        kind: 'entry',
        entryKind: 'fork-pr',
        exposure: 3,
        label: `merge_request pipeline reaches job ${name} (GitLab)`,
      });
      result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: 'triggers' } });
    }
  }

  return result;
}
