/**
 * CircleCI layer analyzer (0035, offline).
 *
 * CircleCI has a detectability gap that defines this analyzer's scope: whether a
 * **forked-PR build receives the project's secrets is a CircleCI project setting**
 * ("Pass secrets to builds from forked pull requests"), configured in the CircleCI
 * UI — it is NOT in `.circleci/config.yml`. Blastgate reads repo files, so it
 * cannot see that toggle. A naive port of the GitHub/GitLab fork-secret model would
 * emit a false FAIL (assuming forks get secrets) or a false PASS (assuming they
 * don't). Neither is honest, so this analyzer does neither: it emits the ci-job and
 * the secret sink it references (the in-repo-detectable facts), and a **warn
 * advisory diagnostic** — never a fork entry, so it never produces a fail on an
 * unprovable path. The blind spot is documented in the threat model and runbook.
 *
 * The graph still gains provider: 'circleci' jobs with `runsInstall`, so the
 * cross-layer install path composes if a future signal establishes untrusted
 * triggerability (e.g. a config-level control or an API integration).
 */

import { parse } from 'yaml';
import type { AttackNode } from '../../graph/types';
import { isInstallCommand } from '../ci/parse';
import { type AnalyzerResult, emptyResult } from '../types';

export interface CircleCiInputs {
  /** `.circleci/config.yml` contents. */
  content: string;
}

const CREDENTIAL_HINT = /(AWS|TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i;

function sinkKindFor(name: string): 'secret' | 'credential' {
  return CREDENTIAL_HINT.test(name) ? 'credential' : 'secret';
}

/** Extract `run` command strings from a job's steps (string, `{run: "..."}`, `{run: {command}}`). */
function runCommands(job: Record<string, unknown>): string[] {
  const steps = job.steps;
  if (!Array.isArray(steps)) {
    return [];
  }
  const out: string[] = [];
  for (const step of steps) {
    if (!step || typeof step !== 'object') {
      continue;
    }
    const run = (step as { run?: unknown }).run;
    if (typeof run === 'string') {
      out.push(run);
    } else if (run && typeof run === 'object') {
      const cmd = (run as { command?: unknown }).command;
      if (typeof cmd === 'string') {
        out.push(cmd);
      }
    }
  }
  return out;
}

/** Credential-looking env vars referenced in run steps (`$VAR`), excluding CircleCI predefined `CIRCLE_*`. */
function referencedSecretVars(job: Record<string, unknown>): string[] {
  const names = new Set<string>();
  const re = /\$\{?([A-Z_][A-Z0-9_]*)\}?/g;
  for (const line of runCommands(job)) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      const name = m[1]!;
      if (!name.startsWith('CIRCLE_') && CREDENTIAL_HINT.test(name)) {
        names.add(name);
      }
    }
  }
  return [...names];
}

export function analyzeCircleCi(inputs: CircleCiInputs): AnalyzerResult {
  const result = emptyResult();

  let doc: Record<string, unknown>;
  try {
    doc = (parse(inputs.content) ?? {}) as Record<string, unknown>;
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse .circleci/config.yml: ${(err as Error).message}`,
    });
    return result;
  }

  const jobs = doc.jobs;
  if (!jobs || typeof jobs !== 'object') {
    return result;
  }

  for (const [name, val] of Object.entries(jobs as Record<string, unknown>)) {
    if (!val || typeof val !== 'object') {
      continue;
    }
    const job = val as Record<string, unknown>;
    const secretVars = referencedSecretVars(job);
    const jobNodeId = `job:.circleci/config.yml#${name}`;

    result.nodes.push({
      id: jobNodeId,
      kind: 'ci-job',
      provider: 'circleci',
      workflow: '.circleci/config.yml',
      job: name,
      triggers: ['unknown'],
      secrets: secretVars,
      // Fork-triggerability is an out-of-repo project setting — not knowable here.
      forkTriggerable: false,
      runsInstall: runCommands(job).some(isInstallCommand),
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
      // The honest advisory: we can see the secret is used, but not whether forked
      // PRs receive it (the CircleCI project toggle). Surface it; do not fail on it.
      result.diagnostics.push({
        level: 'warn',
        message:
          `CircleCI job ${name} references credential ${secret}; whether forked-PR builds ` +
          `receive it is a CircleCI project setting Blastgate cannot see — verify ` +
          `"Pass secrets to builds from forked pull requests" is disabled`,
      });
    }
  }

  return result;
}
