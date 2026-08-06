import { parse } from 'yaml';

export interface StepSpec {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
}

export interface JobSpec {
  permissions?: unknown;
  steps?: StepSpec[];
  env?: Record<string, unknown>;
  secrets?: unknown;
  if?: unknown;
}

export interface WorkflowSpec {
  on?: unknown;
  permissions?: unknown;
  jobs?: Record<string, JobSpec>;
}

/** Parse Actions YAML (KTD7). `yaml`'s 1.2 core schema keeps `on:` a string key. Throws on invalid YAML. */
export function parseWorkflow(yamlText: string): WorkflowSpec {
  return (parse(yamlText) ?? {}) as WorkflowSpec;
}

const UNTRUSTED_EVENTS = new Set([
  'pull_request',
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'pull_request_review',
  'pull_request_review_comment',
]);

/** Normalize the three legal `on:` forms (string, array, map) to an event-name list. */
export function normalizeTriggers(on: unknown): string[] {
  if (typeof on === 'string') {
    return [on];
  }
  if (Array.isArray(on)) {
    return on.filter((x): x is string => typeof x === 'string');
  }
  if (on && typeof on === 'object') {
    return Object.keys(on as Record<string, unknown>);
  }
  return [];
}

export function untrustedTriggers(triggers: string[]): string[] {
  return triggers.filter((t) => UNTRUSTED_EVENTS.has(t));
}

/**
 * Untrusted events that run in the BASE-repo context WITH repo secrets and a
 * potentially writable `GITHUB_TOKEN`, even when driven by an outside contributor —
 * i.e. the events from which a fork/external actor can actually REACH a credential.
 *
 * Plain `pull_request` is deliberately excluded: GitHub runs fork PRs with a
 * read-only `GITHUB_TOKEN` and withholds repo secrets ("secrets are not passed to
 * the runner when a workflow is triggered from a forked repository"). So a write
 * permission or a `secrets.X` reference in a `pull_request`-only job is a declared
 * permission a fork can never obtain — not a reachable path. `pull_request_target`,
 * `workflow_run`, and the issue/review-comment events all run privileged and ARE
 * reachable. This distinction is what keeps a finding a *reachable path* (R14)
 * rather than a pattern match on the permissions block.
 */
const CREDENTIAL_REACHABLE_EVENTS = new Set([
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'pull_request_review',
  'pull_request_review_comment',
]);

/** Untrusted triggers through which a fork/external actor can actually reach a secret or writable token. */
export function credentialReachableTriggers(triggers: string[]): string[] {
  return triggers.filter((t) => CREDENTIAL_REACHABLE_EVENTS.has(t));
}

export function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((v) => collectStrings(v, out));
  } else if (value && typeof value === 'object') {
    Object.values(value as Record<string, unknown>).forEach((v) => collectStrings(v, out));
  }
}

const SECRET_RE = /\bsecrets\.([A-Za-z0-9_]+)/g;
const TOJSON_SECRETS_RE = /toJSON\(\s*secrets\s*\)/;

/**
 * Expression-aware secret scan: matches `secrets.X` anywhere in the job's string
 * scalars (env / with / run / if), including inside `format(...)`, and detects the
 * bulk `toJSON(secrets)` form. `GITHUB_TOKEN` is governed by permissions, not this
 * scan, so it is excluded here.
 */
export function findSecretRefs(job: JobSpec): { names: string[]; usesAllSecrets: boolean } {
  const strings: string[] = [];
  collectStrings(job, strings);
  const names = new Set<string>();
  let usesAllSecrets = false;
  for (const s of strings) {
    SECRET_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SECRET_RE.exec(s)) !== null) {
      if (m[1] && m[1] !== 'GITHUB_TOKEN') {
        names.add(m[1]);
      }
    }
    if (TOJSON_SECRETS_RE.test(s)) {
      usesAllSecrets = true;
    }
  }
  return { names: [...names], usesAllSecrets };
}

const INSTALL_RE =
  /\b(npm\s+(ci|install|i)|yarn(\s+install)?|pnpm\s+(install|i)|pip3?\s+install|python[\d.]*\s+-m\s+pip\s+install|python[\d.]*\s+setup\.py|uv\s+(pip\s+install|sync)|poetry\s+install|pipenv\s+install|bundle\s+install|gem\s+install)\b/;

/** GitHub `author_association` values that denote a trusted (repo-affiliated) actor. */
const TRUSTED_ROLE = /\b(OWNER|MEMBER|COLLABORATOR)\b/;

/**
 * Whether a job's `if:` restricts *who* can trigger it to trusted actors (U17).
 * Conservative and fail-closed: only two recognized patterns count as a guard —
 * an `author_association` compared against a trusted role, or a `github.actor` /
 * `github.triggering_actor` comparison/allowlist. A mere content filter (e.g.
 * `contains(body, '@claude')`) is NOT a guard, so an unrecognized `if:` never
 * downgrades a finding.
 */
export function hasActorGuard(job: JobSpec): boolean {
  const cond = typeof job.if === 'string' ? job.if : '';
  if (!cond) {
    return false;
  }
  if (/author_association/.test(cond) && TRUSTED_ROLE.test(cond)) {
    return true;
  }
  return (
    /\bgithub\.(triggering_actor|actor)\b/.test(cond) && /(==|!=|fromJSON|contains)/.test(cond)
  );
}

/** A shell command that installs dependencies (where a poisoned lifecycle script executes). */
export function isInstallCommand(command: string): boolean {
  return INSTALL_RE.test(command);
}

/** A step that runs a dependency install (where a poisoned lifecycle script would execute). */
export function hasInstallStep(job: JobSpec): boolean {
  return (job.steps ?? []).some((step) => {
    if (typeof step.run === 'string' && isInstallCommand(step.run)) {
      return true;
    }
    return typeof step.uses === 'string' && /^actions\/setup-node@/.test(step.uses);
  });
}

/** Ref expressions that resolve to the untrusted PR/workflow_run head (the attacker's code). */
const UNTRUSTED_REF_RE =
  /pull_request\.head|head_ref|workflow_run\.head_(sha|branch|ref)|refs\/pull\/|merge_commit_sha/;
/** Shell forms that fetch/check out the untrusted PR ref inside a `run:` step. */
const PR_CHECKOUT_CMD_RE = /gh\s+pr\s+checkout|git\s+fetch[^\n]*\bpull\/|checkout\s+FETCH_HEAD/;

/**
 * Whether a privileged job checks out the *untrusted* PR/workflow_run head — the
 * precondition that lets an attacker's code actually run in the job (0041). A
 * `pull_request_target` job with no checkout, or a default-ref checkout (which resolves
 * to the trusted base), runs only committed code and cannot reach the job's secrets;
 * the standard label/triage bots (`actions/github-script` / `actions/labeler` on event
 * metadata) fall here and are NOT findings. Only an explicit untrusted-ref checkout, or
 * a `gh pr checkout` / manual PR-ref fetch, counts as an execution surface.
 */
export function checksOutUntrustedRef(job: JobSpec): boolean {
  for (const step of job.steps ?? []) {
    if (typeof step.uses === 'string' && /actions\/checkout/.test(step.uses)) {
      const ref = step.with?.ref;
      if (typeof ref === 'string' && UNTRUSTED_REF_RE.test(ref)) {
        return true;
      }
    }
    if (typeof step.run === 'string' && PR_CHECKOUT_CMD_RE.test(step.run)) {
      return true;
    }
  }
  return false;
}

/** Pinned ⇔ `@<40-hex-sha>` (or a docker `@sha256:` digest); local `./` actions carry no external risk. */
export function isPinnedAction(uses: string): boolean {
  if (uses.startsWith('./') || uses.startsWith('../')) {
    return true;
  }
  const at = uses.lastIndexOf('@');
  if (at === -1) {
    return false;
  }
  const ref = uses.slice(at + 1);
  return /^[0-9a-f]{40}$/i.test(ref) || /^sha256:[0-9a-f]{64}$/i.test(ref);
}

export function unpinnedActions(job: JobSpec): string[] {
  return (job.steps ?? [])
    .map((s) => s.uses)
    .filter((u): u is string => typeof u === 'string')
    .filter((u) => !isPinnedAction(u));
}

export interface TokenPermissions {
  raw: string;
  overBroad: boolean;
  known: boolean;
}

/** Resolve effective GITHUB_TOKEN permissions: job-level overrides workflow-level; absent = inherited/unknown. */
export function resolvePermissions(workflow: WorkflowSpec, job: JobSpec): TokenPermissions {
  const p = job.permissions ?? workflow.permissions;
  if (p === undefined) {
    return { raw: 'inherited (repo default)', overBroad: false, known: false };
  }
  if (p === 'write-all') {
    return { raw: 'write-all', overBroad: true, known: true };
  }
  if (p === 'read-all') {
    return { raw: 'read-all', overBroad: false, known: true };
  }
  if (p && typeof p === 'object') {
    const entries = Object.entries(p as Record<string, unknown>);
    const overBroad = entries.some(([, v]) => v === 'write');
    const raw = entries.map(([k, v]) => `${k}:${String(v)}`).join(', ') || '{}';
    return { raw, overBroad, known: true };
  }
  return { raw: String(p), overBroad: false, known: true };
}
