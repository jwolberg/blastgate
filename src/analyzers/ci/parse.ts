import { parse } from 'yaml';

export interface StepSpec {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
  if?: unknown;
  name?: unknown;
  id?: unknown;
}

export interface JobSpec {
  needs?: unknown;
  permissions?: unknown;
  steps?: StepSpec[];
  env?: Record<string, unknown>;
  secrets?: unknown;
  if?: unknown;
}

export interface WorkflowSpec {
  name?: unknown;
  on?: unknown;
  permissions?: unknown;
  env?: Record<string, unknown>;
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

/**
 * Whether a job is gated on a *label* — `if: github.event.label.name …` (0044).
 * Applying a label requires triage/write permission, so a `labeled`-triggered job
 * only runs after a trusted actor acts; an outside contributor cannot self-trigger
 * it. A weaker guard than `author_association` (the attacker's text may still be
 * present when a maintainer labels), but it does restrict *who* fires the job — so,
 * like `hasActorGuard`, it neutralizes the injection finding (node's `flaky-test` /
 * `review wanted` bots are this shape).
 */
export function isLabelGated(job: JobSpec): boolean {
  const cond = typeof job.if === 'string' ? job.if : '';
  return /github\.event\.label\.name/.test(cond);
}

// A collaborator/actor permission check inside an `actions/github-script` body.
const SCRIPT_PERMISSION_RE =
  /getCollaboratorPermissionLevel|\.permissions?\.(?:triage|push|admin|write|maintain)\b/;

/**
 * Whether a job halts for unauthorized actors via an in-*step* permission check (0044):
 * an `actions/github-script` step whose script both checks collaborator/actor permission
 * AND `throw`s. A thrown error fails the step, stopping the job before any secret-bearing
 * step runs — a job-wide guard the `if:`-only detector (0017) misses (vite's
 * `ecosystem-ci-trigger` is this shape). Conservative: a check that merely sets an output
 * (non-halting) is NOT a guard, so the finding stands (fail-closed) — this is what keeps
 * ant-design's un-gated DingTalk step a real finding.
 */
export function hasScriptPermissionGuard(job: JobSpec): boolean {
  return (job.steps ?? []).some((step) => {
    if (typeof step.uses !== 'string' || !/actions\/github-script/.test(step.uses)) {
      return false;
    }
    const script = typeof step.with?.script === 'string' ? step.with.script : '';
    return SCRIPT_PERMISSION_RE.test(script) && /\bthrow\b/.test(script);
  });
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

/**
 * Ref expressions naming the untrusted head by COMMIT: fork code wherever they are fetched,
 * since GitHub serves fork PR commits (and refs/pull/*) from the base repo.
 */
const UNTRUSTED_SHA_REF_RE =
  /pull_request\.head\.sha|workflow_run\.head_sha|refs\/pull\/|merge_commit_sha/;
/**
 * Ref expressions naming the untrusted head by BRANCH NAME. actions/checkout resolves a name
 * against `repository:` (default: the base repo), so these are fork code only when
 * `repository:` points elsewhere (0089).
 */
const UNTRUSTED_BRANCH_REF_RE =
  /pull_request\.head\.ref|\bhead_ref\b|workflow_run\.head_(branch|ref)/;
/** `repository:` values that are the base repo itself. Anything else fails closed as the fork. */
const BASE_REPO_RE = /^\s*\$\{\{\s*github\.repository\s*\}\}\s*$/;

/** Whether an actions/checkout `with:` fetches the untrusted head (0041, 0089). */
function checkoutFetchesUntrusted(ref: unknown, repository: unknown): boolean {
  if (typeof ref !== 'string') {
    return false;
  }
  if (UNTRUSTED_SHA_REF_RE.test(ref)) {
    return true;
  }
  // A head repo resolved by an earlier step (`steps.pr.outputs.head_repo`) is common, so any
  // repository: other than the base repo counts as the fork.
  return (
    UNTRUSTED_BRANCH_REF_RE.test(ref) &&
    typeof repository === 'string' &&
    repository.trim() !== '' &&
    !BASE_REPO_RE.test(repository)
  );
}
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
  return untrustedCheckoutStep(job) !== undefined;
}

/** Index of the first step that checks out the untrusted PR/workflow_run head (0041/0048). */
export function untrustedCheckoutStep(job: JobSpec): number | undefined {
  const i = (job.steps ?? []).findIndex((step) => {
    if (typeof step.uses === 'string' && /actions\/checkout/.test(step.uses)) {
      if (checkoutFetchesUntrusted(step.with?.ref, step.with?.repository)) {
        return true;
      }
    }
    return typeof step.run === 'string' && PR_CHECKOUT_CMD_RE.test(step.run);
  });
  return i >= 0 ? i : undefined;
}

/**
 * Index of the first step after an untrusted checkout that executes workspace code: a
 * `run:` step or a local `./` action (0048). Approximation: any `run:` after the checkout
 * is treated as able to run attacker-controlled repo code (scripts, Makefiles, configs).
 */
export function untrustedExecutionStep(job: JobSpec): number | undefined {
  const checkout = untrustedCheckoutStep(job);
  if (checkout === undefined) {
    return undefined;
  }
  const steps = job.steps ?? [];
  for (let i = checkout + 1; i < steps.length; i++) {
    const step = steps[i]!;
    if (
      typeof step.run === 'string' ||
      (typeof step.uses === 'string' && step.uses.startsWith('./'))
    ) {
      return i;
    }
  }
  return undefined;
}

/** Index of the dependency-install step (prefers an explicit install command over setup-node). */
export function installStep(job: JobSpec): number | undefined {
  const steps = job.steps ?? [];
  const run = steps.findIndex((s) => typeof s.run === 'string' && isInstallCommand(s.run));
  if (run >= 0) {
    return run;
  }
  const setup = steps.findIndex(
    (s) => typeof s.uses === 'string' && /^actions\/setup-node@/.test(s.uses),
  );
  return setup >= 0 ? setup : undefined;
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
  /** The token can change repo code: `contents: write` or `write-all` (0047). */
  codeWrite: boolean;
  /** The token can mint cloud credentials via OIDC: `id-token: write` or `write-all` (0047). */
  mintsCredentials: boolean;
}

/** Resolve effective GITHUB_TOKEN permissions: job-level overrides workflow-level; absent = inherited/unknown. */
export function resolvePermissions(workflow: WorkflowSpec, job: JobSpec): TokenPermissions {
  const p = job.permissions ?? workflow.permissions;
  const none = { codeWrite: false, mintsCredentials: false };
  if (p === undefined) {
    return { raw: 'inherited (repo default)', overBroad: false, known: false, ...none };
  }
  if (p === 'write-all') {
    return {
      raw: 'write-all',
      overBroad: true,
      known: true,
      codeWrite: true,
      mintsCredentials: true,
    };
  }
  if (p === 'read-all') {
    return { raw: 'read-all', overBroad: false, known: true, ...none };
  }
  if (p && typeof p === 'object') {
    const scopes = p as Record<string, unknown>;
    const entries = Object.entries(scopes);
    const overBroad = entries.some(([, v]) => v === 'write');
    const raw = entries.map(([k, v]) => `${k}:${String(v)}`).join(', ') || '{}';
    return {
      raw,
      overBroad,
      known: true,
      codeWrite: scopes.contents === 'write',
      mintsCredentials: scopes['id-token'] === 'write',
    };
  }
  return { raw: String(p), overBroad: false, known: true, ...none };
}
