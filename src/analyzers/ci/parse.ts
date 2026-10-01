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
  return untrustedCheckoutStep(job) !== undefined;
}

/** Index of the first step that checks out the untrusted PR/workflow_run head (0041/0048). */
export function untrustedCheckoutStep(job: JobSpec): number | undefined {
  const i = (job.steps ?? []).findIndex((step) => {
    if (typeof step.uses === 'string' && /actions\/checkout/.test(step.uses)) {
      const ref = step.with?.ref;
      if (typeof ref === 'string' && UNTRUSTED_REF_RE.test(ref)) {
        return true;
      }
    }
    return typeof step.run === 'string' && PR_CHECKOUT_CMD_RE.test(step.run);
  });
  return i >= 0 ? i : undefined;
}

// A job compiled by GitHub Agentic Workflows (gh-aw) installs its runtime with this action.
const GH_AW_SETUP_RE = /^github\/gh-aw-actions\/setup@/;
// gh-aw runtime: scripts under its own paths, or its compiler's `$GH_AW_*` variables.
const GH_AW_PATH_RE = /^["']?(?:\$\{?RUNNER_TEMP\}?|\/tmp)\/gh-aw\//;
const GH_AW_VAR_RE = /^["']?\$\{?GH_AW_\w+\}?["']?$/;
const isGhAwWord = (w: string): boolean => GH_AW_PATH_RE.test(w) || GH_AW_VAR_RE.test(w);
// Commands that never run the checked-out workspace's code.
const INERT_COMMANDS = new Set([
  ...['set', 'export', 'echo', 'printf', 'mkdir', 'cp', 'mv', 'rm', 'touch', 'chmod', 'cat'],
  ...['test', '[', '[[', 'true', 'false', 'exit', 'return', 'cd', 'local', 'read', 'shift'],
  ...['wait', 'sleep', 'date', 'id', 'openssl', 'tr', 'head', 'tail', 'grep', 'tee', 'sort'],
  ...['uniq', 'wc', 'base64', 'type', 'which', 'unset', 'declare', 'readonly', 'mktemp', 'ln'],
  ...['ls', 'basename', 'dirname', 'realpath', ':', 'curl', 'kill', 'umask', 'gh', 'jq'],
  ...['break', 'continue', 'for', 'in', 'if', 'then', 'else', 'elif', 'fi', 'do', 'done'],
  ...['while', 'until', 'case', 'esac'],
]);
// Inert unless an argument makes them run something.
const CONDITIONAL_COMMANDS: Record<string, (args: string[]) => boolean> = {
  command: (args) => args[0] === '-v' || args[0] === '-V',
  // Only a single-quoted body, which shellSegments checks as commands of its own.
  trap: (args) => args[0] === "''",
  find: (args) => !args.some((a) => /^-(?:exec|execdir|ok|okdir)$/.test(a)),
  git: (args) => !args.some((a) => /hooksPath/.test(a) || a === '-c'),
  jq: (args) => !args.some((a) => /^-f$|^--from-file/.test(a)),
  npm: (args) => /^(?:root|config|view|ls|-v|--version)$/.test(args[0] ?? ''),
};
const SCRIPT_RUNNERS = new Set(['bash', 'sh', 'node', 'source', '.']);
// What may follow `--` in a gh-aw runtime call: gh-aw's firewall launcher or an agent CLI.
const AGENT_LAUNCH_RE = /^(?:awf|copilot|claude|codex|gemini)$/;
// Shell syntax this tokenizer does not model: backticks, process substitution, arithmetic,
// here-strings. A step using any of them is not provably gh-aw runtime.
const UNMODELED_RE = /`|[<>]\(|\$\(\(|<<</;
// A single-quoted string, including gh-aw's '\'' escapes for a quote inside one.
const SINGLE_QUOTED_RE = /'(?:[^']|'\\'')*'/g;
// A workspace path handed to a runtime script as an argument.
const WORKSPACE_ARG_RE = /^["']?(?:\.{1,2}\/|\$\{?GITHUB_WORKSPACE)/;

/**
 * Simple commands of a `run:` script, or undefined when it uses syntax the tokenizer cannot
 * model. Comments and heredoc bodies are dropped, single-quoted text is literal (a `trap`
 * body is returned for checking instead), and `$(…)` contents become commands of their own.
 */
function shellSegments(run: string): string[] | undefined {
  const out: string[] = [];
  let heredoc: string | undefined;
  for (const line of run.replace(/\\\n/g, ' ').split('\n')) {
    if (heredoc !== undefined) {
      heredoc = line.trim() === heredoc ? undefined : heredoc;
      continue;
    }
    const code = line.replace(/(^|\s)#.*$/, '$1');
    // A trap body runs later; check it like any other command.
    for (const m of code.matchAll(/\btrap\s+'([^']*)'/g)) {
      const body = shellSegments(m[1] ?? '');
      if (body === undefined) {
        return undefined;
      }
      out.push(...body);
    }
    const unquoted = code.replace(SINGLE_QUOTED_RE, "''");
    if (UNMODELED_RE.test(unquoted)) {
      return undefined;
    }
    heredoc = /<<-?\s*(['"]?)(\w+)\1/.exec(unquoted)?.[2];
    const subs = [...unquoted.matchAll(/\$\(([^()]*)\)/g)].map((m) => m[1] ?? '');
    const masked = unquoted
      .replace(/"(?:[^"\\]|\\.)*"/g, (q) => (q.startsWith('"$') || isGhAwWord(q) ? q : '""'))
      .replace(/\$\(([^()]*)\)/g, '$X');
    for (const c of [masked, ...subs]) {
      out.push(...c.split(/&&|\|\||;|\|/));
    }
  }
  return out;
}

/** The command words of a segment, past keywords, groupings, and leading `VAR=value`s. */
function commandWords(segment: string): string[] {
  let s = segment.trim();
  for (let prev = ''; prev !== s;) {
    prev = s;
    s = s
      .replace(/^[({!]\s*/, '')
      .replace(/^(?:if|then|else|elif|do|while|until|time|exec)\s+/, '')
      .replace(/^[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S*)\s*/, '');
  }
  return s.split(/\s+/).filter(Boolean);
}

/** A gh-aw runtime call's arguments: no workspace path of its own, and only an agent launch after `--`. */
function runtimeArgsSafe(args: string[]): boolean {
  // Before `--` the arguments are the runtime's own; after it, an agent launch and its flags.
  const dash = args.indexOf('--');
  const own = dash < 0 ? args : args.slice(0, dash);
  if (own.some((a) => WORKSPACE_ARG_RE.test(a))) {
    return false;
  }
  const launched = args[dash + 1] ?? '';
  return dash < 0 || AGENT_LAUNCH_RE.test(launched) || isGhAwWord(launched);
}

/**
 * A gh-aw runtime step (0062): every command in it is a gh-aw runtime script, a compiler
 * `$GH_AW_*` invocation, gh-aw's `awf` firewall launching its agent, or inert shell plumbing,
 * so it cannot run the PR's code. An allowlist that fails closed: an unrecognized command, a
 * quoted command word, or shell syntax the tokenizer cannot model all count as running the
 * PR's code. What `awf` runs after `--` is the sandboxed agent (the agent class, judged by its
 * own Rule-of-Two verdict), not direct PR-code execution.
 */
export function isGhAwRuntimeStep(run: string): boolean {
  const segments = shellSegments(run);
  if (segments === undefined) {
    return false;
  }
  for (const segment of segments) {
    const [cmd, ...args] = commandWords(segment);
    if (cmd === undefined || /^[)}\]]/.test(cmd)) {
      continue;
    }
    // gh-aw's firewall, launched with its own generated config: what it runs is the agent.
    if (cmd === 'awf') {
      if (!isGhAwWord(args[args.indexOf('--config') + 1] ?? '')) {
        return false;
      }
      continue;
    }
    if (isGhAwWord(cmd)) {
      const target = args.find((a) => !a.startsWith('-'));
      if (target !== undefined && !isGhAwWord(target)) {
        return false;
      }
      if (!runtimeArgsSafe(args)) {
        return false;
      }
      continue;
    }
    if (SCRIPT_RUNNERS.has(cmd)) {
      // The script is the first non-option word; `-c` before it runs an inline command.
      const at = args.findIndex((a) => !a.startsWith('-'));
      const target = args[at];
      if (target === undefined || !isGhAwWord(target) || args.slice(0, at).includes('-c')) {
        return false;
      }
      if (!runtimeArgsSafe(args.slice(at + 1))) {
        return false;
      }
      continue;
    }
    const conditional = CONDITIONAL_COMMANDS[cmd];
    if (conditional ? !conditional(args) : !INERT_COMMANDS.has(cmd)) {
      return false;
    }
  }
  return true;
}

/**
 * Index of the first step after an untrusted checkout that executes workspace code: a
 * `run:` step or a local `./` action (0048). Approximation: any `run:` after the checkout
 * is treated as able to run attacker-controlled repo code (scripts, Makefiles, configs).
 * Exception (0062): in a gh-aw-compiled job, a step on gh-aw's runtime paths runs gh-aw,
 * not the PR; the PR tree reaches that job only through its agent (agent class, warn).
 */
export function untrustedExecutionStep(job: JobSpec): number | undefined {
  const checkout = untrustedCheckoutStep(job);
  if (checkout === undefined) {
    return undefined;
  }
  const steps = job.steps ?? [];
  const ghAw = steps.some((s) => typeof s.uses === 'string' && GH_AW_SETUP_RE.test(s.uses));
  for (let i = checkout + 1; i < steps.length; i++) {
    const step = steps[i]!;
    if (ghAw && typeof step.run === 'string' && isGhAwRuntimeStep(step.run)) {
      continue; // gh-aw's own runtime, not the PR's code (0062)
    }
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
