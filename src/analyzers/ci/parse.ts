import { parse } from 'yaml';

export interface StepSpec {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
  if?: unknown;
  name?: unknown;
  id?: unknown;
  shell?: unknown;
  'working-directory'?: unknown;
}

export interface JobSpec {
  needs?: unknown;
  permissions?: unknown;
  steps?: StepSpec[];
  env?: Record<string, unknown>;
  secrets?: unknown;
  if?: unknown;
  defaults?: unknown;
}

export interface WorkflowSpec {
  name?: unknown;
  on?: unknown;
  permissions?: unknown;
  env?: Record<string, unknown>;
  defaults?: unknown;
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

/** Split an Actions expression on `op` at paren depth 0, outside quotes. */
function splitTopLevel(expr: string, op: '||' | '&&'): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i]!;
    if (quote) {
      quote = c === quote ? undefined : quote;
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === '(') {
      depth++;
    } else if (c === ')') {
      depth--;
    } else if (depth === 0 && expr.startsWith(op, i)) {
      parts.push(expr.slice(start, i));
      start = i + op.length;
      i++;
    }
  }
  parts.push(expr.slice(start));
  return parts.map(unwrapParens);
}

/** Drop parens that wrap the whole expression: `(a && b)` → `a && b`. */
function unwrapParens(expr: string): string {
  let e = expr.trim();
  while (e.startsWith('(') && e.endsWith(')')) {
    let depth = 0;
    let wraps = true;
    for (let i = 0; i < e.length - 1; i++) {
      depth += e[i] === '(' ? 1 : e[i] === ')' ? -1 : 0;
      if (depth === 0) {
        wraps = false;
        break;
      }
    }
    if (!wraps) {
      break;
    }
    e = e.slice(1, -1).trim();
  }
  return e;
}

// Upstream events only a maintainer can fire.
const TRUSTED_UPSTREAM_EVENTS = new Set(['push', 'schedule', 'workflow_dispatch', 'release']);

/**
 * 0097: the job's `if:` keeps an outsider's `workflow_run` out — every top-level `||` branch
 * requires either a different `github.event_name` or an upstream run fired by a trusted event
 * (`github.event.workflow_run.event == 'push'`). Only plain `==` conjuncts count; anything
 * else (nested `||`, `!=`, functions) is not proof. A `branches:` filter is not a gate either:
 * `head_branch` is the fork's branch name, which the outsider picks.
 */
export function excludesUntrustedWorkflowRun(job: JobSpec): boolean {
  const raw = typeof job.if === 'string' ? job.if : '';
  const expr = raw.replace(/^\s*\$\{\{([\s\S]*)\}\}\s*$/, '$1').trim();
  if (!expr) {
    return false;
  }
  return splitTopLevel(expr, '||').every((branch) =>
    splitTopLevel(branch, '&&').some((term) => {
      const run = /^github\.event\.workflow_run\.event\s*==\s*'(\w+)'$/.exec(term);
      if (run) {
        return TRUSTED_UPSTREAM_EVENTS.has(run[1]!);
      }
      const name = /^github\.event_name\s*==\s*'(\w+)'$/.exec(term);
      return name !== null && name[1] !== 'workflow_run';
    }),
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

/** A shell `if` comparing the PR head repo with the base repo for INequality (0090). */
const SAME_REPO_MISMATCH_RE =
  /^\s*(?:if|elif)\b(?=.*!=)(?=.*head[._]?repo)(?=.*(?:\bREPO\b|GITHUB_REPOSITORY|github\.repository))/i;
/** Base-repo tokens are matched case-sensitively: `head_repo` alone must not count as the base. */
const BASE_REPO_TOKEN_RE = /\bREPO\b|GITHUB_REPOSITORY|github\.repository/;

/**
 * Whether a `run:` script exits for fork PRs before its PR-ref fetch (0090): an `if` that
 * compares the head repo with the base repo using `!=` and whose body (up to its `fi`) exits,
 * all before the fetch. Only same-repo PRs, which come from collaborators, then reach the fetch.
 * Narrow on purpose: an `==` guard, a guard after the fetch, or one that does not exit
 * protects nothing.
 */
function exitsForForkBeforeFetch(script: string): boolean {
  const lines = script.split('\n');
  const fetchAt = lines.findIndex((l) => PR_CHECKOUT_CMD_RE.test(l));
  if (fetchAt < 0) {
    return false;
  }
  for (let i = 0; i < fetchAt; i++) {
    const line = lines[i] ?? '';
    if (!SAME_REPO_MISMATCH_RE.test(line) || !BASE_REPO_TOKEN_RE.test(line)) {
      continue;
    }
    let body = line;
    for (let j = i; j < fetchAt; j++) {
      if (j > i) body += `\n${lines[j] ?? ''}`;
      if (/\bfi\b/.test(lines[j] ?? '')) {
        if (/\bexit\b/.test(body)) return true;
        break;
      }
    }
  }
  return false;
}

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

/** Whether this step checks out the untrusted PR/workflow_run head (0041/0048). */
function isUntrustedCheckout(step: StepSpec): boolean {
  if (typeof step.uses === 'string' && /actions\/checkout/.test(step.uses)) {
    if (checkoutFetchesUntrusted(step.with?.ref, step.with?.repository)) {
      return true;
    }
  }
  return (
    typeof step.run === 'string' &&
    PR_CHECKOUT_CMD_RE.test(step.run) &&
    !exitsForForkBeforeFetch(step.run)
  );
}

/** Index of the first step that checks out the untrusted PR/workflow_run head (0041/0048). */
export function untrustedCheckoutStep(job: JobSpec): number | undefined {
  const i = (job.steps ?? []).findIndex(isUntrustedCheckout);
  return i >= 0 ? i : undefined;
}

/**
 * A workspace-relative directory in normal form: '' is the workspace root. Undefined when the
 * value is not a plain relative path (an expression, an absolute path, `..`), which callers
 * treat as the root so they fail closed (0113).
 */
function workspaceDir(value: unknown): string | undefined {
  if (value === undefined) return '';
  if (typeof value !== 'string' || /\$\{\{|^\s*\/|(^|\/)\.\.(\/|$)/.test(value)) return undefined;
  return value
    .trim()
    .replace(/^(\.\/)+/, '')
    .replace(/\/+$/, '')
    .replace(/^\.$/, '');
}

/**
 * Whether a local `uses: ./dir` action at step `at` resolves into untrusted code (0113). A
 * local action is read from the workspace, so it is fork code when an earlier untrusted
 * checkout landed at the workspace root, or when the action lives under the directory the
 * untrusted checkout was written to (`with: path:`). An action outside every untrusted
 * checkout directory comes from the base checkout and runs base-repo code, even if it is
 * handed the PR directory as data.
 */
function localActionIsUntrusted(steps: StepSpec[], at: number, uses: string): boolean {
  const action = workspaceDir(uses);
  for (let i = 0; i < at; i++) {
    const step = steps[i]!;
    if (!isUntrustedCheckout(step)) continue;
    // `gh pr checkout` and friends check out into the working directory: the root.
    const dir = typeof step.uses === 'string' ? workspaceDir(step.with?.path) : '';
    if (dir === undefined || dir === '' || action === undefined) return true;
    if (action === dir || action.startsWith(`${dir}/`)) return true;
  }
  return false;
}

/**
 * Index of the first step after an untrusted checkout that executes workspace code: a
 * `run:` step or a local `./` action (0048). Approximation: any `run:` after the checkout
 * is treated as able to run attacker-controlled repo code (scripts, Makefiles, configs),
 * unless it only runs git and shell builtins (0096).
 */
export function untrustedExecutionStep(
  job: JobSpec,
  workflow: WorkflowSpec = {},
): number | undefined {
  const checkout = untrustedCheckoutStep(job);
  if (checkout === undefined) {
    return undefined;
  }
  const steps = job.steps ?? [];
  const runDefaults = (d: unknown): unknown =>
    (d as { run?: { 'working-directory'?: unknown } } | undefined)?.run?.['working-directory'];
  const context: RunContext = {
    workingDirectory:
      runDefaults(job.defaults) !== undefined || runDefaults(workflow.defaults) !== undefined,
    loaderEnv: [job.env, workflow.env].some((env) =>
      Object.keys(env ?? {}).some((k) => LOADER_ENV_RE.test(k)),
    ),
  };
  // Cite the step that plainly runs build tooling when there is one; otherwise the first step
  // that cannot be shown to run nothing (0096 review).
  // A local `./` action outside every untrusted checkout directory is base-repo code (0113).
  const baseAction = (i: number): boolean => {
    const uses = steps[i]!.uses;
    return (
      typeof uses === 'string' && uses.startsWith('./') && !localActionIsUntrusted(steps, i, uses)
    );
  };
  for (let i = checkout + 1; i < steps.length; i++) {
    if (runsBuildTooling(steps[i]!) && !baseAction(i)) {
      return i;
    }
  }
  for (let i = checkout + 1; i < steps.length; i++) {
    const step = steps[i]!;
    if (
      runsWorkspaceCode(step, context) ||
      (typeof step.uses === 'string' && step.uses.startsWith('./') && !baseAction(i))
    ) {
      return i;
    }
  }
  return undefined;
}

// 0096: commands that act on the checkout without running anything it contains. Deliberately
// minimal: file writers (cp, mv, tee) can plant a hook or config, and readers and testers
// (cat, grep, jq, test, [[, printf) have argument forms that evaluate or load code. Anything
// not listed counts as executing; that only keeps a fail, never drops one.
const NON_EXECUTING_COMMANDS = new Set([
  'echo',
  'exit',
  'true',
  'false',
  'set',
  'export',
  'mkdir',
  'rm',
  'ls',
  'pwd',
  'date',
  'sleep',
  'cd',
  'pushd',
  'popd',
]);
const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'fi', '!', '{', '}']);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
// Variables that make a later program load code: a hijacked PATH, a shell or loader hook, git.
const LOADER_ENV_RE =
  /^(?:PATH|BASH_ENV|ENV|HOME|XDG_CONFIG_HOME|NODE_OPTIONS|LD_\w+|DYLD_\w+|GIT_\w+|PYTHON\w*|PERL5\w*|RUBY\w*|PS4|PROMPT_COMMAND)(?:=|$)/;
// Git subcommands that read, fetch, or move refs and run no user-supplied command. Hooks and
// filters need config: a fresh checkout's own .git carries none, and `-c`, `config`, and any
// way of pointing git at another directory (which may be a committed bare repo) are refused.
const GIT_SAFE_SUBCOMMANDS = new Set([
  'fetch',
  'pull',
  'checkout',
  'switch',
  'log',
  'show',
  'diff',
  'status',
  'rev-parse',
  'rev-list',
  'merge-base',
  'tag',
  'push',
  'clean',
  'reset',
  'branch',
  'ls-remote',
  'ls-files',
  'describe',
  'remote',
  'cat-file',
  'add',
  'commit',
  'merge',
]);
const GIT_SAFE_CONFIG_KEY_RE =
  /^(?:user\.(?:name|email)|safe\.directory|init\.defaultBranch|core\.(?:autocrlf|sparseCheckout)|http\..*\.extraheader|advice\.\w+|pull\.rebase|fetch\.prune)$/;
const GIT_EXEC_OPTION_RE = /^(?:-x|--exec|--upload-pack|--receive-pack|--ext-diff|--config)/;
// Git subcommands that talk to a remote: a variable argument could be an attacker-chosen
// `--upload-pack=…`.
const GIT_REMOTE_SUBCOMMANDS = new Set(['fetch', 'pull', 'push', 'ls-remote', 'remote']);
const GIT_DIR_OPTION_RE = /^(?:-C|--git-dir|--work-tree)/;
const SAFE_REDIRECT_TARGET_RE = /^(?:&[\d-]+|\/dev\/null|\$\{?GITHUB_(?:OUTPUT|STEP_SUMMARY)\}?)$/;

interface ShellScript {
  commands: string[][];
  redirects: string[];
}

/**
 * A small single-pass reader for the shell subset a git-only step uses: words, quotes
 * ('…', "…", $'…'), backslash escapes, comments, `;` `&` `|` and newlines, and `<` / `>`
 * redirects. Returns undefined for anything outside that subset (substitutions, subshells,
 * heredocs, unterminated quotes) so the caller treats the script as executing (0096).
 */
function readShell(script: string): ShellScript | undefined {
  const commands: string[][] = [];
  const redirects: string[] = [];
  let command: string[] = [];
  let word = '';
  let inWord = false;
  let redirect: 'in' | 'out' | undefined;
  const endWord = (): void => {
    if (inWord) {
      if (redirect === 'out') {
        redirects.push(word);
      } else if (redirect === undefined) {
        command.push(word);
      }
      redirect = undefined;
    }
    word = '';
    inWord = false;
  };
  const endCommand = (): void => {
    endWord();
    if (command.length > 0) {
      commands.push(command);
    }
    command = [];
  };
  for (let i = 0; i < script.length; i++) {
    const c = script[i]!;
    if (c === '\\') {
      if (script[i + 1] !== '\n') {
        word += script[i + 1] ?? '';
        inWord = true;
      }
      i++;
    } else if (c === "'") {
      const end = script.indexOf("'", i + 1);
      if (end < 0) {
        return undefined;
      }
      word += script.slice(i + 1, end);
      inWord = true;
      i = end;
    } else if (c === '$' && script[i + 1] === "'") {
      let j = i + 2;
      for (; j < script.length && script[j] !== "'"; j++) {
        if (script[j] === '\\') {
          j++;
        }
      }
      if (j >= script.length) {
        return undefined;
      }
      word += script.slice(i + 2, j);
      inWord = true;
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      for (; j < script.length && script[j] !== '"'; j++) {
        const d = script[j];
        if (d === '`' || (d === '$' && script[j + 1] === '(')) {
          return undefined;
        }
        if (d === '\\') {
          j++;
        }
        word += script[j] ?? '';
      }
      if (j >= script.length) {
        return undefined;
      }
      inWord = true;
      i = j;
    } else if (c === '`' || c === '(' || c === ')' || (c === '$' && script[i + 1] === '(')) {
      return undefined;
    } else if (c === '#' && !inWord) {
      const nl = script.indexOf('\n', i);
      i = nl < 0 ? script.length : nl - 1;
    } else if (c === ' ' || c === '\t') {
      endWord();
    } else if (c === '\n' || c === ';' || c === '&' || c === '|') {
      endCommand();
    } else if (c === '<') {
      if (script[i + 1] === '<' || script[i + 1] === '(') {
        return undefined;
      }
      endWord();
      redirect = 'in';
    } else if (c === '>') {
      if (/^\d+$/.test(word)) {
        word = '';
        inWord = false;
      }
      endWord();
      if (script[i + 1] === '>') {
        i++;
      }
      if (script[i + 1] === '(') {
        return undefined;
      }
      if (script[i + 1] === '&') {
        const m = /^&[\d-]+/.exec(script.slice(i + 1));
        redirects.push(m ? m[0] : '&');
        i += m ? m[0].length : 1;
      } else {
        redirect = 'out';
      }
    } else {
      word += c;
      inWord = true;
    }
  }
  endCommand();
  return redirect === undefined ? { commands, redirects } : undefined;
}

/** Whether a `git …` invocation stays within the read/fetch subcommands with no exec hook. */
function gitRunsNothing(args: string[]): boolean {
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('-c') || a.startsWith('--config-env') || GIT_DIR_OPTION_RE.test(a)) {
      return false;
    }
    if (!a.startsWith('-')) {
      break;
    }
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (sub === 'config') {
    const key = rest.find((x) => !x.startsWith('-'));
    return key !== undefined && GIT_SAFE_CONFIG_KEY_RE.test(key);
  }
  return (
    sub !== undefined &&
    GIT_SAFE_SUBCOMMANDS.has(sub) &&
    !rest.some((x) => GIT_EXEC_OPTION_RE.test(x)) &&
    !(GIT_REMOTE_SUBCOMMANDS.has(sub) && rest.some((x) => x.includes('$')))
  );
}

// `${{ }}` values a PR author cannot shape into shell: SHAs, numbers, ids, repo names, the base
// ref, secrets, runner facts. GitHub pastes any other expression into the script before bash
// runs, so it counts as executing (0096).
const INERT_EXPRESSION_RES = [
  /^(?:secrets|runner)\.\w+$/,
  /^github\.(?:sha|ref|ref_name|run_id|run_number|run_attempt|repository|repository_owner|workspace|base_ref|server_url|api_url|event_name)$/,
  /^github\.[\w.]*(?:\.sha|_sha|\.number|\.clone_url|\.full_name|\.base\.ref)$/,
];

export interface RunContext {
  /** The step runs outside the workspace root (`defaults.run.working-directory`). */
  workingDirectory?: boolean;
  /** The job or workflow `env:` sets a loader variable such as PATH. */
  loaderEnv?: boolean;
}

/**
 * Whether a `run:` script can execute code from the workspace (0096). Conservative: a script
 * is non-executing only when it parses cleanly and every simple command is a plain builtin or
 * a read/fetch git command run from the workspace root, nothing sets PATH or a loader
 * variable, and output goes nowhere a later command loads. Anything else counts as
 * executing, so the check can only drop a fail whose step plainly runs nothing.
 */
export function runsWorkspaceCode(step: StepSpec, context: RunContext = {}): boolean {
  if (typeof step.run !== 'string') {
    return false;
  }
  if (step.shell !== undefined && step.shell !== 'bash' && step.shell !== 'sh') {
    return true;
  }
  if (context.loaderEnv || Object.keys(step.env ?? {}).some((k) => LOADER_ENV_RE.test(k))) {
    return true;
  }
  let unsafeExpression = false;
  const raw = step.run.replace(/\$\{\{([\s\S]*?)\}\}/g, (_, expr: string) => {
    unsafeExpression ||= !INERT_EXPRESSION_RES.some((re) => re.test(expr.trim()));
    return 'X';
  });
  if (unsafeExpression) {
    return true;
  }
  if (/GITHUB_ENV|GITHUB_PATH/.test(raw)) {
    return true;
  }
  // `${A:$T}` and `${arr[$T]}` evaluate their inner text as arithmetic, which runs `a[$(cmd)]`.
  if (/\$\{[^}]*[$[]/.test(raw)) {
    return true;
  }
  const parsed = readShell(raw);
  if (!parsed || parsed.redirects.some((t) => !SAFE_REDIRECT_TARGET_RE.test(t))) {
    return true;
  }
  // A directory the PR controls can hold a committed bare repo whose config git then loads.
  let movedDir = step['working-directory'] !== undefined || context.workingDirectory === true;
  for (const words of parsed.commands) {
    let i = 0;
    while (i < words.length && (SHELL_KEYWORDS.has(words[i]!) || ASSIGNMENT_RE.test(words[i]!))) {
      if (ASSIGNMENT_RE.test(words[i]!) && LOADER_ENV_RE.test(words[i]!)) {
        return true;
      }
      i++;
    }
    const name = words[i];
    const args = words.slice(i + 1);
    if (name === undefined) {
      continue;
    }
    if (name === 'git') {
      if (movedDir || !gitRunsNothing(args)) {
        return true;
      }
    } else if (!NON_EXECUTING_COMMANDS.has(name)) {
      return true;
    } else if (name === 'export' && args.some((x) => LOADER_ENV_RE.test(x))) {
      return true;
    } else if (name === 'cd' || name === 'pushd' || name === 'popd') {
      movedDir = true;
    }
  }
  return false;
}

/**
 * Key path within a job of the first scalar that references each `secrets.X`, so a report
 * can cite where the job exposes the secret (0096).
 */
export function secretRefPaths(job: JobSpec): Map<string, (string | number)[]> {
  const found = new Map<string, (string | number)[]>();
  const walk = (value: unknown, path: (string | number)[]): void => {
    if (typeof value === 'string') {
      for (const m of value.matchAll(SECRET_RE)) {
        if (m[1] && !found.has(m[1])) {
          found.set(m[1], path);
        }
      }
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, [...path, i]));
    } else if (value && typeof value === 'object') {
      Object.entries(value as Record<string, unknown>).forEach(([k, v]) => walk(v, [...path, k]));
    }
  };
  walk(job, []);
  return found;
}

// Commands that run the checked-out project's own code or build files.
const BUILD_TOOL_RE =
  /^(?:\.{1,2}\/\S+|npm|npx|yarn|pnpm|bun|node|make|gradle|mvn|python3?|pip3?|poetry|pytest|tox|go|cargo|bundle|rake|ruby|dotnet|composer|php|sh|bash)$/;

/** A step that plainly runs project code: a local action, or a build/test tool command. */
export function runsBuildTooling(step: StepSpec): boolean {
  if (typeof step.uses === 'string') {
    return step.uses.startsWith('./');
  }
  if (typeof step.run !== 'string') {
    return false;
  }
  const parsed = readShell(step.run.replace(/\$\{\{[\s\S]*?\}\}/g, 'X'));
  return (parsed?.commands ?? []).some((words) => {
    const name = words.find((w) => !SHELL_KEYWORDS.has(w) && !ASSIGNMENT_RE.test(w));
    return name !== undefined && BUILD_TOOL_RE.test(name);
  });
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
