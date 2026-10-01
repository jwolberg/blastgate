/**
 * Untrusted-text → agent injection detection (0022).
 *
 * The AISI Mythos-5 injection lived in a GitHub issue read by an AI triage agent.
 * Blastgate scans committed workflows offline, so what it can see deterministically
 * is the *configuration* that opens the path: a job triggered by an event that
 * carries attacker-authored free text, which then either pipes that text into a
 * step or runs a coding-agent action that ingests the event by design. When that
 * job also holds a secret/token, the injection is a reachable exfiltration path.
 */

import type { SinkClass } from '../../graph/types';
import { agentProfileFor } from './agents';
import {
  collectStrings,
  hasActorGuard,
  hasScriptPermissionGuard,
  isLabelGated,
  type JobSpec,
  type StepSpec,
} from './parse';

/** Events that carry attacker-authored free text (issue/PR/discussion bodies, comments). */
export const UNTRUSTED_TEXT_EVENTS = new Set([
  'issues',
  'issue_comment',
  'pull_request_target',
  'pull_request',
  'pull_request_review',
  'pull_request_review_comment',
  'discussion',
  'discussion_comment',
]);

export function untrustedTextTriggers(triggers: string[]): string[] {
  return triggers.filter((t) => UNTRUSTED_TEXT_EVENTS.has(t));
}

/**
 * Untrusted-text events that ALSO run privileged (base-repo context), so an injection
 * into them can actually reach the job's secrets / writable token. Plain `pull_request`
 * is excluded: a fork PR runs with a READ-ONLY token and no secrets, so an injection
 * there is a code-execution risk on the runner — not a credential exfiltration path (the
 * sink Blastgate models). Mirrors parse.ts's `credentialReachableTriggers` for the
 * fork-PR entry, so both entry kinds honor GitHub's fork-token rule identically.
 */
export function credentialReachableTextTriggers(triggers: string[]): string[] {
  return untrustedTextTriggers(triggers).filter((t) => t !== 'pull_request');
}

// Attacker-authored fields of the event payload: `.body` / `.title` on issue,
// comment, pull_request, review, discussion. Numbers/ids/logins are not free text.
const UNTRUSTED_TEXT_REF = /github\.event\.[\w.]*(?:body|title)\b/g;
// Non-global copy for boolean membership tests (avoids shared-lastIndex hazards).
const UNTRUSTED_TEXT_REF_TEST = /github\.event\.[\w.]*(?:body|title)\b/;
// Boolean expression functions that only *compare* their argument to a literal —
// `contains(<text>, '…')` etc. — so untrusted text inside one is matched, not injected.
const BOOLEAN_GUARD_CALL = /\b(?:contains|startsWith|endsWith)\s*\([^()]*\)/g;

// Coding-agent actions with no profile (agents.ts) that still read the event context by
// design (so the body reaches the agent even without an explicit `${{ … }}` interpolation).
const UNPROFILED_AGENT_RE =
  /(?:anthropics\/claude|claude-code|opencode|aider|sweep-ai|gpt-engineer)/i;

/** A recognized agent or LLM action: a profiled one (U1) or an unprofiled agent name. */
function isAgentAction(uses: string): boolean {
  return agentProfileFor(uses) !== undefined || UNPROFILED_AGENT_RE.test(uses);
}

/** A coding agent: ingests the event by design, unlike a tool-less LLM step (R8). */
function isCodingAgent(uses: string): boolean {
  const resolved = agentProfileFor(uses);
  return resolved ? !resolved.profile.toolLess : UNPROFILED_AGENT_RE.test(uses);
}

/** The attacker-authored event-text expressions a job interpolates into its steps. */
export function injectableTextRefs(job: JobSpec): string[] {
  const strings: string[] = [];
  collectStrings(job, strings);
  const refs = new Set<string>();
  for (const s of strings) {
    for (const m of s.matchAll(UNTRUSTED_TEXT_REF)) {
      refs.add(m[0]);
    }
  }
  return [...refs];
}

/** Known agent and LLM actions a job runs. */
export function agentActionsUsed(job: JobSpec): string[] {
  return (job.steps ?? [])
    .map((s) => s.uses)
    .filter((u): u is string => typeof u === 'string')
    .filter(isAgentAction);
}

/**
 * A job is a prompt-injection surface when an untrusted-text event triggers it AND
 * it either interpolates attacker-authored event text or runs an agent that ingests
 * the event. (Guard/handling exemptions are applied by the analyzer via
 * `injectionNeutralized`, mirroring U17/0017.)
 */
export function isInjectableAgentJob(job: JobSpec, triggers: string[]): boolean {
  if (untrustedTextTriggers(triggers).length === 0) {
    return false;
  }
  return injectableTextRefs(job).length > 0 || agentActionsUsed(job).length > 0;
}

/**
 * Whether the job's untrusted text is *only ever compared*, never injected (0044):
 * every `github.event.*.body/title` reference appears solely inside a boolean guard
 * (`contains`/`startsWith`/`endsWith`), and no coding-agent action is present (an agent
 * ingests the event context regardless of how the text is passed). pytorch's
 * `claude-code.yml` — where the comment body only feeds `contains(…, 'fable')`-style
 * effort/model switches and is deliberately kept out of the agent args — is this shape.
 * A single bare interpolation (`echo ${{ github.event.issue.body }}`) makes it false.
 */
export function textOnlyBooleanMatched(job: JobSpec): boolean {
  if (agentActionsUsed(job).length > 0) {
    return false;
  }
  const strings: string[] = [];
  collectStrings(job, strings);
  let sawRef = false;
  for (const s of strings) {
    if (!UNTRUSTED_TEXT_REF_TEST.test(s)) {
      continue;
    }
    sawRef = true;
    // Remove boolean-guard calls; any text ref left is a real (non-comparison) use.
    if (UNTRUSTED_TEXT_REF_TEST.test(s.replace(BOOLEAN_GUARD_CALL, ''))) {
      return false;
    }
  }
  return sawRef;
}

/**
 * Whether a text-injection finding is neutralized by a recognized guard or safe handling
 * (0044). Any of: an `if:` actor guard (0017), a label gate, an in-step github-script
 * permission-check-with-throw, or text that is only boolean-matched. Conservative — an
 * unrecognized guard leaves the finding standing (fail-closed, like 0041). This applies to
 * the TEXT path only; `workflow_run` artifact injection (0042) keys on a real shell-splice
 * sink and is never softened here.
 */
export function injectionNeutralized(job: JobSpec): boolean {
  return (
    hasActorGuard(job) ||
    isLabelGated(job) ||
    hasScriptPermissionGuard(job) ||
    textOnlyBooleanMatched(job)
  );
}

/** A step that downloads a CI artifact (the artifact may originate from an untrusted run). */
export function downloadsArtifact(job: JobSpec): boolean {
  return (job.steps ?? []).some((s) => {
    if (typeof s.uses === 'string' && /actions\/download-artifact/.test(s.uses)) {
      return true;
    }
    const script = typeof s.with?.script === 'string' ? s.with.script : '';
    return (
      (typeof s.run === 'string' && /gh\s+run\s+download|downloadArtifact\s*\(/.test(s.run)) ||
      /downloadArtifact\s*\(/.test(script)
    );
  });
}

/** A command substitution that reads a file: `$(<file)` or `$(cat file)`. */
const FILE_SUBSTITUTION_AT = /^\$\(\s*(?:<|cat\s)/;
/** Text immediately before `$(` that makes it an assignment's right-hand side. */
const ASSIGNMENT_BEFORE =
  /(?:^|[\s;&|])(?:(?:export|local|readonly|declare)\s+(?:-\w+\s+)*)?[A-Za-z_]\w*=$/;

/**
 * Whether a `run:` script splices a file's contents into a command (0054 / plan KTD9): an
 * unquoted `$(<file)` / `$(cat file)` in command-word or argument position, where the
 * contents are word-split into the command line (argument injection at minimum). An
 * assignment (`X=$(cat f)`, incl. `export`/`local`) neither executes nor word-splits the
 * value, and a substitution inside quotes cannot add arguments — neither is a sink.
 * Quote tracking spans the whole script, so multi-line quoted strings are handled; shell
 * comments and heredoc bodies are skipped (here-strings and `$(( … ))` shifts are not
 * heredocs), and quotes left open at the end fail closed to a
 * plain match (PR #36 review).
 * Accepted false negative: a quoted `"$(<f)"` used as a whole argument can still inject a
 * leading `--flag`.
 */
export function splicesFileIntoCommand(run: string): boolean {
  let inDouble = false;
  let inSingle = false;
  let heredocs: { word: string; stripTabs: boolean }[] = [];
  for (let i = 0; i < run.length; i++) {
    const c = run[i];
    if (inSingle) {
      inSingle = c !== "'";
      continue;
    }
    if (c === '\\') {
      i++; // skip the escaped character (incl. a line continuation)
      continue;
    }
    if (!inDouble && c === '#' && (i === 0 || /[\s;&|(]/.test(run[i - 1] ?? ''))) {
      // A comment runs to end of line; its quotes and substitutions are inert.
      const nl = run.indexOf('\n', i);
      if (nl < 0) {
        break;
      }
      i = nl - 1;
      continue;
    }
    if (!inDouble && run.startsWith('$((', i)) {
      // Arithmetic expansion: `<<` in here is a shift, never a heredoc.
      let depth = 0;
      let j = i + 1;
      for (; j < run.length; j++) {
        depth += run[j] === '(' ? 1 : run[j] === ')' ? -1 : 0;
        if (depth === 0) {
          break;
        }
      }
      if (j >= run.length) {
        continue; // unclosed `$((`: don't skip, keep scanning normally
      }
      if (/\$\(\s*(?:<|cat\s)/.test(run.slice(i + 3, j))) {
        return true; // a file read inside arithmetic is evaluated as an expression
      }
      i = j;
      continue;
    }
    if (!inDouble && run.startsWith('<<<', i)) {
      i += 2; // a here-string, not a heredoc
      continue;
    }
    if (!inDouble && c === '<' && run[i + 1] === '<') {
      const m = /^<<(-?)\s*(['"]?)([A-Za-z_]\w*)\2/.exec(run.slice(i));
      if (m) {
        heredocs.push({ word: m[3]!, stripTabs: m[1] === '-' });
        i += m[0].length - 1;
        continue;
      }
    }
    if (c === '\n' && !inDouble && heredocs.length > 0) {
      // Skip each pending heredoc body: it is stdin text, never command arguments.
      let pos = i + 1;
      for (const h of heredocs) {
        while (pos < run.length) {
          const end = run.indexOf('\n', pos);
          const line = run.slice(pos, end < 0 ? run.length : end);
          pos = end < 0 ? run.length : end + 1;
          if ((h.stripTabs ? line.replace(/^\t+/, '') : line) === h.word) {
            break;
          }
        }
      }
      heredocs = [];
      i = pos - 1;
      continue;
    }
    if (c === "'" && !inDouble) {
      inSingle = true;
    } else if (c === '"') {
      inDouble = !inDouble;
    } else if (!inDouble && c === '$' && FILE_SUBSTITUTION_AT.test(run.slice(i))) {
      const before = run.slice(run.lastIndexOf('\n', i - 1) + 1, i);
      if (!ASSIGNMENT_BEFORE.test(before)) {
        return true;
      }
    }
  }
  // Quotes left open mean the scan lost track of the script: fail closed to a plain match.
  return inSingle || inDouble ? /\$\(\s*(?:<|cat\s)/.test(run) : false;
}

/** A `run:` step that splices a file's contents into a command (0042, sharpened by 0054). */
export function readsFileIntoShell(job: JobSpec): boolean {
  return (job.steps ?? []).some((s) => typeof s.run === 'string' && splicesFileIntoCommand(s.run));
}

/**
 * workflow_run artifact injection (0042): a privileged `workflow_run` job downloads an
 * artifact built by the (untrusted) `pull_request` run and then splices its contents into
 * a shell via command substitution (`gh pr comment $(<PRurl)`). The downloaded content is
 * attacker-controlled, so this is command/argument injection in a privileged context —
 * the one genuine finding the top-25 assessment surfaced (and the shape single-layer tools
 * miss). Passing the artifact as a *quoted argument to a trusted committed script* is NOT
 * this — only a shell-substitution sink counts.
 */
export function workflowRunArtifactInjection(job: JobSpec, triggers: string[]): boolean {
  return triggers.includes('workflow_run') && downloadsArtifact(job) && readsFileIntoShell(job);
}

const SINK_STRENGTH: Record<SinkClass, number> = {
  execution: 4,
  'agent-ingested': 3,
  'action-input': 2,
  unrecognized: 1,
};

export interface UntrustedTextSink {
  sinkClass: SinkClass;
  /** Job-relative key path of the sink (e.g. `['steps', 1, 'run']`), for the source locator. */
  path: (string | number)[];
}

const GITHUB_SCRIPT_RE = /actions\/github-script/;

/** Untrusted text that is interpolated, not merely compared inside a boolean guard call. */
function interpolatesUntrustedText(value: unknown): boolean {
  const strings: string[] = [];
  collectStrings(value, strings);
  return strings.some((s) => UNTRUSTED_TEXT_REF_TEST.test(s.replace(BOOLEAN_GUARD_CALL, '')));
}

/** Keys that never inject: `env` passes text safely as a variable, `if` only compares, `name`/`id` only label. */
const INERT_KEYS = new Set(['env', 'if', 'name', 'id', 'uses']);

type Hit = { sinkClass: SinkClass; path: (string | number)[] };

// A github-script step calling GitHub Models is a tool-less LLM step (KTD7).
const MODELS_ENDPOINT_RE = /models\.github\.ai|models\.inference\.ai\.azure\.com/;
const STEP_OUTPUT_REF = /steps\.([\w-]+)\.outputs\b/g;
const ENV_REF = /\benv\.([A-Za-z_]\w*)/g;

/**
 * Where untrusted text sits in a job beyond direct interpolation: env vars that hold it
 * and step ids whose outputs may carry it. Only an LLM step consults this — `env:` keeps
 * text out of a shell, but a model reads it all the same (R8).
 */
interface Taint {
  env: Set<string>;
  steps: Set<string>;
}

function taintedEnvNames(env: unknown): string[] {
  if (!env || typeof env !== 'object') {
    return [];
  }
  return Object.entries(env as Record<string, unknown>)
    .filter(([, v]) => interpolatesUntrustedText(v))
    .map(([k]) => k);
}

/** Untrusted text, or a reference to a tainted env var or step output, anywhere in `value`. */
function carriesTaint(value: unknown, taint: Taint): boolean {
  const strings: string[] = [];
  collectStrings(value, strings);
  return strings.some(
    (s) =>
      UNTRUSTED_TEXT_REF_TEST.test(s.replace(BOOLEAN_GUARD_CALL, '')) ||
      [...s.matchAll(STEP_OUTPUT_REF)].some((m) => taint.steps.has(m[1] ?? '')) ||
      [...s.matchAll(ENV_REF)].some((m) => taint.env.has(m[1] ?? '')),
  );
}

/**
 * A tool-less LLM step (actions/ai-inference, or github-script calling GitHub Models) that
 * untrusted text reaches. github-script reads `process.env`, so job and step env count.
 */
function llmIngestsTaint(step: StepSpec, uses: string, taint: Taint): boolean {
  if (agentProfileFor(uses)?.profile.toolLess) {
    return carriesTaint(step.with, taint) || carriesTaint(step.env, taint);
  }
  const script = typeof step.with?.script === 'string' ? step.with.script : '';
  if (!GITHUB_SCRIPT_RE.test(uses) || !MODELS_ENDPOINT_RE.test(script)) {
    return false;
  }
  return taint.env.size > 0 || carriesTaint(step.env, taint) || carriesTaint(script, taint);
}

function classifyStep(step: StepSpec, taint: Taint): Hit | undefined {
  const uses = typeof step.uses === 'string' ? step.uses : '';
  if (interpolatesUntrustedText(step.run)) {
    return { sinkClass: 'execution', path: ['run'] };
  }
  if (GITHUB_SCRIPT_RE.test(uses) && interpolatesUntrustedText(step.with?.script)) {
    return { sinkClass: 'execution', path: ['with', 'script'] };
  }
  // A coding agent ingests the event context by design, with or without an interpolation;
  // a tool-less LLM step ingests whatever untrusted text reaches it.
  if (isCodingAgent(uses) || llmIngestsTaint(step, uses, taint)) {
    return { sinkClass: 'agent-ingested', path: ['uses'] };
  }
  for (const [key, value] of Object.entries(step.with ?? {})) {
    if (interpolatesUntrustedText(value)) {
      return { sinkClass: 'action-input', path: ['with', key] };
    }
  }
  return unrecognizedIn(step, new Set(['run', 'with']));
}

/** Fail-closed: untrusted text in any key we do not classify is `unrecognized`, never dropped. */
function unrecognizedIn(node: object, handled: Set<string>): Hit | undefined {
  for (const [key, value] of Object.entries(node)) {
    if (!handled.has(key) && !INERT_KEYS.has(key) && interpolatesUntrustedText(value)) {
      // Point at the exact child of a map (e.g. `with.title`) so evidence names the input.
      const child =
        value && typeof value === 'object' && !Array.isArray(value)
          ? Object.keys(value).find((k) =>
              interpolatesUntrustedText((value as Record<string, unknown>)[k]),
            )
          : undefined;
      return { sinkClass: 'unrecognized', path: child === undefined ? [key] : [key, child] };
    }
  }
  return undefined;
}

/**
 * Classify the strongest sink untrusted event text reaches in a job (0046). `undefined`
 * when the text never lands anywhere that could inject — only passed through `env:`, only
 * compared in `if:` / `contains()`, or absent. Guard exemptions (R6) are applied by the
 * analyzer, not here.
 */
export function classifyUntrustedText(job: JobSpec): UntrustedTextSink | undefined {
  let best: UntrustedTextSink | undefined;
  const consider = (hit: Hit | undefined, prefix: (string | number)[]): void => {
    if (hit && (!best || SINK_STRENGTH[hit.sinkClass] > SINK_STRENGTH[best.sinkClass])) {
      best = { sinkClass: hit.sinkClass, path: [...prefix, ...hit.path] };
    }
  };
  const taint: Taint = { env: new Set(taintedEnvNames(job.env)), steps: new Set() };
  (job.steps ?? []).forEach((step, i) => {
    const stepTaint: Taint = {
      env: new Set([...taint.env, ...taintedEnvNames(step.env)]),
      steps: taint.steps,
    };
    consider(classifyStep(step, stepTaint), ['steps', i]);
    // A later step may read this one's outputs: they carry whatever text it was given.
    if (typeof step.id === 'string' && carriesTaint(step, stepTaint)) {
      taint.steps.add(step.id);
    }
  });
  // Job-level keys (e.g. a reusable workflow's `with:`) — permissions/secrets hold no event text.
  consider(unrecognizedIn(job, new Set(['steps', 'permissions', 'secrets'])), []);
  return best;
}

/** Index of the `run:` step that splices a downloaded artifact into a shell (0042 evidence). */
export function artifactSpliceStep(job: JobSpec): number | undefined {
  const i = (job.steps ?? []).findIndex(
    (s) => typeof s.run === 'string' && splicesFileIntoCommand(s.run),
  );
  return i >= 0 ? i : undefined;
}
