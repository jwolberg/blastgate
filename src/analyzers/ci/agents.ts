/**
 * Agent-in-CI profiles (KTD1): one cited, versioned entry per recognized AI agent
 * action, recording its trigger gate, the inputs that open the gate to outsiders,
 * the inputs that grant tools, and its documented defaults (R2). A ref outside the
 * profile's range is `unknown` and can only warn (R9). Defaults were re-read
 * against each action's source at the pinned versions on 2026-10-01.
 */

import type { RepoVisibility } from '../../engine/build';
import { credentialReachableTextTriggers } from './injection';
import {
  findSecretRefs,
  hasActorGuard,
  hasScriptPermissionGuard,
  isLabelGated,
  normalizeTriggers,
  resolvePermissions,
  type JobSpec,
  type StepSpec,
  type WorkflowSpec,
} from './parse';

/** Which agent family a profile describes. */
export type AgentId = 'claude' | 'codex' | 'gemini' | 'llm-inference';

/** A version as numeric components, e.g. `v1.0.238` → `[1, 0, 238]`. */
type Version = number[];

export interface AgentProfile {
  id: AgentId;
  /** `owner/repo`, lowercase. */
  action: string;
  /** Covered versions: `[min, below)`. A partial ref (`v1`) must lie wholly inside. */
  range: { min: Version; below: Version };
  /** `write-access`: the action itself refuses actors without repo write access. */
  gate: 'write-access' | 'none';
  /** Inputs whose `'*'` value opens the gate to every outsider. */
  outsiderInputs: string[];
  /** Inputs that grant or restrict the agent's tools. */
  toolInputs: string[];
  /** Inputs that hand the agent a credential. */
  credentialInputs: string[];
  /** Documented defaults that U3's assessment relies on. */
  defaults: Record<string, string>;
  /** No tools of its own: ingests text, cannot act on it (R8). */
  toolLess: boolean;
  /** Full commit SHAs known to fall inside `range`. Empty: every SHA pin is unknown. */
  pinnedShas: string[];
  citations: string[];
}

export const AGENT_PROFILES: readonly AgentProfile[] = [
  {
    id: 'claude',
    action: 'anthropics/claude-code-action',
    range: { min: [1, 0, 0], below: [2, 0, 0] },
    gate: 'write-access',
    outsiderInputs: ['allowed_non_write_users', 'allowed_bots'],
    toolInputs: ['claude_args', 'settings'],
    credentialInputs: ['anthropic_api_key', 'claude_code_oauth_token', 'github_token'],
    // With allowed_non_write_users set, subprocess env is scrubbed of Anthropic,
    // cloud, and Actions secrets unless CLAUDE_CODE_SUBPROCESS_ENV_SCRUB is 0 (KTD2).
    defaults: { subprocessEnvScrub: 'on when allowed_non_write_users is set' },
    toolLess: false,
    pinnedShas: [],
    citations: [
      'https://github.com/anthropics/claude-code-action/blob/v1/docs/security.md',
      'https://github.com/anthropics/claude-code-action/blob/v1/action.yml',
    ],
  },
  {
    id: 'codex',
    action: 'openai/codex-action',
    range: { min: [1, 0, 0], below: [2, 0, 0] },
    gate: 'write-access',
    // `allow-users: '*'` admits every user; `allow-bot-users` rejects '*' and
    // `allow-bots` admits only github-actions[bot].
    outsiderInputs: ['allow-users'],
    toolInputs: ['sandbox', 'permission-profile', 'codex-args', 'safety-strategy'],
    credentialInputs: ['openai-api-key'],
    defaults: { sandbox: 'workspace-write', 'safety-strategy': 'drop-sudo' },
    toolLess: false,
    pinnedShas: [],
    citations: [
      'https://github.com/openai/codex-action/blob/v1/docs/security.md',
      'https://github.com/openai/codex-action/blob/v1/src/checkActorPermissions.ts',
    ],
  },
  {
    id: 'gemini',
    action: 'google-github-actions/run-gemini-cli',
    range: { min: [0, 0, 0], below: [1, 0, 0] },
    // No actor check of its own: any attacker-reachable trigger reaches it (KTD4).
    gate: 'none',
    outsiderInputs: [],
    toolInputs: ['settings'],
    credentialInputs: ['gemini_api_key', 'google_api_key', 'gcp_workload_identity_provider'],
    defaults: { gemini_cli_version: 'latest', mode: '--yolo' },
    toolLess: false,
    pinnedShas: [],
    citations: [
      'https://github.com/google-github-actions/run-gemini-cli/blob/v0/action.yml',
      'https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g',
    ],
  },
  {
    id: 'llm-inference',
    action: 'actions/ai-inference',
    range: { min: [1, 0, 0], below: [4, 0, 0] },
    gate: 'none',
    outsiderInputs: [],
    // Off by default; when set they still only warn (R8) — see implementation notes.
    toolInputs: ['enable-github-mcp', 'provider'],
    credentialInputs: ['token', 'github-mcp-token'],
    defaults: { 'enable-github-mcp': 'false', provider: 'github-models' },
    toolLess: true,
    pinnedShas: [],
    citations: ['https://github.com/actions/ai-inference/blob/v2/action.yml'],
  },
];

export interface AgentResolution {
  profile: AgentProfile;
  /** True when the ref lies inside the profile's version range. */
  covered: boolean;
  /** Why the ref is not covered, naming it (R9). */
  unknown?: string;
}

const SHA_RE = /^[0-9a-f]{40}$/i;
const VERSION_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/;

/**
 * The profile a step's `uses:` names, or undefined when it is not a recognized
 * agent. `covered` is false for a ref no range covers: a branch, an unrecorded
 * SHA, a missing ref, or a version outside the range.
 */
export function agentProfileFor(uses: string): AgentResolution | undefined {
  const at = uses.indexOf('@');
  const name = (at < 0 ? uses : uses.slice(0, at)).toLowerCase();
  const ref = at < 0 ? '' : uses.slice(at + 1);
  const profile = AGENT_PROFILES.find((p) => p.action === name);
  if (!profile) {
    return undefined;
  }
  if (ref === '') {
    return { profile, covered: false, unknown: `${profile.action} has no pinned ref` };
  }
  if (SHA_RE.test(ref)) {
    return profile.pinnedShas.includes(ref.toLowerCase())
      ? { profile, covered: true }
      : {
          profile,
          covered: false,
          unknown: `SHA ${ref} is not a recorded ${profile.action} release`,
        };
  }
  const m = VERSION_RE.exec(ref);
  if (!m) {
    return {
      profile,
      covered: false,
      unknown: `${ref} is a branch, not a ${profile.action} release`,
    };
  }
  const prefix = m
    .slice(1)
    .filter((x) => x !== undefined)
    .map(Number);
  return inRange(prefix, profile.range)
    ? { profile, covered: true }
    : { profile, covered: false, unknown: `no profile covers ${profile.action}@${ref}` };
}

/** A partial ref (`v1` = every 1.x.y) is covered only when all it can point to lies in range. */
function inRange(prefix: Version, range: { min: Version; below: Version }): boolean {
  const lo = pad(prefix);
  const hi = pad([...prefix.slice(0, -1), (prefix.at(-1) ?? 0) + 1]);
  const full = prefix.length === 3;
  return (
    compare(lo, range.min) >= 0 &&
    (full ? compare(lo, range.below) < 0 : compare(hi, range.below) <= 0)
  );
}

function pad(v: Version): Version {
  return [v[0] ?? 0, v[1] ?? 0, v[2] ?? 0];
}

function compare(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) {
      return d;
    }
  }
  return 0;
}

const GEMINI_CLI_FIX: Version = [0, 39, 1];
const GEMINI_CLI_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-preview\.(\d+))?$/;

/**
 * Whether the Gemini CLI a run-gemini-cli step installs ignores the tool allowlist
 * under `--yolo` (fixed in 0.39.1 and 0.40.0-preview.3, GHSA-wpqr-6v78-jr5g). The
 * action defaults `gemini_cli_version` to `latest`, so only an old literal pin is
 * vulnerable; anything Blastgate cannot read as a version is `unknown`.
 */
export function geminiYoloIgnoresAllowlist(cliVersion: unknown): boolean | 'unknown' {
  if (cliVersion === undefined || cliVersion === null || cliVersion === '') {
    return false;
  }
  if (typeof cliVersion !== 'string') {
    return 'unknown';
  }
  if (['latest', 'preview', 'nightly'].includes(cliVersion)) {
    return false;
  }
  const m = GEMINI_CLI_RE.exec(cliVersion);
  if (!m) {
    return 'unknown';
  }
  const v = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (m[4] !== undefined && compare(v, [0, 40, 0]) === 0) {
    return Number(m[4]) < 3;
  }
  return compare(v, GEMINI_CLI_FIX) < 0;
}

// ---- Rule-of-Two assessment (U3) ----

/** One Rule-of-Two leg: held, missing, or not readable from configuration. */
export type Leg = 'held' | 'missing' | 'unknown';

export interface AgentAssessment {
  /** The step's `uses:`. */
  uses: string;
  profileId?: AgentId;
  /** The ref lies in the profile's version range (R9). */
  covered: boolean;
  /** R3: an outsider can trigger the agent step itself. */
  direct: Leg;
  /** R4: the agent has a tool that can read a credential the job holds. */
  access: Leg;
  /** R5: the agent has a way to get data out. */
  exfil: Leg;
  /** Why each leg is held, missing, or unknown (R10). */
  reasons: { direct: string; access: string; exfil: string };
  /** What Blastgate could not read (R9). */
  unknown: string[];
}

export interface AssessInputs {
  workflow: WorkflowSpec;
  job: JobSpec;
  stepIndex: number;
  visibility: RepoVisibility;
}

/** What the agent's granted tools can do. */
interface Tools {
  shell: Leg;
  fileRead: Leg;
  network: Leg;
}

const NO_TOOLS: Tools = { shell: 'missing', fileRead: 'missing', network: 'missing' };
const ALL_TOOLS: Tools = { shell: 'held', fileRead: 'held', network: 'held' };

const isExpression = (v: unknown): boolean => typeof v === 'string' && v.includes('${{');
const str = (v: unknown): string => (typeof v === 'string' ? v : v === undefined ? '' : String(v));

/**
 * Judge one agent step against the Agents Rule of Two (R3–R5). Every leg names why it
 * holds or not (R10); anything unreadable — an uncovered version, a non-literal tool
 * grant — is recorded in `unknown` (R9). Only an assessment whose three legs are all
 * `held` and whose version is covered may fail (U5).
 */
export function assessAgentStep(inputs: AssessInputs): AgentAssessment {
  const { workflow, job, stepIndex } = inputs;
  const step = job.steps?.[stepIndex] ?? {};
  const uses = str(step.uses);
  const resolved = agentProfileFor(uses);
  if (!resolved) {
    const why = `no profile for ${uses}`;
    return {
      uses,
      covered: false,
      direct: 'unknown',
      access: 'unknown',
      exfil: 'unknown',
      reasons: { direct: why, access: why, exfil: why },
      unknown: [why],
    };
  }
  const { profile } = resolved;
  const unknown: string[] = resolved.unknown ? [resolved.unknown] : [];
  const tools = toolsOf(profile, step, unknown);
  const direct = directLeg(profile, workflow, job, step, unknown);
  const access = accessLeg(profile, workflow, job, stepIndex, tools);
  const exfil = exfilLeg(workflow, job, tools, inputs.visibility);
  return {
    uses,
    profileId: profile.id,
    covered: resolved.covered,
    direct: direct.leg,
    access: access.leg,
    exfil: exfil.leg,
    reasons: { direct: direct.why, access: access.why, exfil: exfil.why },
    unknown,
  };
}

type Verdict = { leg: Leg; why: string };

/** R3: an attacker-reachable trigger, the action's gate absent or opened, and no job guard. */
function directLeg(
  profile: AgentProfile,
  workflow: WorkflowSpec,
  job: JobSpec,
  step: StepSpec,
  unknown: string[],
): Verdict {
  const events = credentialReachableTextTriggers(normalizeTriggers(workflow.on));
  if (events.length === 0) {
    return { leg: 'missing', why: 'no outsider-triggerable event starts this job' };
  }
  if (hasActorGuard(job) || isLabelGated(job) || hasScriptPermissionGuard(job)) {
    return { leg: 'missing', why: 'a job guard restricts who can trigger it' };
  }
  const on = events.join('/');
  if (profile.gate === 'none') {
    return { leg: 'held', why: `any ${on} author triggers it (the action has no actor check)` };
  }
  let sawExpression = false;
  for (const input of profile.outsiderInputs) {
    const value = step.with?.[input];
    if (isExpression(value)) {
      sawExpression = true;
      continue;
    }
    const opened = str(value)
      .split(',')
      .some((v) => v.trim() === '*');
    // allowed_non_write_users only works with an explicit github_token (not App auth).
    const effective =
      opened && (input !== 'allowed_non_write_users' || str(step.with?.github_token) !== '');
    if (effective) {
      return { leg: 'held', why: `\`${input}: '*'\` lets any ${on} author trigger it` };
    }
  }
  if (sawExpression) {
    unknown.push(`${profile.action} gate inputs are non-literal`);
    return { leg: 'unknown', why: 'its write-access gate inputs are non-literal' };
  }
  return {
    leg: 'missing',
    why: 'the action requires write access to trigger it, so outsider text arrives only indirectly',
  };
}

/** The tools a step grants, from its profile's tool inputs. */
function toolsOf(profile: AgentProfile, step: StepSpec, unknown: string[]): Tools {
  const w = step.with ?? {};
  switch (profile.id) {
    case 'claude':
      return claudeTools(w, unknown);
    case 'codex':
      // `codex exec` always runs commands; only `danger-full-access` opens the network.
      return {
        shell: 'held',
        fileRead: 'held',
        network: str(w.sandbox) === 'danger-full-access' ? 'held' : 'missing',
      };
    case 'gemini':
      return geminiTools(w, unknown);
    case 'llm-inference':
      return NO_TOOLS;
  }
}

const CLAUDE_BYPASS_RE = /--dangerously-skip-permissions|--permission-mode[\s=]+bypassPermissions/;
const CLAUDE_TOOLS_FLAG_RE = /--allowed-?tools[\s=]+((?:"[^"]*"|'[^']*'|[^\s-][^\s]*|\s+)+)/gi;
const TOOL_TOKEN_RE = /([A-Za-z]+)(?:\(([^)]*)\))?/g;

/** claude-code-action: only explicitly granted tools count (`claude_args`, `settings`). */
function claudeTools(w: Record<string, unknown>, unknown: string[]): Tools {
  const args = w.claude_args;
  if (isExpression(args)) {
    unknown.push('claude_args is a non-literal expression');
    return { shell: 'unknown', fileRead: 'unknown', network: 'unknown' };
  }
  if (CLAUDE_BYPASS_RE.test(str(args))) {
    return ALL_TOOLS;
  }
  const granted: string[] = [];
  for (const m of str(args).matchAll(CLAUDE_TOOLS_FLAG_RE)) {
    granted.push(m[1] ?? '');
  }
  const settings = parseJsonInput(w.settings);
  if (settings === 'unreadable') {
    unknown.push('settings is not inline JSON');
  } else {
    const allow = (settings as { permissions?: { allow?: unknown } } | undefined)?.permissions
      ?.allow;
    if (Array.isArray(allow)) {
      granted.push(...allow.map(str));
    }
  }
  const tools = { ...NO_TOOLS };
  for (const m of granted.join(' ').matchAll(TOOL_TOKEN_RE)) {
    const [, name, spec] = m;
    if (name === 'Bash' && (spec === undefined || /^\s*\*?\s*(?::\s*\*)?\s*$/.test(spec))) {
      tools.shell = tools.fileRead = tools.network = 'held';
    } else if (name === 'Read') {
      tools.fileRead = 'held';
    } else if (name === 'WebFetch') {
      tools.network = 'held';
    }
  }
  if (settings === 'unreadable' && tools.shell !== 'held') {
    return { shell: 'unknown', fileRead: 'unknown', network: 'unknown' };
  }
  return tools;
}

/** run-gemini-cli runs `--yolo`: every tool unless `settings` restricts the core set. */
function geminiTools(w: Record<string, unknown>, unknown: string[]): Tools {
  const settings = parseJsonInput(w.settings);
  if (settings === 'unreadable') {
    unknown.push('settings is not inline JSON');
    return { shell: 'unknown', fileRead: 'unknown', network: 'unknown' };
  }
  const s = settings as { tools?: { core?: unknown }; coreTools?: unknown } | undefined;
  const core = s?.tools?.core ?? s?.coreTools;
  if (!Array.isArray(core)) {
    return ALL_TOOLS;
  }
  const list = core.map(str);
  const bypass = geminiYoloIgnoresAllowlist(w.gemini_cli_version);
  if (bypass === 'unknown') {
    unknown.push('gemini_cli_version is not a readable version');
  }
  const restrictedShell = list.some((t) => t.startsWith('run_shell_command('));
  const shell: Leg = list.includes('run_shell_command')
    ? 'held'
    : restrictedShell && bypass === true
      ? 'held'
      : restrictedShell && bypass === 'unknown'
        ? 'unknown'
        : 'missing';
  return {
    shell,
    fileRead:
      shell === 'held' || list.some((t) => /^read_(?:many_)?files?$/.test(t)) ? 'held' : shell,
    network:
      shell === 'held' || list.some((t) => /^(?:web_fetch|google_web_search)$/.test(t))
        ? 'held'
        : shell,
  };
}

/** An action input holding inline JSON: parsed, absent (undefined), or unreadable. */
function parseJsonInput(v: unknown): unknown {
  if (v === undefined || v === '') {
    return undefined;
  }
  if (typeof v !== 'string' || isExpression(v)) {
    return 'unreadable';
  }
  try {
    return JSON.parse(v);
  } catch {
    return 'unreadable';
  }
}

const AUTH_FILE_ACTION_RE = /^google-github-actions\/auth@/i;

/** R4: a tool that can read a credential the job holds (Precision Core 0047 rules). */
function accessLeg(
  profile: AgentProfile,
  workflow: WorkflowSpec,
  job: JobSpec,
  stepIndex: number,
  tools: Tools,
): Verdict {
  if (profile.toolLess) {
    return { leg: 'missing', why: 'a tool-less LLM step cannot read credentials' };
  }
  const step = job.steps?.[stepIndex] ?? {};
  const perms = resolvePermissions(workflow, job);
  const scrubbed = profile.id === 'claude' && claudeScrubs(workflow, job, step);
  const envCreds: string[] = [];
  if (!scrubbed) {
    const secrets = findSecretRefs(withoutHiddenKey(profile, job, stepIndex));
    if (secrets.usesAllSecrets || secrets.names.length > 0) {
      envCreds.push(secrets.usesAllSecrets ? 'every repo secret' : secrets.names.join(', '));
    }
    if (perms.codeWrite) {
      envCreds.push('a contents:write GITHUB_TOKEN');
    }
    if (perms.mintsCredentials) {
      envCreds.push('an id-token:write OIDC token');
    }
  }
  const diskCreds = onDiskCredentials(profile, job, stepIndex, perms.codeWrite);
  const readable = [
    ...(tools.shell === 'held' ? envCreds : []),
    ...(tools.shell === 'held' || tools.fileRead === 'held' ? diskCreds : []),
  ];
  if (readable.length > 0) {
    return { leg: 'held', why: `its tools can read ${readable.join('; ')}` };
  }
  const anyCreds = envCreds.length + diskCreds.length > 0;
  if (anyCreds && (tools.shell === 'unknown' || tools.fileRead === 'unknown')) {
    return { leg: 'unknown', why: 'the job holds credentials but the tool grants are unreadable' };
  }
  if (scrubbed && diskCreds.length === 0) {
    return {
      leg: 'missing',
      why: 'subprocess secret scrubbing is on and no credential is on disk',
    };
  }
  return {
    leg: 'missing',
    why: anyCreds
      ? 'no granted tool can read the credentials the job holds'
      : 'the job holds no secret, code-write token, or OIDC token',
  };
}

/**
 * codex-action serves its `openai-api-key` through a proxy and, under the default
 * `drop-sudo` (or `unprivileged-user`), Codex cannot read it back. Only `unsafe` exposes
 * it. Drop the key input so it is not counted as a readable secret.
 */
function withoutHiddenKey(profile: AgentProfile, job: JobSpec, stepIndex: number): JobSpec {
  const step = job.steps?.[stepIndex];
  if (profile.id !== 'codex' || !step || str(step.with?.['safety-strategy']) === 'unsafe') {
    return job;
  }
  const rest = Object.fromEntries(
    Object.entries(step.with ?? {}).filter(([k]) => !profile.credentialInputs.includes(k)),
  );
  const steps = [...(job.steps ?? [])];
  steps[stepIndex] = { ...step, with: rest };
  return { ...job, steps };
}

/** KTD2: with `allowed_non_write_users`, claude scrubs subprocess env unless the var is 0. */
function claudeScrubs(workflow: WorkflowSpec, job: JobSpec, step: StepSpec): boolean {
  if (str(step.with?.allowed_non_write_users) === '') {
    return false;
  }
  const envs = [step.env, job.env, workflow.env];
  return !envs.some((e) => str(e?.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB).trim() === '0');
}

/** Credentials on the runner's disk before the agent runs (readable despite env scrubbing). */
function onDiskCredentials(
  profile: AgentProfile,
  job: JobSpec,
  stepIndex: number,
  codeWrite: boolean,
): string[] {
  const out: string[] = [];
  const before = (job.steps ?? []).slice(0, stepIndex);
  const persisted = before.some(
    (s) =>
      /^actions\/checkout@/i.test(str(s.uses)) &&
      str(s.with?.['persist-credentials']).toLowerCase() !== 'false',
  );
  if (persisted && codeWrite) {
    out.push('the contents:write token actions/checkout persisted in .git/config');
  }
  if (before.some((s) => AUTH_FILE_ACTION_RE.test(str(s.uses)))) {
    out.push('the credentials file google-github-actions/auth wrote');
  }
  const step = job.steps?.[stepIndex];
  if (profile.id === 'gemini' && str(step?.with?.gcp_workload_identity_provider) !== '') {
    out.push('the GCP credentials file from gcp_workload_identity_provider (OIDC)');
  }
  return out;
}

const PUBLIC_SURFACE_SCOPES = ['issues', 'pull-requests', 'discussions'];

/** R5: a shell or network tool, a token that writes a public surface, or public logs. */
function exfilLeg(
  workflow: WorkflowSpec,
  job: JobSpec,
  tools: Tools,
  visibility: RepoVisibility,
): Verdict {
  if (tools.shell === 'held' || tools.network === 'held') {
    return { leg: 'held', why: 'it has a shell or network tool' };
  }
  const p = job.permissions ?? workflow.permissions;
  const scopes = p && typeof p === 'object' ? (p as Record<string, unknown>) : {};
  const surface =
    p === 'write-all' ? 'every surface' : PUBLIC_SURFACE_SCOPES.find((s) => scopes[s] === 'write');
  if (surface) {
    return { leg: 'held', why: `its token can write ${surface}, which the agent's output reaches` };
  }
  if (visibility === 'public') {
    return { leg: 'held', why: 'the repo is public, so its Actions logs are publicly readable' };
  }
  if (tools.shell === 'unknown' || tools.network === 'unknown') {
    return { leg: 'unknown', why: 'its tool grants are unreadable' };
  }
  return {
    leg: 'missing',
    why:
      visibility === 'unknown'
        ? 'no shell, network, or public-write tool, and repository visibility is unknown'
        : 'no shell, network, or public-write tool, and the repo is private',
  };
}
