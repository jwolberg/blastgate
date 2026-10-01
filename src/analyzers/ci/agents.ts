/**
 * Agent-in-CI profiles (KTD1): one cited, versioned entry per recognized AI agent
 * action, recording its trigger gate, the inputs that open the gate to outsiders,
 * the inputs that grant tools, and its documented defaults (R2). A ref outside the
 * profile's range is `unknown` and can only warn (R9). Defaults were re-read
 * against each action's source at the pinned versions on 2026-10-01.
 */

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
