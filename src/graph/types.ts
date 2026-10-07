/**
 * The attack-surface graph model: typed nodes (one variant per layer) and typed
 * directed edges. Every analyzer emits into this shape; reachability traverses it.
 * See plan U2 / KTD2 and the graph-schema diagram in the plan's HTD.
 */

export type NodeKind = 'entry' | 'dependency' | 'ci-job' | 'agent-grant' | 'sink';

/**
 * How a finding's entry point arises. Most are attacker-controllable; `privileged-hook`
 * is the exception — a committed, deterministic privileged capability (a `type: command`
 * hook) that fires without any prompt injection, surfaced as a scope-review advisory
 * rather than an injectable surface (U18). `ci-divergent` is an install/build script
 * engineered to behave differently under observation to evade CI (0021).
 */
export type EntryKind =
  | 'new-dependency'
  | 'fork-pr'
  | 'injectable-agent-surface'
  | 'ci-divergent'
  | 'privileged-hook'
  | 'untrusted-text-injection'
  | 'agent-config-change'
  | 'gate-tamper';

/** A sensitive thing a reachable path can arrive at. */
export type SinkKind = 'secret' | 'credential' | 'privileged-capability';

/** The four capability classes an agent/MCP grant can confer. */
export type CapabilityClass = 'filesystem' | 'network' | 'shell' | 'tool';

/** CI provider a job comes from. Absent = github (the original assumed provider). */
export type CiProvider = 'github' | 'gitlab' | 'circleci';

/** An attacker-controllable entry point. `exposure` feeds ranking (post-traversal). */
export interface EntryNode {
  id: string;
  kind: 'entry';
  entryKind: EntryKind;
  /** Relative attacker-controllability, higher = more exposed. Ranking input only. */
  exposure: number;
  label: string;
  /**
   * A `fork-pr` entry whose triggering job restricts *who* can trigger it to trusted
   * actors (an `if:` actor guard). A guarded path is real (broad scope still applies)
   * but not externally attacker-controllable, so the gate downgrades it fail→warn (U17).
   */
  guarded?: boolean;
  /** Where untrusted text lands (`untrusted-text-injection` entries only, 0046). */
  sinkClass?: SinkClass;
  /** Source location of the sink, for `fail` evidence (0046 / plan R7). */
  evidence?: SourceEvidence;
  /** Rule-of-Two assessment of the agent step (`agent-ingested` entries only, 0059). */
  agent?: AgentAssessment;
}

/** Repository visibility (KTD5): supplied by the surface, never guessed. */
export type RepoVisibility = 'public' | 'private' | 'unknown';

/** One Rule-of-Two leg: held, missing, or not readable from configuration. */
export type Leg = 'held' | 'missing' | 'unknown';

/** An agent step judged against the Agents Rule of Two (Agent-in-CI U3 / 0057). */
export interface AgentAssessment {
  /** The step's `uses:`. */
  uses: string;
  profileId?: 'claude' | 'codex' | 'gemini' | 'llm-inference';
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
  /** The credentials the agent's tools can read: secret names, every secret, the GITHUB_TOKEN. */
  readable: { secrets: string[]; allSecrets: boolean; token: boolean };
}

/**
 * Where untrusted event text lands in a job (0046 / plan KTD1–KTD2), strongest first.
 * Only `execution` can fail; the rest are warn-tier until the text is proven executed.
 */
export type SinkClass = 'execution' | 'agent-ingested' | 'action-input' | 'unrecognized';

/** A 1-based source location in a repo file. */
export interface SourceEvidence {
  file: string;
  line: number;
}

export interface DependencyNode {
  id: string;
  kind: 'dependency';
  pkg: string;
  version: string;
  isDirect: boolean;
  hasInstallScript: boolean;
  /** Which package ecosystem this dependency belongs to. Absent = npm (0028, 0032). */
  ecosystem?: 'npm' | 'python' | 'ruby';
}

export interface CiJobNode {
  id: string;
  kind: 'ci-job';
  /** Which CI provider emitted this job. Absent = github (0031). */
  provider?: CiProvider;
  workflow: string;
  job: string;
  triggers: string[];
  secrets: string[];
  forkTriggerable: boolean;
  /** The job runs a dependency install step (where a poisoned lifecycle script executes). */
  runsInstall: boolean;
  /** Where attacker-controlled code first executes in the job (after an untrusted checkout, 0048). */
  execEvidence?: SourceEvidence;
  /** Where the job exposes each held sink, keyed by sink identity (0096). */
  exposure?: Record<string, SourceEvidence>;
  /** The dependency-install step (where a new dependency's install script runs, 0048). */
  installEvidence?: SourceEvidence;
}

export interface AgentGrantNode {
  id: string;
  kind: 'agent-grant';
  source: string;
  capabilityClass: CapabilityClass;
  scope: string;
  exceedsBaseline: boolean;
}

export interface SinkNode {
  id: string;
  kind: 'sink';
  sinkKind: SinkKind;
  identity: string;
}

export type AttackNode = EntryNode | DependencyNode | CiJobNode | AgentGrantNode | SinkNode;

/**
 * Edge kinds encode reachability semantics:
 * - `controls`  — an entry controls a dependency (a new/updated package)
 * - `triggers`  — an entry triggers a CI job (a fork PR / untrusted input)
 * - `injects`   — an entry injects into an agent surface (prompt injection)
 * - `runs-in`   — a dependency's install script runs within a CI job
 * - `holds`     — a CI job holds a secret sink
 * - `reaches`   — an agent grant reaches a privileged-capability / secret sink
 */
export type EdgeKind = 'controls' | 'triggers' | 'injects' | 'runs-in' | 'holds' | 'reaches';

export interface AttackEdge {
  kind: EdgeKind;
}
