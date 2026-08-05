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
}

export interface DependencyNode {
  id: string;
  kind: 'dependency';
  pkg: string;
  version: string;
  isDirect: boolean;
  hasInstallScript: boolean;
}

export interface CiJobNode {
  id: string;
  kind: 'ci-job';
  workflow: string;
  job: string;
  triggers: string[];
  secrets: string[];
  forkTriggerable: boolean;
  /** The job runs a dependency install step (where a poisoned lifecycle script executes). */
  runsInstall: boolean;
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
