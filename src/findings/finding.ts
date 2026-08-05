/**
 * The stable `Finding` shape every surface consumes (CLI, GitHub Action, plugin,
 * MCP). One engine, one finding shape — R7 parity depends on no surface
 * re-deriving this. See plan U7 / KTD10.
 */

import type { EntryKind, SinkKind } from '../graph/types';
import type { OwaspLabels } from '../taxonomy/label';

/**
 * Whole-run outcome. `unknown` means the run could not be fully evaluated (a parse
 * or analysis error) — it is NOT a pass: CI blocks on it, the local hook warns
 * loudly. Precedence fail > unknown > warn > pass (0020, KTD4 fail-closed).
 */
export type Verdict = 'fail' | 'warn' | 'pass' | 'unknown';

/** Per-finding gate tier under KTD4 (secret/credential fail, capability warns). */
export type Tier = 'fail' | 'warn';

export interface FindingEntry {
  kind: EntryKind;
  label: string;
}

export interface FindingSink {
  kind: SinkKind;
  identity: string;
}

export interface Finding {
  /** Stable id (`<entry.id>=><sink.id>`) — deterministic ordering and dedup. */
  id: string;
  /** Gate tier for this finding (KTD4). */
  tier: Tier;
  /** Severity score, higher = more severe (ranking output, KTD3). */
  score: number;
  /** Human-readable node labels, entry → … → sink. */
  path: string[];
  /** Node ids backing `path`, same order/length (machine consumers). */
  pathNodeIds: string[];
  /** Hop count (edges) along the path. */
  hops: number;
  entry: FindingEntry;
  sink: FindingSink;
  /** Why the sink is reachable from the entry. */
  reason: string;
  /** How to break the path. */
  remediation: string;
  /** Raw OWASP category ids (may be empty — "no applicable category" is valid, KTD9). */
  owasp: OwaspLabels;
  /** Versioned display labels, e.g. `["ASI04:2026","MCP04:2025"]`. */
  labels: string[];
  /**
   * Set when a human has accepted this finding via `.blastgate/acknowledged.json`
   * (U14): the reason, and the tier is downgraded fail→warn. Absent otherwise.
   */
  acknowledged?: string;
}

/**
 * KTD4 fail-threshold policy: a reachable secret or credential sink fails the
 * gate; a lower-sensitivity privileged-capability sink only warns.
 */
export function tierForSink(kind: SinkKind): Tier {
  return kind === 'privileged-capability' ? 'warn' : 'fail';
}
