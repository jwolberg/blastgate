/**
 * Reachability cost bound (0018).
 *
 * `reachablePaths` runs a bidirectional search for every (entry, sink) pair, so its
 * cost is `|entries| × |sinks|`. A crafted repo can inflate both — thousands of
 * fabricated new-dep entries and thousands of unique `secrets.X` names — into a
 * multi-million-pair search that hangs CI or exhausts memory. Rather than run it,
 * the engine checks this bound first and fails *closed* to UNKNOWN (0020): a gate
 * that cannot evaluate safely must not hang, and must not pass.
 */

import type { AttackGraph } from './graph';

/** Default ceiling on entry×sink pairs. Real PRs sit far below this; a DoS is far above. */
export const MAX_REACHABILITY_PAIRS = 200_000;

/** The pairwise search cost of this graph: |entries| × |sinks|. */
export function reachabilityCost(ag: AttackGraph): number {
  return ag.entryNodes().length * ag.sinkNodes().length;
}

/** True when the pairwise reachability search would exceed the (default or given) cap. */
export function exceedsReachabilityCap(
  ag: AttackGraph,
  cap: number = MAX_REACHABILITY_PAIRS,
): boolean {
  return reachabilityCost(ag) > cap;
}
