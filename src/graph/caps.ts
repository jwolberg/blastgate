/**
 * Reachability cost bound (0018, recalibrated 0039).
 *
 * `reachablePaths` runs one single-source BFS per attacker-controllable entry, and
 * each BFS costs `O(nodes + edges)`. So the real work is `|entries| × (|nodes| +
 * |edges|)` — linear in graph size, not the `|entries| × |sinks|` product the old
 * per-pair `bidirectional` search cost. That product blew this cap on real
 * monorepos (40+ workflow files → hundreds of secret sinks × hundreds of
 * fork-triggerable jobs) and handed large adopters a blocking UNKNOWN with zero
 * findings, even though the genuine reachable paths were few and short (0039).
 *
 * The guard still matters: a crafted repo can fabricate tens of thousands of
 * entries to force that many BFS traversals. Rather than run it, the engine checks
 * this bound first and fails *closed* to UNKNOWN (0020) — a gate that cannot
 * evaluate safely must not hang, and must not pass. The ceiling is measured in the
 * cost unit that now reflects the algorithm, so real monorepos evaluate while a
 * genuine DoS is still refused.
 */

import type { AttackGraph } from './graph';

/**
 * Default ceiling on total reachability work (`|entries| × (|nodes| + |edges|)`).
 * ~5e7 BFS node-visits run in well under a second; real monorepos land orders of
 * magnitude below this, while a fabricated tens-of-thousands-of-entries graph
 * exceeds it and fails closed.
 */
export const MAX_REACHABILITY_COST = 50_000_000;

/**
 * The reachability search cost of this graph: `|entries| × (|nodes| + |edges|)` —
 * one `O(nodes + edges)` BFS per entry. A worst-case upper bound (in this shallow
 * graph most BFS traversals visit only a tiny reachable subgraph).
 */
export function reachabilityCost(ag: AttackGraph): number {
  return ag.entryNodes().length * (ag.graph.order + ag.graph.size);
}

/** True when the reachability search would exceed the (default or given) cap. */
export function exceedsReachabilityCap(
  ag: AttackGraph,
  cap: number = MAX_REACHABILITY_COST,
): boolean {
  return reachabilityCost(ag) > cap;
}
