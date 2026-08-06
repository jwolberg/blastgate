import { singleSource } from 'graphology-shortest-path';
import type { AttackGraph } from './graph';
import type { AttackNode, EntryNode, SinkNode } from './types';

/** A reachable path from an attacker-controllable entry to a sensitive sink. */
export interface ReachPath {
  entry: EntryNode;
  sink: SinkNode;
  /** Ordered nodes from entry to sink inclusive. */
  nodes: AttackNode[];
  /** Edge count (path length in hops). */
  hops: number;
}

const byId = (a: { id: string }, b: { id: string }): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/**
 * Every sink reachable from `entry`, one shortest path each (0039). A single
 * unweighted BFS from the entry (`singleSource`) computes the shortest path to *all* reachable
 * nodes at once — replacing the old per-(entry, sink) bidirectional search, whose
 * `|entries| × |sinks|` call count made large monorepos fail closed to UNKNOWN
 * even though the real paths are few and short. Sinks are returned in id order so
 * callers stay byte-identical across runs (R7 parity / stable CI).
 */
function sinksReachableFrom(ag: AttackGraph, entry: EntryNode): ReachPath[] {
  const sinkIds = new Set(ag.sinkNodes().map((s) => s.id));
  const shortest = singleSource(ag.graph, entry.id); // { targetId: [path ids] }
  const paths: ReachPath[] = [];
  for (const [targetId, ids] of Object.entries(shortest)) {
    if (!sinkIds.has(targetId)) {
      continue; // presence alone is not reachability (R14); non-sink targets are ignored
    }
    paths.push({
      entry,
      sink: ag.node(targetId) as SinkNode,
      nodes: ids.map((id) => ag.node(id)),
      hops: ids.length - 1,
    });
  }
  return paths.sort((a, b) => byId(a.sink, b.sink));
}

/**
 * Compute the shortest reachable path per sink (R3). For each sink, keeps the
 * shortest path found across all attacker-controllable entries. A sink with no
 * reachable entry is never returned — presence alone is not reachability (R14).
 */
export function shortestPathsToSinks(ag: AttackGraph): ReachPath[] {
  const entries = [...ag.entryNodes()].sort(byId);
  const bySink = new Map<string, ReachPath>();

  for (const entry of entries) {
    for (const candidate of sinksReachableFrom(ag, entry)) {
      const existing = bySink.get(candidate.sink.id);
      if (!existing || candidate.hops < existing.hops) {
        bySink.set(candidate.sink.id, candidate);
      }
    }
  }

  return [...bySink.values()];
}

/**
 * Shortest path per (entry, sink) pair — the engine's view (U7). A refinement of
 * R3's "shortest path per sink": distinct attacker entry points reaching the same
 * sink are distinct findings with distinct remediations, so a shorter single-layer
 * path (e.g. fork-PR → job → secret) never hides a longer cross-layer one
 * (install-script → dep → job → secret) that is the whole point of the tool.
 * Entries are visited in id order and each entry's sinks in id order, so the
 * output is byte-identical across runs (R7 parity / stable CI).
 */
export function reachablePaths(ag: AttackGraph): ReachPath[] {
  const entries = [...ag.entryNodes()].sort(byId);
  const paths: ReachPath[] = [];
  for (const entry of entries) {
    paths.push(...sinksReachableFrom(ag, entry));
  }
  return paths;
}
