import { bidirectional } from 'graphology-shortest-path';
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

/**
 * Compute the shortest reachable path per sink (R3). Runs an unweighted BFS
 * shortest-path from every attacker-controllable entry to every sink; for each
 * sink, keeps the shortest path found across all entries. A sink with no
 * reachable entry is never returned — presence alone is not reachability (R14).
 */
export function shortestPathsToSinks(ag: AttackGraph): ReachPath[] {
  const entries = ag.entryNodes();
  const sinks = ag.sinkNodes();
  const bySink = new Map<string, ReachPath>();

  for (const entry of entries) {
    for (const sink of sinks) {
      const ids: string[] | null = bidirectional(ag.graph, entry.id, sink.id);
      if (!ids) {
        continue;
      }
      const candidate: ReachPath = {
        entry,
        sink,
        nodes: ids.map((id) => ag.node(id)),
        hops: ids.length - 1,
      };
      const existing = bySink.get(sink.id);
      if (!existing || candidate.hops < existing.hops) {
        bySink.set(sink.id, candidate);
      }
    }
  }

  return [...bySink.values()];
}
