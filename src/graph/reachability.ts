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

const byId = (a: { id: string }, b: { id: string }): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/**
 * Shortest path per (entry, sink) pair — the engine's view (U7). A refinement of
 * R3's "shortest path per sink": distinct attacker entry points reaching the same
 * sink are distinct findings with distinct remediations, so a shorter single-layer
 * path (e.g. fork-PR → job → secret) never hides a longer cross-layer one
 * (install-script → dep → job → secret) that is the whole point of the tool.
 * Entries and sinks are visited in id order so the output is byte-identical across
 * runs (R7 parity / stable CI).
 */
export function reachablePaths(ag: AttackGraph): ReachPath[] {
  const entries = [...ag.entryNodes()].sort(byId);
  const sinks = [...ag.sinkNodes()].sort(byId);
  const paths: ReachPath[] = [];

  for (const entry of entries) {
    for (const sink of sinks) {
      const ids: string[] | null = bidirectional(ag.graph, entry.id, sink.id);
      if (!ids) {
        continue;
      }
      paths.push({
        entry,
        sink,
        nodes: ids.map((id) => ag.node(id)),
        hops: ids.length - 1,
      });
    }
  }

  return paths;
}
