import { labelPath, type OwaspLabels } from '../taxonomy/label';
import type { ReachPath } from './reachability';
import type { EntryKind, SinkKind } from './types';

/** A reachable path with its OWASP labels and severity score. */
export interface RankedFinding {
  path: ReachPath;
  labels: OwaspLabels;
  score: number;
}

/** Sink sensitivity dominates the score: raw secret/credential > capability. */
const SINK_WEIGHT: Record<SinkKind, number> = {
  secret: 3,
  credential: 3,
  'privileged-capability': 1,
};

/** How exposed the entry point is: public fork PR > injectable agent > new dep. */
const ENTRY_KIND_EXPOSURE: Record<EntryKind, number> = {
  'fork-pr': 3,
  'injectable-agent-surface': 2,
  'new-dependency': 1,
};

function score(path: ReachPath): number {
  return (
    SINK_WEIGHT[path.sink.sinkKind] * 100 +
    ENTRY_KIND_EXPOSURE[path.entry.entryKind] * 10 +
    path.entry.exposure
  );
}

/**
 * Rank reachable paths most-severe first (KTD3). Ranking is a post-traversal
 * pass over structural reachability output — it never re-queries the graph.
 */
export function rankFindings(paths: ReachPath[]): RankedFinding[] {
  return paths
    .map((path) => ({ path, labels: labelPath(path), score: score(path) }))
    .sort((a, b) => b.score - a.score);
}
