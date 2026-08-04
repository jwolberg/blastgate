import { describe, expect, it } from 'vitest';
import { rankFindings } from './ranking';
import type { ReachPath } from './reachability';
import type { EntryKind, EntryNode, SinkKind, SinkNode } from './types';

function reachPath(id: string, entryKind: EntryKind, sinkKind: SinkKind, exposure = 1): ReachPath {
  const entry: EntryNode = { id: `e-${id}`, kind: 'entry', entryKind, exposure, label: id };
  const sink: SinkNode = { id: `s-${id}`, kind: 'sink', sinkKind, identity: id };
  return { entry, sink, nodes: [entry, sink], hops: 1 };
}

describe('rankFindings', () => {
  it('ranks a secret-sink path above a privileged-capability path at equal hops', () => {
    const capability = reachPath('a', 'new-dependency', 'privileged-capability');
    const secret = reachPath('b', 'new-dependency', 'secret');

    const ranked = rankFindings([capability, secret]);

    expect(ranked[0]!.path.sink.sinkKind).toBe('secret');
  });

  it('ranks a fork-PR entry above a new-dependency entry to the same sink kind', () => {
    const dependency = reachPath('d', 'new-dependency', 'secret');
    const forkPr = reachPath('f', 'fork-pr', 'secret');

    const ranked = rankFindings([dependency, forkPr]);

    expect(ranked[0]!.path.entry.entryKind).toBe('fork-pr');
  });

  it('attaches OWASP labels to each ranked finding', () => {
    const ranked = rankFindings([reachPath('a', 'new-dependency', 'secret')]);

    expect(ranked[0]!.labels).toEqual({ agentic: 'ASI04', mcp: 'MCP04' });
  });
});
