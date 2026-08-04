import { describe, expect, it } from 'vitest';
import { AttackGraph } from './graph';
import { shortestPathsToSinks } from './reachability';
import type {
  AgentGrantNode,
  CiJobNode,
  DependencyNode,
  EntryKind,
  EntryNode,
  SinkKind,
  SinkNode,
} from './types';

function entry(id: string, entryKind: EntryKind = 'new-dependency', exposure = 1): EntryNode {
  return { id, kind: 'entry', entryKind, exposure, label: id };
}
function dep(id: string): DependencyNode {
  return {
    id,
    kind: 'dependency',
    pkg: id,
    version: '1.0.0',
    isDirect: true,
    hasInstallScript: true,
  };
}
function job(id: string): CiJobNode {
  return {
    id,
    kind: 'ci-job',
    workflow: 'ci.yml',
    job: id,
    triggers: ['pull_request_target'],
    secrets: ['AWS_SECRET_ACCESS_KEY'],
    forkTriggerable: true,
  };
}
function grant(id: string): AgentGrantNode {
  return {
    id,
    kind: 'agent-grant',
    source: '.mcp.json',
    capabilityClass: 'shell',
    scope: '*',
    exceedsBaseline: true,
  };
}
function sink(id: string, sinkKind: SinkKind = 'secret'): SinkNode {
  return { id, kind: 'sink', sinkKind, identity: id };
}

describe('shortestPathsToSinks', () => {
  it('returns one path for a linear entry->dep->job->sink chain', () => {
    const g = new AttackGraph();
    [entry('e'), dep('d'), job('j'), sink('s')].forEach((n) => g.addNode(n));
    g.addEdge('e', 'd', { kind: 'controls' });
    g.addEdge('d', 'j', { kind: 'runs-in' });
    g.addEdge('j', 's', { kind: 'holds' });

    const paths = shortestPathsToSinks(g);

    expect(paths).toHaveLength(1);
    expect(paths[0]!.nodes.map((n) => n.id)).toEqual(['e', 'd', 'j', 's']);
    expect(paths[0]!.hops).toBe(3);
  });

  it('keeps only the shortest path per sink when two entries reach it', () => {
    const g = new AttackGraph();
    [entry('e1'), entry('e2'), dep('a'), job('b'), sink('s')].forEach((n) => g.addNode(n));
    // e1 -> a -> b -> s (3 hops)
    g.addEdge('e1', 'a', { kind: 'controls' });
    g.addEdge('a', 'b', { kind: 'runs-in' });
    g.addEdge('b', 's', { kind: 'holds' });
    // e2 -> s (1 hop)
    g.addEdge('e2', 's', { kind: 'reaches' });

    const paths = shortestPathsToSinks(g);

    expect(paths).toHaveLength(1);
    expect(paths[0]!.entry.id).toBe('e2');
    expect(paths[0]!.hops).toBe(1);
  });

  it('reports one path per sink when an entry reaches several sinks', () => {
    const g = new AttackGraph();
    [entry('e'), grant('gfs'), sink('s1'), sink('s2', 'privileged-capability')].forEach((n) =>
      g.addNode(n),
    );
    g.addEdge('e', 'gfs', { kind: 'injects' });
    g.addEdge('gfs', 's1', { kind: 'reaches' });
    g.addEdge('gfs', 's2', { kind: 'reaches' });

    const paths = shortestPathsToSinks(g);

    expect(paths).toHaveLength(2);
    expect(new Set(paths.map((p) => p.sink.id))).toEqual(new Set(['s1', 's2']));
  });

  it('returns nothing when there is no attacker-controllable entry', () => {
    const g = new AttackGraph();
    [dep('d'), job('j'), sink('s')].forEach((n) => g.addNode(n));
    g.addEdge('d', 'j', { kind: 'runs-in' });
    g.addEdge('j', 's', { kind: 'holds' });

    expect(shortestPathsToSinks(g)).toEqual([]);
  });

  it('terminates and returns a finite shortest path when the graph has a cycle', () => {
    const g = new AttackGraph();
    [entry('e'), dep('a'), job('b'), sink('s')].forEach((n) => g.addNode(n));
    g.addEdge('e', 'a', { kind: 'controls' });
    g.addEdge('a', 'b', { kind: 'runs-in' });
    g.addEdge('b', 'a', { kind: 'runs-in' }); // cycle a <-> b
    g.addEdge('b', 's', { kind: 'holds' });

    const paths = shortestPathsToSinks(g);

    expect(paths).toHaveLength(1);
    expect(paths[0]!.nodes.map((n) => n.id)).toEqual(['e', 'a', 'b', 's']);
  });

  it('does not report a sink that is present but unreachable (R14)', () => {
    const g = new AttackGraph();
    [entry('e'), dep('d'), sink('isolated')].forEach((n) => g.addNode(n));
    g.addEdge('e', 'd', { kind: 'controls' }); // 'isolated' has no incoming edge

    expect(shortestPathsToSinks(g)).toEqual([]);
  });
});
