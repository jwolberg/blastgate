import { describe, expect, it } from 'vitest';
import { exceedsReachabilityCap, reachabilityCost } from '../graph/caps';
import { AttackGraph } from '../graph/graph';
import { buildGraph, type EngineInputs } from './build';
import { runEngine } from './gate';

function graphWith(entries: number, sinks: number): AttackGraph {
  const ag = new AttackGraph();
  for (let i = 0; i < entries; i++) {
    ag.addNode({
      id: `entry:${i}`,
      kind: 'entry',
      entryKind: 'new-dependency',
      exposure: 1,
      label: `e${i}`,
    });
  }
  for (let i = 0; i < sinks; i++) {
    ag.addNode({ id: `sink:${i}`, kind: 'sink', sinkKind: 'secret', identity: `S${i}` });
  }
  return ag;
}

/** A fork-triggerable job holding a secret — one entry × one sink, a fail finding. */
const WORKFLOW = [
  'on:',
  '  pull_request_target:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: gh pr checkout 123',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');
const failingInputs = { ci: { workflows: [{ path: 'ci.yml', content: WORKFLOW }] } };

/**
 * A synthetic large monorepo: `workflows` files, each with `jobsPer` fork-triggerable
 * jobs holding a *distinct* secret. Every job yields one fork-PR entry and one unique
 * secret sink, so `|entries| × |sinks|` grows as the product — the shape that blew the
 * old 200k-pair cap and handed big repos a 0-finding UNKNOWN (0039).
 */
function bigMonorepoInputs(workflows: number, jobsPer: number): EngineInputs {
  const wfs: { path: string; content: string }[] = [];
  let n = 0;
  for (let w = 0; w < workflows; w++) {
    const lines = ['on:', '  pull_request_target:', 'jobs:'];
    for (let j = 0; j < jobsPer; j++) {
      const idx = n++;
      lines.push(
        `  job${idx}:`,
        '    steps:',
        '      - run: gh pr checkout 123',
        '      - run: npm ci',
        '        env:',
        `          TOK: \${{ secrets.SECRET_${idx} }}`,
      );
    }
    wfs.push({ path: `.github/workflows/wf${w}.yml`, content: lines.join('\n') });
  }
  return { ci: { workflows: wfs } };
}

describe('reachability cost bound (0018, recalibrated 0039)', () => {
  it('cost is entries × (nodes + edges) — one BFS per entry over the whole graph', () => {
    // graphWith(3, 4): 3 entries + 4 sinks = 7 nodes, 0 edges → 3 × (7 + 0).
    expect(reachabilityCost(graphWith(3, 4))).toBe(21);
  });
  it('exceedsReachabilityCap respects the boundary (strictly greater)', () => {
    const ag = graphWith(3, 3); // 6 nodes, 0 edges → cost 3 × 6 = 18
    expect(reachabilityCost(ag)).toBe(18);
    expect(exceedsReachabilityCap(ag, 17)).toBe(true);
    expect(exceedsReachabilityCap(ag, 18)).toBe(false);
  });
});

describe('runEngine fails closed on an over-cap graph (0018)', () => {
  it('over the cap → UNKNOWN, an error diagnostic, and no findings — never a hang', () => {
    const result = runEngine(failingInputs, { maxCost: 0 });
    expect(result.verdict).toBe('unknown');
    expect(result.findings).toHaveLength(0);
    expect(result.diagnostics.some((d) => d.level === 'error' && /too large/.test(d.message))).toBe(
      true,
    );
  });
  it('the same inputs under the default cap evaluate normally (fail)', () => {
    expect(runEngine(failingInputs).verdict).toBe('fail');
  });
});

describe('large monorepo no longer fails closed on the cap (0039)', () => {
  const inputs = bigMonorepoInputs(60, 8); // 480 fork jobs → 480 entries × 480 secrets

  it('the entry×sink product exceeds the old 200k-pair cap (the dimension that blew it)', () => {
    const { graph } = buildGraph(inputs);
    expect(graph.entryNodes().length * graph.sinkNodes().length).toBeGreaterThan(200_000);
  });

  it('evaluates to a real verdict (fail) instead of a 0-finding UNKNOWN', () => {
    const result = runEngine(inputs);
    expect(result.verdict).toBe('fail');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.diagnostics.some((d) => d.level === 'error')).toBe(false);
  });
});
