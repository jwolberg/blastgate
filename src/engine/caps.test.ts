import { describe, expect, it } from 'vitest';
import { exceedsReachabilityCap, reachabilityCost } from '../graph/caps';
import { AttackGraph } from '../graph/graph';
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

describe('reachability cost bound (0018)', () => {
  it('cost is entries × sinks', () => {
    expect(reachabilityCost(graphWith(3, 4))).toBe(12);
  });
  it('exceedsReachabilityCap respects the boundary (strictly greater)', () => {
    const ag = graphWith(3, 3); // 9 pairs
    expect(exceedsReachabilityCap(ag, 8)).toBe(true);
    expect(exceedsReachabilityCap(ag, 9)).toBe(false);
  });
});

describe('runEngine fails closed on an over-cap graph (0018)', () => {
  it('over the cap → UNKNOWN, an error diagnostic, and no findings — never a hang', () => {
    const result = runEngine(failingInputs, { maxPairs: 0 });
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
