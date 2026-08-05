import { describe, expect, it } from 'vitest';
import type { GateResult } from '../engine/gate';
import {
  parseRunRecords,
  RUN_RECORD_SCHEMA_VERSION,
  toRunRecord,
  type RunRecord,
} from './run-record';
import { renderTrendReport } from './trend';

const failResult: GateResult = {
  verdict: 'fail',
  diagnostics: [],
  findings: [
    {
      id: 'a',
      tier: 'fail',
      score: 300,
      path: ['x', 'AWS_SECRET_ACCESS_KEY'],
      pathNodeIds: ['e', 's'],
      hops: 1,
      entry: { kind: 'fork-pr', label: 'x' },
      sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
      reason: 'r',
      remediation: 'fix',
      owasp: {},
      labels: [],
    },
    {
      id: 'b',
      tier: 'warn',
      score: 100,
      path: ['y'],
      pathNodeIds: ['c'],
      hops: 0,
      entry: { kind: 'injectable-agent-surface', label: 'y' },
      sink: { kind: 'privileged-capability', identity: 'filesystem:/' },
      reason: 'r',
      remediation: 'fix',
      owasp: {},
      labels: [],
    },
  ],
};

describe('toRunRecord (schema phase 0)', () => {
  it('captures the verdict, tier counts, and metadata at the versioned schema', () => {
    const rec = toRunRecord(failResult, {
      timestamp: '2026-08-05T10:00:00Z',
      sha: 'abc123',
      base: 'main',
    });
    expect(rec.schemaVersion).toBe(RUN_RECORD_SCHEMA_VERSION);
    expect(rec.verdict).toBe('fail');
    expect(rec.findingCount).toBe(2);
    expect(rec.failCount).toBe(1);
    expect(rec.warnCount).toBe(1);
    expect(rec.sha).toBe('abc123');
    expect(rec.base).toBe('main');
  });
});

describe('parseRunRecords', () => {
  it('parses valid records, drops malformed ones, and sorts oldest→newest', () => {
    const a = JSON.stringify(toRunRecord(failResult, { timestamp: '2026-08-02T00:00:00Z' }));
    const b = JSON.stringify(toRunRecord(failResult, { timestamp: '2026-08-05T00:00:00Z' }));
    const records = parseRunRecords([b, 'not json {', a]);
    expect(records).toHaveLength(2);
    expect(records[0]!.timestamp).toBe('2026-08-02T00:00:00Z'); // sorted ascending
  });
});

describe('renderTrendReport (phase 1)', () => {
  const records: RunRecord[] = [
    toRunRecord(failResult, { timestamp: '2026-08-02T00:00:00Z', sha: 'aaa' }),
    toRunRecord(
      { ...failResult, verdict: 'pass', findings: [] },
      { timestamp: '2026-08-05T00:00:00Z', sha: 'bbb' },
    ),
  ];

  it('produces a self-contained HTML page (no external assets)', () => {
    const html = renderTrendReport(records);
    expect(html).toContain('<!doctype html>');
    expect(html).toContain('<svg'); // inline chart, not a linked image
    expect(html).not.toMatch(/https?:\/\//); // no external hosts referenced
  });

  it('shows each run and the latest verdict', () => {
    const html = renderTrendReport(records);
    expect(html).toContain('2026-08-02T00:00:00Z');
    expect(html).toContain('2026-08-05T00:00:00Z');
    expect(html).toContain('PASS'); // latest verdict
  });

  it('handles an empty directory of runs without throwing', () => {
    expect(() => renderTrendReport([])).not.toThrow();
    expect(renderTrendReport([])).toContain('No runs recorded');
  });
});
