import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { resetSkeptic, runApprove } from './approve';
import { parseCrawlConfig } from './config';
import { renderPacket } from './review';

const HERE = dirname(fileURLToPath(import.meta.url));
const REAL = JSON.parse(
  readFileSync(join(HERE, 'fixtures', 'disclose', 'real-fails.json'), 'utf8'),
) as Record<string, Finding[]>;
const F = REAL['fork-pr-secret']![0]!;
const SHA = 'a'.repeat(40);

let dir = '';
const packet = (
  name: string,
  over: { repo?: string; verdict?: string; skeptic?: string; findings?: Finding[] } = {},
): void => {
  let md = renderPacket({
    repo: over.repo ?? 'acme/widgets',
    sha: SHA,
    engineVersion: '9.9.9',
    archetype: 'fork-pr->credential',
    findings: over.findings ?? [F],
    readSource: () => null,
    workflows: [],
  });
  md = md.replace('verdict: pending', `verdict: ${over.verdict ?? 'pending'}`);
  md = md.replace('skeptic: pending', `skeptic: ${over.skeptic ?? 'pending'}`);
  writeFileSync(join(dir, 'packets', name), md);
};
const config = (obj: object = {}): string => {
  const p = join(dir, 'config.json');
  writeFileSync(p, JSON.stringify(obj));
  return p;
};
const run = (cfg: string) =>
  runApprove({ packets: join(dir, 'packets'), config: cfg }, { log: () => {} });
const approvedIn = (cfg: string) => parseCrawlConfig(readFileSync(cfg, 'utf8')).approved;

describe('crawl approve (0100)', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bg-approve-'));
    mkdirSync(join(dir, 'packets'), { recursive: true });
  });

  it('approves a packet the skeptic could not refute, with no human verdict needed (0101)', () => {
    packet('a__fork.md', { skeptic: 'could-not-refute' });
    const cfg = config({ allowlist: ['fork-pr->credential'] });
    const r = run(cfg);
    expect(r.added).toHaveLength(1);
    expect(approvedIn(cfg)).toEqual([
      { repo: 'acme/widgets', sha: SHA, findingId: F.id, skeptic: 'could-not-refute' },
    ]);
    expect(parseCrawlConfig(readFileSync(cfg, 'utf8')).allowlist).toEqual(['fork-pr->credential']);
  });

  it('approves a doubtful packet as a possible vulnerability (0101)', () => {
    packet('a.md', { skeptic: 'doubtful' });
    const cfg = config();
    run(cfg);
    expect(approvedIn(cfg)).toEqual([
      { repo: 'acme/widgets', sha: SHA, findingId: F.id, skeptic: 'doubtful' },
    ]);
  });

  it('never approves what the skeptic refuted, and flags packets it has not checked', () => {
    packet('a.md', { skeptic: 'refuted' });
    packet('b.md', { skeptic: 'pending' });
    const cfg = config();
    const r = run(cfg);
    expect(r.added).toEqual([]);
    expect(r.skipped).toEqual([{ packet: 'b.md', reason: 'skeptic has not run' }]);
    expect(approvedIn(cfg)).toEqual([]);
  });

  it('never approves a packet Jay marked refuted, whatever the skeptic said', () => {
    packet('a.md', { verdict: 'refuted', skeptic: 'could-not-refute' });
    const cfg = config();
    const r = run(cfg);
    expect(r.added).toEqual([]);
    expect(r.skipped).toEqual([{ packet: 'a.md', reason: 'marked refuted by a human' }]);
  });

  it('refuses a packet whose approval block names a different repo or commit', () => {
    packet('a.md', { skeptic: 'could-not-refute' });
    const p = join(dir, 'packets', 'a.md');
    writeFileSync(
      p,
      readFileSync(p, 'utf8').replace(/"repo": "acme\/widgets"/g, '"repo": "acme/other"'),
    );
    const r = run(config());
    expect(r.added).toEqual([]);
    expect(r.skipped[0]?.reason).toMatch(/does not match/);
  });

  it('keeps existing approvals and does not duplicate them on a rerun', () => {
    packet('a.md', { skeptic: 'could-not-refute' });
    const prior = { repo: 'x/y', sha: 'b'.repeat(40), findingId: 'p', skeptic: 'could-not-refute' };
    const cfg = config({ approved: [prior] });
    run(cfg);
    run(cfg);
    expect(approvedIn(cfg)).toHaveLength(2);
    expect(approvedIn(cfg)[0]).toEqual(prior);
  });

  it('skips README.md and SUMMARY.md', () => {
    writeFileSync(
      join(dir, 'packets', 'README.md'),
      'verdict: confirmed\nskeptic: could-not-refute\n',
    );
    writeFileSync(join(dir, 'packets', 'SUMMARY.md'), '# summary');
    expect(run(config())).toEqual({ added: [], skipped: [] });
  });
});

describe('crawl skeptic-reset between the two skeptic stages (0100)', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bg-reset-'));
    mkdirSync(join(dir, 'packets'), { recursive: true });
  });
  const withReasoning = (name: string, skeptic: string): string => {
    packet(name, { skeptic });
    const p = join(dir, 'packets', name);
    writeFileSync(
      p,
      readFileSync(p, 'utf8').replace(
        '## Skeptic\n\nNot run yet.',
        '## Skeptic\n\nStage-one reasoning that must not reach stage two.',
      ),
    );
    return p;
  };

  it('clears every non-refuted packet back to a blank skeptic slot, so stage two reads it unbiased', () => {
    const doubtful = withReasoning('a.md', 'doubtful');
    const passed = withReasoning('b.md', 'could-not-refute');
    const refuted = withReasoning('c.md', 'refuted');
    const r = resetSkeptic(join(dir, 'packets'));
    expect(r).toEqual({ reset: ['a.md', 'b.md'], kept: ['c.md'] });
    for (const p of [doubtful, passed]) {
      const md = readFileSync(p, 'utf8');
      expect(md).toMatch(/^skeptic: pending$/m);
      expect(md).toContain('## Skeptic\n\nNot run yet.');
      expect(md).not.toContain('Stage-one reasoning');
    }
    expect(readFileSync(refuted, 'utf8')).toMatch(/^skeptic: refuted$/m);
    expect(readFileSync(refuted, 'utf8')).toContain('Stage-one reasoning');
  });

  it('never touches a verdict or the approval block', () => {
    const p = withReasoning('a.md', 'doubtful');
    writeFileSync(p, readFileSync(p, 'utf8').replace('verdict: pending', 'verdict: confirmed'));
    const before = readFileSync(p, 'utf8');
    resetSkeptic(join(dir, 'packets'));
    const after = readFileSync(p, 'utf8');
    expect(after).toMatch(/^verdict: confirmed$/m);
    expect(after.slice(after.indexOf('## Findings'))).toBe(
      before.slice(before.indexOf('## Findings')),
    );
  });
});
