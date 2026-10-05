import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { runApprove } from './approve';
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

  it('approves a confirmed packet the skeptic could not refute, recording the skeptic pass', () => {
    packet('a__fork.md', { verdict: 'confirmed', skeptic: 'could-not-refute' });
    const cfg = config({ allowlist: ['fork-pr->credential'] });
    const r = run(cfg);
    expect(r.added).toHaveLength(1);
    expect(approvedIn(cfg)).toEqual([
      { repo: 'acme/widgets', sha: SHA, findingId: F.id, skeptic: 'could-not-refute' },
    ]);
    expect(parseCrawlConfig(readFileSync(cfg, 'utf8')).allowlist).toEqual(['fork-pr->credential']);
  });

  it.each(['doubtful', 'refuted', 'pending'])(
    'refuses a confirmed packet whose skeptic said %s, and says why',
    (skeptic) => {
      packet('a__fork.md', { verdict: 'confirmed', skeptic });
      const cfg = config();
      const r = run(cfg);
      expect(r.added).toEqual([]);
      expect(r.skipped).toEqual([{ packet: 'a__fork.md', reason: `skeptic: ${skeptic}` }]);
      expect(approvedIn(cfg)).toEqual([]);
    },
  );

  it('ignores packets Jay did not confirm, even if the skeptic passed them', () => {
    packet('a.md', { verdict: 'refuted', skeptic: 'could-not-refute' });
    packet('b.md', { verdict: 'unsure', skeptic: 'could-not-refute' });
    packet('c.md', { verdict: 'pending', skeptic: 'could-not-refute' });
    const cfg = config();
    expect(run(cfg)).toEqual({ added: [], skipped: [] });
    expect(approvedIn(cfg)).toEqual([]);
  });

  it('refuses a packet whose approval block names a different repo or commit', () => {
    packet('a.md', { verdict: 'confirmed', skeptic: 'could-not-refute' });
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
    packet('a.md', { verdict: 'confirmed', skeptic: 'could-not-refute' });
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
