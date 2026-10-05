import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { type CrawlConfig, DEFAULT_CRAWL_CONFIG } from './config';
import { composeReport, gate, tierReport } from './disclose';
import { createDisclosure, emptyLedger } from './ledger';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'disclose');
/** Real `fail` findings produced by running the engine on the incident fixtures in test/fixtures. */
const REAL = JSON.parse(readFileSync(join(FIXTURES, 'real-fails.json'), 'utf8')) as Record<
  string,
  Finding[]
>;
const SHA = `${'a'.repeat(39)}b`;
const NOW = '2026-10-01T00:00:00Z';

function real(name: string): Finding {
  const f = REAL[name]?.[0];
  if (!f) throw new Error(`missing fixture ${name}`);
  return f;
}

const cfg = (over: Partial<CrawlConfig> = {}): CrawlConfig => ({
  ...DEFAULT_CRAWL_CONFIG,
  ...over,
});
const input = {
  repo: 'acme/widgets',
  sha: SHA,
  archetype: 'untrusted-text-injection',
  findingIds: ['f1'],
};
/** Jay's per-fail approval of `input` at SHA (0092). */
const approvedInput = [
  { repo: input.repo, sha: SHA, findingId: 'f1', skeptic: 'could-not-refute' as const },
];

describe('gate (KTD6 steps 1, 3, 5)', () => {
  it('holds an allowlisted archetype tripped by a false-positive report', () => {
    const tripped = { ...emptyLedger(), trippedArchetypes: [input.archetype] };
    const r = gate(input, cfg({ allowlist: [input.archetype], submitMode: true }), tripped);
    expect(r).toMatchObject({
      decision: 'held',
      reason: 'archetype tripped by a false-positive report',
    });
  });

  it('holds every fail when the allowlist is empty', () => {
    const r = gate(input, cfg(), emptyLedger());
    expect(r).toMatchObject({ decision: 'held', reason: 'archetype not allowlisted' });
  });

  it('allows an allowlisted archetype as a dry run while submitMode is off', () => {
    const r = gate(
      input,
      cfg({ allowlist: [input.archetype], approved: approvedInput }),
      emptyLedger(),
    );
    expect(r).toEqual({ decision: 'allowed', dryRun: true, tier: 'vulnerability' });
  });

  it('is live (dryRun false) only when submitMode is on', () => {
    const r = gate(
      input,
      cfg({ allowlist: [input.archetype], approved: approvedInput, submitMode: true }),
      emptyLedger(),
    );
    expect(r).toEqual({ decision: 'allowed', dryRun: false, tier: 'vulnerability' });
  });

  it('holds finding ids already disclosed on that repo as a duplicate', () => {
    const ledger = createDisclosure(emptyLedger(), {
      repo: 'acme/widgets',
      findingIds: ['f1', 'f2'],
      archetype: input.archetype,
      state: 'queued',
      now: NOW,
    });
    const r = gate(input, cfg({ allowlist: [input.archetype], approved: approvedInput }), ledger);
    expect(r).toMatchObject({ decision: 'held', reason: 'duplicate' });
  });

  it('does not treat other repos or a resolved-before-report entry as duplicates', () => {
    const other = createDisclosure(emptyLedger(), {
      repo: 'acme/other',
      findingIds: ['f1'],
      archetype: input.archetype,
      state: 'held',
      now: NOW,
    });
    const c = cfg({ allowlist: [input.archetype], approved: approvedInput });
    expect(gate(input, c, other).decision).toBe('allowed');
    const resolved = {
      ...other,
      disclosures: [
        {
          ...other.disclosures[0]!,
          repo: 'acme/widgets',
          state: 'resolved-before-report' as const,
        },
      ],
    };
    expect(gate(input, c, resolved).decision).toBe('allowed');
  });
});

describe('gate: per-fail approval (0092)', () => {
  const allow = (approved: CrawlConfig['approved']) =>
    cfg({ allowlist: [input.archetype], approved, submitMode: true });

  it('holds an allowlisted fail nobody approved', () => {
    expect(gate(input, allow([]), emptyLedger())).toMatchObject({
      decision: 'held',
      reason: 'not approved at this commit',
    });
  });

  it('holds a fail approved at a different commit (the repo moved after review)', () => {
    const stale = [{ ...approvedInput[0]!, sha: 'c'.repeat(40) }];
    expect(gate(input, allow(stale), emptyLedger())).toMatchObject({
      decision: 'held',
      reason: 'not approved at this commit',
    });
  });

  it('holds when only some of the reported finding ids are approved', () => {
    const two = { ...input, findingIds: ['f1', 'f2'] };
    expect(gate(two, allow(approvedInput), emptyLedger())).toMatchObject({
      decision: 'held',
      reason: 'not approved at this commit',
    });
  });

  it('does not let an approval for another repo release this one', () => {
    const other = [{ ...approvedInput[0]!, repo: 'acme/other' }];
    expect(gate(input, allow(other), emptyLedger()).decision).toBe('held');
  });

  it('never replaces the allowlist: an approved fail of a non-allowlisted archetype is held', () => {
    const c = cfg({ approved: approvedInput, submitMode: true });
    expect(gate(input, c, emptyLedger())).toMatchObject({
      decision: 'held',
      reason: 'archetype not allowlisted',
    });
  });

  it('never overrides the tripwire', () => {
    const tripped = { ...emptyLedger(), trippedArchetypes: [input.archetype] };
    expect(gate(input, allow(approvedInput), tripped)).toMatchObject({
      decision: 'held',
      reason: 'archetype tripped by a false-positive report',
    });
  });

  it('allows a fail whose every finding id is approved at that exact commit', () => {
    const two = { ...input, findingIds: ['f1', 'f2'] };
    const both = [...approvedInput, { ...approvedInput[0]!, findingId: 'f2' }];
    expect(gate(two, allow(both), emptyLedger())).toEqual({
      decision: 'allowed',
      dryRun: false,
      tier: 'vulnerability',
    });
  });
});

describe('gate: report tier from the skeptic result (0101)', () => {
  const doubtfulOnly = [{ ...approvedInput[0]!, skeptic: 'doubtful' as const }];
  const cfgP = (sendPossible: boolean, approved: CrawlConfig['approved'] = doubtfulOnly) =>
    cfg({ allowlist: [input.archetype], approved, submitMode: true, sendPossible });

  it('holds a doubtful (possible) report while sendPossible is off', () => {
    expect(gate(input, cfgP(false), emptyLedger())).toMatchObject({
      decision: 'held',
      reason: 'possible vulnerability: sending paused',
    });
  });

  it('sends a doubtful report as the possible tier once sendPossible is on', () => {
    expect(gate(input, cfgP(true), emptyLedger())).toEqual({
      decision: 'allowed',
      dryRun: false,
      tier: 'possible',
    });
  });

  it('a report with any doubtful finding is the possible tier', () => {
    const two = { ...input, findingIds: ['f1', 'f2'] };
    const mixed = [approvedInput[0]!, { ...doubtfulOnly[0]!, findingId: 'f2' }];
    expect(gate(two, cfgP(true, mixed), emptyLedger())).toMatchObject({ tier: 'possible' });
  });
});

describe('tierReport (0101)', () => {
  const base = composeReport({
    repo: 'acme/widgets',
    sha: SHA,
    findings: [real('untrusted-text-shell')],
    blastgateVersion: '9.9.9',
  });

  it('labels a could-not-refute report a security vulnerability, confidently', () => {
    const r = tierReport(base, 'vulnerability', 'acme/widgets');
    expect(r.summary).toMatch(
      /^Security vulnerability in acme\/widgets: attacker-controlled input reaches /,
    );
    expect(r.description).toMatch(/^## Security vulnerability in `acme\/widgets`/);
    expect(r.description).toMatch(/could not disprove/i);
    expect(r.description).not.toMatch(/possible/i);
    expect(r.severity).toBe('high');
  });

  it('labels a doubtful report a possible vulnerability and asks the owner to investigate', () => {
    const r = tierReport(base, 'possible', 'acme/widgets');
    expect(r.summary).toMatch(/^Possible security vulnerability in acme\/widgets: /);
    expect(r.description).toMatch(/^## Possible security vulnerability in `acme\/widgets`/);
    expect(r.description).toMatch(/please investigate/i);
    expect(r.description).toMatch(/could not confirm every step/i);
    expect(r.description).not.toMatch(/proven path/i);
    expect(r.severity).toBe('medium');
  });

  it('keeps every finding block and the commit footer unchanged', () => {
    for (const t of ['vulnerability', 'possible'] as const) {
      const r = tierReport(base, t, 'acme/widgets');
      const tail = (d: string) => d.slice(d.indexOf('\n\n---\n\n'));
      expect(tail(r.description)).toBe(tail(base.description));
      expect(r.description).toContain(SHA);
      expect(r.summary.length).toBeLessThanOrEqual(1024);
    }
  });
});

describe('composeReport (KTD7)', () => {
  const base = { repo: 'acme/widgets', sha: SHA, blastgateVersion: '9.9.9' };

  it('writes an automated-scan header, evidence, fix, labels, version and full SHA', () => {
    const { summary, description } = composeReport({
      ...base,
      findings: [real('untrusted-text-shell')],
    });
    expect(summary.length).toBeLessThanOrEqual(1024);
    expect(summary).toContain('acme/widgets');
    expect(description).toMatch(/automated/i);
    expect(description).toMatch(/proven path/i);
    expect(description).toContain(
      'https://github.com/jwolberg/blastgate/blob/main/docs/threat-model.md',
    );
    expect(description).toMatch(/90[- ]day/);
    expect(description).toMatch(/decline/i);
    expect(description).toContain('.github/workflows/triage.yml:12');
    expect(description).toContain('DEPLOY_KEY');
    expect(description).toContain('**fix:**');
    expect(description).toContain('`ASI01:2026`');
    expect(description).toContain('`MCP10:2025`');
    expect(description).toContain('9.9.9');
    expect(description).toContain(SHA);
  });

  it('reports every finding for the repo', () => {
    const { description } = composeReport({
      ...base,
      findings: [real('untrusted-text-shell'), real('fork-pr-secret')],
    });
    expect(description.match(/^### /gm)).toHaveLength(2);
  });

  it('never carries the illustrative payload', () => {
    for (const [name, list] of Object.entries(REAL)) {
      const f = list[0]!;
      if (!f.evidence?.payload) continue;
      const { summary, description } = composeReport({ ...base, findings: [f] });
      expect(description, name).not.toContain(f.evidence.payload);
      expect(summary, name).not.toContain(f.evidence.payload);
      expect(description, name).not.toContain('attacker.example');
    }
    expect(REAL['untrusted-text-shell']![0]!.evidence?.payload).toBeTruthy();
  });

  it('keeps the summary at or under 1024 chars for a very long path', () => {
    const f = real('untrusted-text-shell');
    const long = `${'a/'.repeat(5000)}x.yml`;
    const big: Finding = {
      ...f,
      path: [long, long, long],
      entry: { ...f.entry, label: long },
      sink: { ...f.sink, identity: long },
      evidence: { ...f.evidence!, file: long },
    };
    const { summary } = composeReport({
      ...base,
      repo: `o/${'r'.repeat(5000)}`,
      findings: [big, big],
    });
    expect(summary.length).toBeLessThanOrEqual(1024);
    expect(summary.length).toBeGreaterThan(0);
  });

  describe('hostile repo-sourced strings', () => {
    const H =
      '[x](https://evil) ![i](https://evil/p.png) @octocat <img src=x> #123 ``` `` ` \u0007bell www.evil.com a@b.co';
    const make = (v: string, nl: string): Finding => {
      const f = real('untrusted-text-shell');
      return {
        ...f,
        path: [`entry ${v}`, `step ${v}`, `sink ${v}`],
        entry: { ...f.entry, label: `label ${v}` },
        sink: { ...f.sink, identity: `ident ${v}` },
        reason: `why ${v}${nl}second line`,
        remediation: `fix ${v}`,
        labels: [`L ${v}`],
        acknowledged: `ack ${v}`,
        advisories: [{ id: `GHSA ${v}`, package: `pkg ${v}`, summary: v }],
        evidence: { ...f.evidence!, file: `.github/workflows/${v}.yml`, capability: `cap ${v}` },
      };
    };
    const base = { repo: 'acme/widgets', sha: SHA, blastgateVersion: '9.9.9' };

    it('renders links, images, mentions, html, issue refs, bare urls and control chars inert', () => {
      const { summary, description } = composeReport({ ...base, findings: [make(H, '\n')] });
      for (const text of [summary, description]) {
        expect(text).not.toContain('](');
        expect(text).not.toContain('![');
        expect(text).not.toContain('<img');
        expect(text).not.toMatch(/<[a-zA-Z!/]/);
        expect(text).not.toContain('@octocat');
        expect(text).not.toContain('a@b.co');
        expect(text).not.toContain('#123');
        expect(text).not.toContain('https://evil');
        expect(text).not.toContain('www.evil.com');
        // eslint-disable-next-line no-control-regex
        expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
      }
      expect(description).toContain('octocat'); // still readable, just not a live mention
    });

    it('cannot break out of a code span: backtick and line structure equals the benign report', () => {
      const h = composeReport({ ...base, findings: [make(H, '\n')] }).description;
      const b = composeReport({ ...base, findings: [make('x', ' ')] }).description;
      expect(h.split('`').length).toBe(b.split('`').length);
      expect(h.split('\n').length).toBe(b.split('\n').length);
    });

    it('caps each field length', () => {
      const f = make('x', ' ');
      const long = 'z'.repeat(20000);
      const { description } = composeReport({
        ...base,
        findings: [
          {
            ...f,
            reason: long,
            remediation: long,
            path: [long],
            entry: { ...f.entry, label: long },
          },
        ],
      });
      expect(description.length).toBeLessThan(8000);
    });
  });

  it('snapshots the real incident fixtures', () => {
    for (const [name, list] of Object.entries(REAL)) {
      const { summary, description } = composeReport({
        repo: 'acme/widgets',
        sha: SHA,
        blastgateVersion: '0.1.0',
        findings: list,
      });
      expect(`${summary}\n\n${description}`).toMatchSnapshot(name);
    }
  });
});
