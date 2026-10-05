import { describe, expect, it } from 'vitest';
import { DEFAULT_CRAWL_CONFIG, parseCrawlConfig } from './config';

describe('parseCrawlConfig', () => {
  it('defaults: empty allowlist, dry run, site off, 5/hour 20/day', () => {
    expect(parseCrawlConfig('{}')).toEqual({
      allowlist: [],
      submitMode: false,
      publishSite: false,
      reporterLogin: '',
      throttle: { perHour: 5, perDay: 20 },
      discoveryBudget: 300,
      discoveryMinutes: 60,
      approved: [],
    });
    expect(DEFAULT_CRAWL_CONFIG.allowlist).toEqual([]);
    expect(DEFAULT_CRAWL_CONFIG.approved).toEqual([]);
  });

  it('accepts a full valid config and a partial throttle', () => {
    const c = parseCrawlConfig(
      JSON.stringify({
        allowlist: ['untrusted-text-injection'],
        submitMode: true,
        publishSite: true,
        reporterLogin: 'blastgate-bot',
        throttle: { perHour: 2 },
      }),
    );
    expect(c).toEqual({
      allowlist: ['untrusted-text-injection'],
      submitMode: true,
      publishSite: true,
      reporterLogin: 'blastgate-bot',
      throttle: { perHour: 2, perDay: 20 },
      discoveryBudget: 300,
      discoveryMinutes: 60,
      approved: [],
    });
  });

  it('accepts per-fail approvals pinned to a full commit sha, deduplicated (0092)', () => {
    const a = {
      repo: 'acme/widgets',
      sha: 'a'.repeat(40),
      findingId: 'entry:x=>sink:y',
      skeptic: 'could-not-refute',
    };
    expect(parseCrawlConfig(JSON.stringify({ approved: [a, { ...a }] })).approved).toEqual([a]);
  });

  it('rejects a malformed approval (0092)', () => {
    const ok = {
      repo: 'acme/widgets',
      sha: 'a'.repeat(40),
      findingId: 'f1',
      skeptic: 'could-not-refute',
    };
    const bad = (v: unknown) => () => parseCrawlConfig(JSON.stringify({ approved: v }));
    expect(bad('f1')).toThrow(/approved/);
    expect(bad([{ ...ok, sha: 'abc123' }])).toThrow(/sha/);
    expect(bad([{ ...ok, sha: 'A'.repeat(40) }])).toThrow(/sha/);
    expect(bad([{ ...ok, repo: '../evil' }])).toThrow(/repo/);
    expect(bad([{ ...ok, findingId: '' }])).toThrow(/findingId/);
    expect(bad([{ ...ok, note: 'x' }])).toThrow(/unknown key "note"/);
    expect(bad([{ repo: ok.repo, sha: ok.sha, skeptic: ok.skeptic }])).toThrow(/findingId/);
  });

  it('rejects an approval the skeptic did not pass (0100)', () => {
    const ok = { repo: 'acme/widgets', sha: 'a'.repeat(40), findingId: 'f1' };
    const bad = (v: unknown) => () => parseCrawlConfig(JSON.stringify({ approved: [v] }));
    expect(bad(ok)).toThrow(/skeptic/);
    expect(bad({ ...ok, skeptic: 'doubtful' })).toThrow(/skeptic/);
    expect(bad({ ...ok, skeptic: 'refuted' })).toThrow(/skeptic/);
    expect(bad({ ...ok, skeptic: 'pending' })).toThrow(/skeptic/);
  });

  it('accepts a positive integer discoveryBudget', () => {
    expect(parseCrawlConfig('{"discoveryBudget":50}').discoveryBudget).toBe(50);
  });

  it('rejects a zero, negative, fractional, huge, or non-number discoveryBudget', () => {
    for (const v of ['0', '-3', '1.5', '"300"', 'null', '100000']) {
      expect(() => parseCrawlConfig(`{"discoveryBudget":${v}}`), v).toThrow(
        /discoveryBudget must be/,
      );
    }
  });

  it('0088: accepts discoveryMinutes and rejects zero, fractional, or over the 240 cap', () => {
    expect(parseCrawlConfig('{"discoveryMinutes":20}').discoveryMinutes).toBe(20);
    for (const v of ['0', '-1', '2.5', '"60"', '241']) {
      expect(() => parseCrawlConfig(`{"discoveryMinutes":${v}}`), v).toThrow(
        /discoveryMinutes must be/,
      );
    }
  });

  it('rejects unknown keys at the top level and in throttle', () => {
    expect(() => parseCrawlConfig('{"submitmode":true}')).toThrow(/unknown key "submitmode"/);
    expect(() => parseCrawlConfig('{"throttle":{"perMinute":1}}')).toThrow(/unknown key/);
  });

  it('rejects wrong types and bad values', () => {
    expect(() => parseCrawlConfig('{"submitMode":"yes"}')).toThrow(/submitMode/);
    expect(() => parseCrawlConfig('{"publishSite":1}')).toThrow(/publishSite/);
    expect(() => parseCrawlConfig('{"allowlist":"a"}')).toThrow(/allowlist/);
    expect(() => parseCrawlConfig('{"allowlist":[""]}')).toThrow(/allowlist/);
    expect(() => parseCrawlConfig('{"throttle":{"perHour":0}}')).toThrow(/perHour/);
    expect(() => parseCrawlConfig('{"throttle":{"perDay":1.5}}')).toThrow(/perDay/);
    expect(() => parseCrawlConfig('{"reporterLogin":5}')).toThrow(/reporterLogin/);
    expect(() => parseCrawlConfig('{"reporterLogin":"a b"}')).toThrow(/reporterLogin/);
    expect(() => parseCrawlConfig('[]')).toThrow(/object/);
    expect(() => parseCrawlConfig('not json')).toThrow(/JSON/);
  });
});
