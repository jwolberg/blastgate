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
    });
    expect(DEFAULT_CRAWL_CONFIG.allowlist).toEqual([]);
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
    });
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
