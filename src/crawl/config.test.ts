import { describe, expect, it } from 'vitest';
import { DEFAULT_CRAWL_CONFIG, parseCrawlConfig } from './config';

describe('parseCrawlConfig', () => {
  it('defaults: empty allowlist, dry run, site off, 5/hour 20/day', () => {
    expect(parseCrawlConfig('{}')).toEqual({
      allowlist: [],
      submitMode: false,
      publishSite: false,
      throttle: { perHour: 5, perDay: 20 },
    });
    expect(DEFAULT_CRAWL_CONFIG.allowlist).toEqual([]);
  });

  it('accepts a full valid config and a partial throttle', () => {
    const c = parseCrawlConfig(
      JSON.stringify({
        allowlist: ['untrusted-text-injection'],
        submitMode: true,
        publishSite: true,
        throttle: { perHour: 2 },
      }),
    );
    expect(c).toEqual({
      allowlist: ['untrusted-text-injection'],
      submitMode: true,
      publishSite: true,
      throttle: { perHour: 2, perDay: 20 },
    });
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
    expect(() => parseCrawlConfig('[]')).toThrow(/object/);
    expect(() => parseCrawlConfig('not json')).toThrow(/JSON/);
  });
});
