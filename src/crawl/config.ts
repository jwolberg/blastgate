/**
 * Crawler ops config (U4, KTD6) — the knobs that gate outbound writes. Strict: unknown keys
 * are rejected so a typo (`submitmode`) can never silently leave a safety default in place or
 * flip one. Every default is the safe one: empty allowlist, dry run, site unpublished.
 */

export interface CrawlThrottle {
  perHour: number;
  perDay: number;
}

export interface CrawlConfig {
  /** Archetypes whose fails are auto-submitted (KTD6.1). Empty = everything is held. */
  allowlist: string[];
  /** Off = dry run: the exact report is recorded, nothing is sent (KTD6.3). */
  submitMode: boolean;
  /** Off = the site is built but never pushed (KTD6.3). */
  publishSite: boolean;
  /** GitHub login the reports are filed as; credits for it mean "credited". Empty = tracking skipped. */
  reporterLogin: string;
  throttle: CrawlThrottle;
  /** Max code-search requests one scan run spends on discovery (~9/min, so 300 is ~35 min). */
  discoveryBudget: number;
}

/** Upper bound: well above what a 5 hour job can spend at the 9/min search throttle (~2,700). */
export const MAX_DISCOVERY_BUDGET = 5000;

export const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  allowlist: [],
  submitMode: false,
  publishSite: false,
  reporterLogin: '',
  throttle: { perHour: 5, perDay: 20 },
  discoveryBudget: 300,
};

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function fail(msg: string): never {
  throw new Error(`invalid crawl config: ${msg}`);
}

function rejectUnknown(o: Record<string, unknown>, known: readonly string[], where: string): void {
  for (const k of Object.keys(o)) {
    if (!known.includes(k)) fail(`unknown key "${k}"${where ? ` in ${where}` : ''}`);
  }
}

function bool(o: Record<string, unknown>, k: string, dflt: boolean): boolean {
  const v = o[k];
  if (v === undefined) return dflt;
  if (typeof v !== 'boolean') fail(`${k} must be a boolean`);
  return v;
}

function posInt(
  o: Record<string, unknown>,
  k: string,
  dflt: number,
  label = `throttle.${k}`,
  max = Number.MAX_SAFE_INTEGER,
): number {
  const v = o[k];
  if (v === undefined) return dflt;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > max) {
    fail(`${label} must be a positive integer${max < Number.MAX_SAFE_INTEGER ? ` <= ${max}` : ''}`);
  }
  return v;
}

/** Parse the ops config JSON. Throws on invalid JSON, unknown keys, or wrong types. */
export function parseCrawlConfig(text: string): CrawlConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return fail(`not valid JSON (${(e as Error).message})`);
  }
  if (!isObj(raw)) fail('top level must be an object');
  rejectUnknown(
    raw,
    ['allowlist', 'submitMode', 'publishSite', 'reporterLogin', 'throttle', 'discoveryBudget'],
    '',
  );

  let allowlist: string[] = [];
  if (raw.allowlist !== undefined) {
    const a = raw.allowlist;
    if (!Array.isArray(a) || !a.every((x) => typeof x === 'string' && x !== '')) {
      fail('allowlist must be an array of non-empty strings');
    }
    allowlist = [...new Set(a as string[])];
  }

  let throttle = { ...DEFAULT_CRAWL_CONFIG.throttle };
  if (raw.throttle !== undefined) {
    const t = raw.throttle;
    if (!isObj(t)) fail('throttle must be an object');
    rejectUnknown(t, ['perHour', 'perDay'], 'throttle');
    throttle = {
      perHour: posInt(t, 'perHour', throttle.perHour),
      perDay: posInt(t, 'perDay', throttle.perDay),
    };
  }

  let reporterLogin = DEFAULT_CRAWL_CONFIG.reporterLogin;
  if (raw.reporterLogin !== undefined) {
    const l = raw.reporterLogin;
    if (typeof l !== 'string' || !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))?$/.test(l)) {
      fail('reporterLogin must be a GitHub login (or empty)');
    }
    reporterLogin = l;
  }

  return {
    allowlist,
    submitMode: bool(raw, 'submitMode', DEFAULT_CRAWL_CONFIG.submitMode),
    publishSite: bool(raw, 'publishSite', DEFAULT_CRAWL_CONFIG.publishSite),
    reporterLogin,
    throttle,
    discoveryBudget: posInt(
      raw,
      'discoveryBudget',
      DEFAULT_CRAWL_CONFIG.discoveryBudget,
      'discoveryBudget',
      MAX_DISCOVERY_BUDGET,
    ),
  };
}
