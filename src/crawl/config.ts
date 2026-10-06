/**
 * Crawler ops config (U4, KTD6) — the knobs that gate outbound writes. Strict: unknown keys
 * are rejected so a typo (`submitmode`) can never silently leave a safety default in place or
 * flip one. Every default is the safe one: empty allowlist, no approvals, dry run, site unpublished.
 */

import { isPlainRepoName } from './github';

export interface CrawlThrottle {
  perHour: number;
  perDay: number;
}

/**
 * Jay's hand verdict that one fail-tier finding is real, pinned to the exact commit he reviewed
 * (0092). A report is sent only when every finding in it carries one for the commit it names.
 */
export interface Approval {
  repo: string;
  /** Full 40-char lowercase commit sha the finding was reviewed at. */
  sha: string;
  findingId: string;
  /**
   * The skeptic's verdict on the packet this approval came from (0100). It sets the report tier
   * (0101): could-not-refute is a security vulnerability, doubtful a possible one. A refuted or
   * unchecked fail can never be approved.
   */
  skeptic: ReportableSkeptic;
}

/** The skeptic verdict for a vulnerability it tried and failed to disprove (0100). */
export const SKEPTIC_PASS = 'could-not-refute';
/** Skeptic verdicts that may be reported, most confident first (0101). */
export const REPORTABLE_SKEPTIC = [SKEPTIC_PASS, 'doubtful'] as const;
export type ReportableSkeptic = (typeof REPORTABLE_SKEPTIC)[number];

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
  /**
   * Wall-clock limit on discovery per run (0088). Secondary search limits can stretch a few
   * searches into hours, so the budget alone does not bound time; past this, no new search
   * starts and the run moves on to scanning.
   */
  discoveryMinutes: number;
  /** Per-fail approvals (0092). Required on top of `allowlist`; empty = nothing is sent. */
  approved: Approval[];
  /**
   * Send possible-vulnerability (skeptic: doubtful) reports (0101). Off until the analyzer's
   * guard and wrong-line bugs (0095/0096) are fixed; those reports are held meanwhile.
   */
  sendPossible: boolean;
  /**
   * Days a PVR enable request (0102) stays open (0106). Past it, the owner never turned PVR on:
   * the hold becomes final and the repo is no longer rescanned for it.
   */
  pvrRequestTtlDays: number;
}

/** A year: past that an unanswered request is not coming back. */
export const MAX_PVR_REQUEST_TTL_DAYS = 365;

/** Upper bound: well above what a 5 hour job can spend at the 9/min search throttle (~2,700). */
export const MAX_DISCOVERY_BUDGET = 5000;

/** Leaves room in the 300 minute scan job for one in-flight request's retries and the scans. */
export const MAX_DISCOVERY_MINUTES = 240;

export const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  allowlist: [],
  submitMode: false,
  publishSite: false,
  reporterLogin: '',
  throttle: { perHour: 5, perDay: 20 },
  discoveryBudget: 300,
  discoveryMinutes: 60,
  approved: [],
  sendPossible: false,
  pvrRequestTtlDays: 90,
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

const SHA_RE = /^[0-9a-f]{40}$/;

function approvals(v: unknown): Approval[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) fail('approved must be an array of {repo, sha, findingId, skeptic}');
  const seen = new Map<string, Approval>();
  v.forEach((a: unknown, i) => {
    const where = `approved[${i}]`;
    if (!isObj(a)) fail(`${where} must be an object`);
    rejectUnknown(a, ['repo', 'sha', 'findingId', 'skeptic'], where);
    const { repo, sha, findingId, skeptic } = a;
    if (typeof repo !== 'string' || !isPlainRepoName(repo))
      fail(`${where}.repo must be owner/name`);
    if (typeof sha !== 'string' || !SHA_RE.test(sha)) {
      fail(`${where}.sha must be a full 40-char lowercase commit sha`);
    }
    if (typeof findingId !== 'string' || findingId === '') {
      fail(`${where}.findingId must be a non-empty string`);
    }
    if (!(REPORTABLE_SKEPTIC as readonly unknown[]).includes(skeptic)) {
      fail(
        `${where}.skeptic must be one of ${REPORTABLE_SKEPTIC.join(', ')}; a refuted or unchecked fail cannot be approved (use crawl approve)`,
      );
    }
    seen.set(JSON.stringify([repo, sha, findingId]), {
      repo,
      sha,
      findingId,
      skeptic: skeptic as ReportableSkeptic,
    });
  });
  return [...seen.values()];
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
    [
      'allowlist',
      'submitMode',
      'publishSite',
      'reporterLogin',
      'throttle',
      'discoveryBudget',
      'discoveryMinutes',
      'approved',
      'sendPossible',
      'pvrRequestTtlDays',
    ],
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
    discoveryMinutes: posInt(
      raw,
      'discoveryMinutes',
      DEFAULT_CRAWL_CONFIG.discoveryMinutes,
      'discoveryMinutes',
      MAX_DISCOVERY_MINUTES,
    ),
    approved: approvals(raw.approved),
    sendPossible: bool(raw, 'sendPossible', DEFAULT_CRAWL_CONFIG.sendPossible),
    pvrRequestTtlDays: posInt(
      raw,
      'pvrRequestTtlDays',
      DEFAULT_CRAWL_CONFIG.pvrRequestTtlDays,
      'pvrRequestTtlDays',
      MAX_PVR_REQUEST_TTL_DAYS,
    ),
  };
}
