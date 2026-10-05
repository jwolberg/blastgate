/**
 * PVR submitter (U5, KTD4/KTD6 steps 4-8). Runs in the SUBMIT job, which never clones: it
 * consumes candidates the scan job prepared (composed report + re-verify result) and files
 * them as GitHub private vulnerability reports.
 *
 * Safety posture: the ledger is persisted as `submitting` BEFORE the POST goes out, so a crash
 * mid-request leaves a record that startup recovery holds for Jay (AE7). Anything that is not a
 * definite success or a definite pre-send refusal ends `held` with a non-retryable reason; a
 * `submitting` entry is never retried automatically.
 */

import { gate, tierReport } from './disclose';
import type { CrawlConfig } from './config';
import { GitHubRateLimitError, isPlainRepoName, type GitHubClient } from './github';
import {
  REASON_NO_PVR,
  REASON_RATE_LIMITED,
  UNCERTAIN_REASON,
  isRetryableHold,
  createDisclosure,
  recordWouldSend,
  transition,
  type Disclosure,
  type DisclosureKey,
  type Ledger,
} from './ledger';
import type { ReverifyStatus } from './scan';

export interface SubmitCandidate {
  repo: string;
  /** Full sha of the scanned commit the report names (its footer); approvals pin to it (0092). */
  sha: string;
  archetype: string;
  findingIds: string[];
  report: { summary: string; description: string };
  reverify: ReverifyStatus;
}

export type SubmitOutcomeKind =
  'submitted' | 'dry-run' | 'held' | 'deferred' | 'resolved' | 'retry' | 'duplicate' | 'stopped';

export interface SubmitOutcome {
  repo: string;
  outcome: SubmitOutcomeKind;
  reason?: string;
}

export interface SubmitSummary {
  counts: Record<string, number>;
  /** Set when the run halted early (kill switch, GitHub rate limit). */
  stoppedReason?: string;
}

export interface SubmitOptions {
  ledger: Ledger;
  candidates: readonly SubmitCandidate[];
  config: CrawlConfig;
  client: GitHubClient;
  killSwitch: boolean;
  /** Durably save the ledger. Awaited before any POST and after its result is recorded. */
  persist: (ledger: Ledger) => Promise<void>;
  now: () => Date;
}

export interface SubmitResult {
  ledger: Ledger;
  summary: SubmitSummary;
  outcomes: SubmitOutcome[];
}

export { REASON_NO_PVR };
const REASON_SEND_FAILED = 'submission failed';
const STOP_KILL = 'kill switch';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/** The single place the PVR request body is built. GitHub may require `vulnerabilities`; send it empty. */
export function buildRequestBody(
  report: SubmitCandidate['report'] & { severity?: 'high' | 'medium' },
): Record<string, unknown> {
  return {
    summary: report.summary,
    description: report.description,
    severity: report.severity ?? 'high',
    vulnerabilities: [],
  };
}

const sameIds = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && [...a].sort().join('\n') === [...b].sort().join('\n');

/** Submissions inside the trailing hour/day, from ledger timestamps (`submitting` counts: it may be sent). */
function budgetUsed(ledger: Ledger, now: number): { hour: number; day: number } {
  let hour = 0;
  let day = 0;
  for (const d of ledger.disclosures) {
    if (d.state !== 'submitted' && d.state !== 'submitting') continue;
    const age = now - Date.parse(d.updatedAt);
    if (age < DAY_MS) day++;
    if (age < HOUR_MS) hour++;
  }
  return { hour, day };
}

/**
 * Only a 429 stops the run. A header-signalled 403 never reaches here: the client waits it out
 * and throws GitHubRateLimitError. A plain 403 is a permission answer for that one repo.
 */
function isRateLimit(status: number): boolean {
  return status === 429;
}

export async function submitAll(opts: SubmitOptions): Promise<SubmitResult> {
  const { config, client, persist } = opts;
  let ledger = opts.ledger;
  const outcomes: SubmitOutcome[] = [];
  let stoppedReason: string | undefined;
  let dirty = false;

  const iso = (): string => opts.now().toISOString();
  const push = (repo: string, outcome: SubmitOutcomeKind, reason?: string): void => {
    outcomes.push({ repo, outcome, ...(reason !== undefined ? { reason } : {}) });
  };
  const apply = (next: Ledger): void => {
    ledger = next;
    dirty = true;
  };

  for (const c of opts.candidates) {
    if (stoppedReason !== undefined) {
      push(c.repo, 'stopped', stoppedReason);
      continue;
    }
    if (opts.killSwitch) {
      stoppedReason = STOP_KILL;
      push(c.repo, 'stopped', stoppedReason);
      continue;
    }
    if (!isPlainRepoName(c.repo) || c.findingIds.length === 0) {
      push(c.repo, 'held', 'invalid repo or empty finding ids');
      continue;
    }

    // Existing disclosure for these ids? Only queued / retryable-held ones are worked again.
    const overlapping = ledger.disclosures.filter(
      (d) =>
        d.repo === c.repo &&
        d.state !== 'resolved-before-report' &&
        d.findingIds.some((id) => c.findingIds.includes(id)),
    );
    let existing: Disclosure | undefined;
    if (overlapping.length > 0) {
      const only = overlapping.length === 1 ? overlapping[0] : undefined;
      const reusable =
        only !== undefined &&
        sameIds(only.findingIds, c.findingIds) &&
        (only.state === 'queued' || (only.state === 'held' && isRetryableHold(only)));
      if (!reusable) {
        push(c.repo, 'duplicate', `existing disclosure (${overlapping[0]?.state})`);
        continue;
      }
      existing = only;
    }

    // Throttle: deferred work stays out of the ledger and is simply picked up next run.
    const used = budgetUsed(ledger, opts.now().getTime());
    if (used.hour >= config.throttle.perHour || used.day >= config.throttle.perDay) {
      push(
        c.repo,
        'deferred',
        used.hour >= config.throttle.perHour ? 'hourly budget' : 'daily budget',
      );
      continue;
    }

    const key: DisclosureKey = { repo: c.repo, findingIds: c.findingIds };
    if (!existing) {
      apply(
        createDisclosure(ledger, {
          ...key,
          archetype: c.archetype,
          state: 'queued',
          now: iso(),
        }),
      );
    }
    const current = (): Disclosure =>
      ledger.disclosures.find(
        (d) =>
          d.repo === c.repo &&
          sameIds(d.findingIds, c.findingIds) &&
          d.state !== 'resolved-before-report',
      ) as Disclosure;

    /** Hold in place; no write if it is already held for this very reason. */
    const hold = (reason: string): void => {
      const d = current();
      if (d.state === 'held' && d.reason === reason) return;
      // held -> held is not a legal edge: a changed reason goes through queued.
      if (d.state === 'held') apply(transition(ledger, key, 'queued', { now: iso() }));
      apply(transition(ledger, key, 'held', { now: iso(), reason }));
    };
    /** Held -> queued just before an attempt, so a failed attempt does not churn the ledger. */
    const queue = (): void => {
      if (current().state === 'held') apply(transition(ledger, key, 'queued', { now: iso() }));
    };

    // Re-verify result from the scan job.
    if (c.reverify === 'resolved') {
      apply(transition(ledger, key, 'resolved-before-report', { now: iso() }));
      push(c.repo, 'resolved');
      continue;
    }
    if (c.reverify !== 'still-fails') {
      push(c.repo, 'retry', c.reverify);
      continue;
    }

    // Gate (tripwire, allowlist, per-fail approval, once-per-finding), evaluated without this
    // entry's own record.
    const others: Ledger = {
      ...ledger,
      disclosures: ledger.disclosures.filter((d) => d !== current()),
    };
    const decision = gate(
      { repo: c.repo, sha: c.sha, archetype: c.archetype, findingIds: c.findingIds },
      config,
      others,
    );
    if (decision.decision === 'held') {
      const reason = decision.reason ?? 'held by gate';
      hold(reason);
      push(c.repo, 'held', reason);
      continue;
    }

    // PVR pre-check.
    let pvrEnabled = false;
    let noPvrReason = REASON_NO_PVR;
    try {
      const pvr = await client.get(`/repos/${c.repo}/private-vulnerability-reporting`);
      if (isRateLimit(pvr.status)) {
        stoppedReason = `GitHub rate limit (HTTP ${pvr.status}) on PVR pre-check`;
        push(c.repo, 'stopped', stoppedReason);
        continue;
      }
      const body = pvr.json as { enabled?: unknown } | null;
      pvrEnabled = pvr.status === 200 && body?.enabled === true;
      if (pvr.status === 403) noPvrReason = `${REASON_NO_PVR} (HTTP 403)`;
    } catch (e) {
      if (e instanceof GitHubRateLimitError) {
        stoppedReason = `GitHub rate limit (HTTP ${e.status}) on PVR pre-check`;
        push(c.repo, 'stopped', stoppedReason);
        continue;
      }
      push(c.repo, 'retry', `PVR pre-check failed: ${(e as Error).message}`);
      continue;
    }
    if (!pvrEnabled) {
      hold(noPvrReason);
      push(c.repo, 'held', noPvrReason);
      continue;
    }

    // Tier (0101): the skeptic's result decides how confidently the report speaks.
    const body = buildRequestBody(tierReport(c.report, decision.tier ?? 'possible', c.repo));
    queue();

    if (decision.dryRun) {
      apply(recordWouldSend(ledger, key, body, iso()));
      push(c.repo, 'dry-run');
      continue;
    }

    // Persist `submitting` BEFORE the request leaves the process (AE7).
    apply(transition(ledger, key, 'submitting', { now: iso() }));
    await persist(ledger);
    dirty = false;

    let status = 0;
    let json: unknown = null;
    try {
      const r = await client.post(`/repos/${c.repo}/security-advisories/reports`, body);
      status = r.status;
      json = r.json;
    } catch (e) {
      if (e instanceof GitHubRateLimitError) {
        // Refused by GitHub: definitely not filed.
        const reason = `${REASON_RATE_LIMITED} ${e.status})`;
        apply(transition(ledger, key, 'held', { now: iso(), reason }));
        stoppedReason = `GitHub rate limit (HTTP ${e.status})`;
        push(c.repo, 'held', reason);
      } else {
        // Transport died mid-request: the report may exist. Final hold.
        apply(transition(ledger, key, 'held', { now: iso(), reason: UNCERTAIN_REASON }));
        push(c.repo, 'held', UNCERTAIN_REASON);
      }
      await persist(ledger);
      dirty = false;
      continue;
    }

    const res = json as { html_url?: unknown; ghsa_id?: unknown } | null;
    if (status === 201 && typeof res?.html_url === 'string') {
      apply(
        transition(ledger, key, 'submitted', {
          now: iso(),
          reportUrl: res.html_url,
          ...(typeof res.ghsa_id === 'string' ? { ghsaId: res.ghsa_id } : {}),
        }),
      );
      push(c.repo, 'submitted');
    } else if (isRateLimit(status)) {
      const reason = `${REASON_RATE_LIMITED} ${status})`;
      apply(transition(ledger, key, 'held', { now: iso(), reason }));
      stoppedReason = `GitHub rate limit (HTTP ${status})`;
      push(c.repo, 'held', reason);
    } else if (status === 201) {
      // Created but no URL to record: it exists, so never re-send.
      apply(transition(ledger, key, 'held', { now: iso(), reason: UNCERTAIN_REASON }));
      push(c.repo, 'held', UNCERTAIN_REASON);
    } else {
      const reason = `${REASON_SEND_FAILED} (HTTP ${status})`;
      apply(transition(ledger, key, 'held', { now: iso(), reason }));
      push(c.repo, 'held', reason);
    }
    await persist(ledger);
    dirty = false;
  }

  if (dirty) await persist(ledger);

  const counts: Record<string, number> = {};
  for (const o of outcomes) counts[o.outcome] = (counts[o.outcome] ?? 0) + 1;
  return {
    ledger,
    summary: { counts, ...(stoppedReason !== undefined ? { stoppedReason } : {}) },
    outcomes,
  };
}
