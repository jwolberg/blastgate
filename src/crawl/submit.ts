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

import { gate, pvrCloseOutComment, pvrEnableRequest, tierReport } from './disclose';
import type { Approval, CrawlConfig } from './config';
import { GitHubRateLimitError, isPlainRepoName, type GitHubClient } from './github';
import {
  REASON_NO_PVR,
  REASON_NO_PVR_REQUESTED,
  REASON_NOT_APPROVED,
  REASON_RATE_LIMITED,
  REASON_REQUEST_DECLINED,
  reasonPvrRequestFailed,
  reasonRequestGone,
  setPvrRequest,
  UNCERTAIN_REASON,
  isRetryableHold,
  createDisclosure,
  recordWouldSend,
  transition,
  type Disclosure,
  type DisclosureKey,
  type Ledger,
  type PvrRequest,
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
  | 'submitted'
  | 'dry-run'
  | 'held'
  | 'deferred'
  | 'resolved'
  | 'retry'
  | 'duplicate'
  | 'stopped'
  | 'requested';

export interface SubmitOutcome {
  repo: string;
  outcome: SubmitOutcomeKind;
  reason?: string;
}

export interface SubmitSummary {
  counts: Record<string, number>;
  /** Set when the run halted early (kill switch, GitHub rate limit). */
  stoppedReason?: string;
  /** New comments by someone other than us on PVR request issues (0104); read them by hand. */
  ownerReplies: number;
  /** Fails released by an approval carried from an earlier commit (0103). */
  carried: number;
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
    // 0102/0105: a public PVR request, and its close-out, count against the same budget.
    for (const at of [d.pvrRequest?.at, d.pvrRequest?.closedOutAt]) {
      if (at === undefined) continue;
      const age = now - Date.parse(at);
      if (age < DAY_MS) day++;
      if (age < HOUR_MS) hour++;
    }
    if (d.state !== 'submitted' && d.state !== 'submitting') continue;
    const age = now - Date.parse(d.updatedAt);
    if (age < DAY_MS) day++;
    if (age < HOUR_MS) hour++;
  }
  return { hour, day };
}

const ISSUE_URL = /^https:\/\/github\.com\/[^/]+\/[^/]+\/issues\/(\d+)$/;

interface IssueCheck {
  /** `unknown` = the lookup failed or said nothing usable; change nothing. */
  state: 'open' | 'closed' | 'gone' | 'unknown';
  status: number;
  /** New replies by anyone but the issue's author (us), and the newest one's `created_at`. */
  replies: number;
  repliesSeenAt?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Read the PVR request issue (0104): its state, and replies newer than the last ones counted.
 * Rate limits surface as a 429 status or a thrown GitHubRateLimitError; the caller stops.
 */
async function checkRequestIssue(
  client: GitHubClient,
  repo: string,
  req: PvrRequest,
): Promise<IssueCheck> {
  const n = ISSUE_URL.exec(req.url ?? '')?.[1];
  if (n === undefined) return { state: 'unknown', status: 0, replies: 0 };
  const r = await client.get(`/repos/${repo}/issues/${n}`);
  if (r.status === 404 || r.status === 410) return { state: 'gone', status: r.status, replies: 0 };
  const issue = r.json;
  if (r.status !== 200 || !isObj(issue) || (issue.state !== 'open' && issue.state !== 'closed')) {
    return { state: 'unknown', status: r.status, replies: 0 };
  }
  const author = isObj(issue.user) ? String(issue.user.login ?? '').toLowerCase() : '';
  const c = await client.get(`/repos/${repo}/issues/${n}/comments`, {
    per_page: 100,
    ...(req.repliesSeenAt ? { since: req.repliesSeenAt } : {}),
  });
  if (isRateLimit(c.status)) return { state: 'unknown', status: c.status, replies: 0 };
  let replies = 0;
  let newest = req.repliesSeenAt;
  for (const x of c.status === 200 && Array.isArray(c.json) ? c.json : []) {
    if (!isObj(x) || !isObj(x.user) || typeof x.created_at !== 'string') continue;
    if (String(x.user.login ?? '').toLowerCase() === author) continue;
    if (req.repliesSeenAt !== undefined && x.created_at <= req.repliesSeenAt) continue;
    replies++;
    if (newest === undefined || x.created_at > newest) newest = x.created_at;
  }
  return {
    state: issue.state,
    status: r.status,
    replies,
    ...(newest !== undefined ? { repliesSeenAt: newest } : {}),
  };
}

/** GitHub's compare API lists at most 300 files; a full list may be truncated. */
const COMPARE_FILE_CAP = 300;
/** Older reviewed commits tried per fail; each costs one compare request. */
const MAX_CARRY_TRIES = 3;

/**
 * Paths whose change can alter what a workflow does: anything under `.github/` (workflows and
 * the local actions kept there) and any `action.yml`/`action.yaml`, the entry point of a local
 * action wherever it lives.
 */
export function touchesWorkflowSurface(path: string): boolean {
  return path.startsWith('.github/') || /(^|\/)action\.ya?ml$/.test(path);
}

/**
 * 0103: approvals for `c` carried forward from an earlier reviewed commit, or undefined. Needs
 * an approval for EVERY finding id at one common commit, from which `c.sha` is strictly ahead,
 * with a complete file list that touches no workflow surface. The skeptic tier is kept. A
 * GitHubRateLimitError propagates (the caller stops the run).
 */
async function carryApprovals(
  client: GitHubClient,
  config: CrawlConfig,
  c: SubmitCandidate,
): Promise<Approval[] | undefined> {
  const mine = config.approved.filter((a) => a.repo === c.repo && a.sha !== c.sha);
  const shas = [...new Set(mine.map((a) => a.sha))]
    .filter((sha) =>
      c.findingIds.every((id) => mine.some((a) => a.sha === sha && a.findingId === id)),
    )
    .sort()
    .slice(0, MAX_CARRY_TRIES);
  for (const sha of shas) {
    const r = await client.get(`/repos/${c.repo}/compare/${sha}...${c.sha}`);
    if (isRateLimit(r.status)) throw new GitHubRateLimitError('compare rate limited', r.status);
    const cmp = r.json;
    if (r.status !== 200 || !isObj(cmp) || cmp.status !== 'ahead' || !Array.isArray(cmp.files)) {
      continue;
    }
    const files = cmp.files as unknown[];
    if (files.length >= COMPARE_FILE_CAP) continue;
    const paths = files.flatMap((f) =>
      isObj(f) ? [f.filename, f.previous_filename].filter((p) => typeof p === 'string') : [null],
    );
    if (paths.some((p) => typeof p !== 'string' || touchesWorkflowSurface(p))) continue;
    return c.findingIds.map((id) => {
      const a = mine.find((x) => x.sha === sha && x.findingId === id) as Approval;
      return { ...a, sha: c.sha };
    });
  }
  return undefined;
}

/**
 * Whether a repo's PVR request issue can be closed out (0105), and with which text: `filed` once
 * a report went out, `resolved` once every disclosure was resolved before reporting. Anything
 * still in flight (queued, submitting, or a retryable hold) or held for good means: leave it.
 */
function closeOutKind(ledger: Ledger, repo: string): 'filed' | 'resolved' | undefined {
  const mine = ledger.disclosures.filter((d) => d.repo === repo);
  if (mine.some((d) => d.reportUrl !== undefined)) {
    const pending = mine.some(
      (d) =>
        d.state === 'queued' ||
        d.state === 'submitting' ||
        (d.state === 'held' && isRetryableHold(d)),
    );
    return pending ? undefined : 'filed';
  }
  return mine.length > 0 && mine.every((d) => d.state === 'resolved-before-report')
    ? 'resolved'
    : undefined;
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
  let ownerReplies = 0;
  let carriedCount = 0;

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
    const input = { repo: c.repo, sha: c.sha, archetype: c.archetype, findingIds: c.findingIds };
    let decision = gate(input, config, others);
    // 0103: HEAD moved since the review. If nothing that can change a workflow's behaviour
    // changed in between, the approval at the reviewed commit still stands for this one.
    if (decision.decision === 'held' && decision.reason === REASON_NOT_APPROVED) {
      let carried: Approval[] | undefined;
      try {
        carried = await carryApprovals(client, config, c);
      } catch (e) {
        if (!(e instanceof GitHubRateLimitError)) throw e;
        stoppedReason = `GitHub rate limit (HTTP ${e.status}) on approval carry-forward`;
        push(c.repo, 'stopped', stoppedReason);
        continue;
      }
      if (carried) {
        decision = gate(input, { ...config, approved: [...config.approved, ...carried] }, others);
        if (decision.decision === 'allowed') carriedCount++;
      }
    }
    if (decision.decision === 'held') {
      const reason = decision.reason ?? 'held by gate';
      hold(reason);
      push(c.repo, 'held', reason);
      continue;
    }

    // PVR pre-check.
    let pvrEnabled = false;
    // 0102: only a definite "PVR is off" (200, enabled: false) may lead to asking the owner;
    // a 401/403/404 says nothing about the repo and must never trigger a public issue.
    let pvrDefinitelyOff = false;
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
      pvrDefinitelyOff = pvr.status === 200 && body?.enabled === false;
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
    // 0104: read the request issue, if this repo was asked. Closed (or gone) while PVR is still
    // off means the owner declined; closed with PVR on means they did what we asked.
    const holder = ledger.disclosures.find((d) => d.repo === c.repo && d.pvrRequest?.url);
    if (holder?.pvrRequest) {
      let check: IssueCheck = { state: 'unknown', status: 0, replies: 0 };
      let limited: number | undefined;
      try {
        check = await checkRequestIssue(client, c.repo, holder.pvrRequest);
        if (isRateLimit(check.status)) limited = check.status;
      } catch (e) {
        if (e instanceof GitHubRateLimitError) limited = e.status;
        // Any other failure says nothing about the issue: carry on as if it were not checked.
      }
      if (limited !== undefined) {
        stoppedReason = `GitHub rate limit (HTTP ${limited}) on PVR request issue`;
        push(c.repo, 'stopped', stoppedReason);
        continue;
      }
      if (check.replies > 0) {
        ownerReplies += check.replies;
        apply(
          setPvrRequest(
            ledger,
            { repo: holder.repo, findingIds: holder.findingIds },
            { ...holder.pvrRequest, repliesSeenAt: check.repliesSeenAt as string },
            iso(),
          ),
        );
      }
      if (!pvrEnabled && (check.state === 'closed' || check.state === 'gone')) {
        const reason =
          check.state === 'closed' ? REASON_REQUEST_DECLINED : reasonRequestGone(check.status);
        hold(reason);
        push(c.repo, 'held', reason);
        continue;
      }
    }
    if (!pvrEnabled) {
      const asked = ledger.disclosures.some((d) => d.repo === c.repo && d.pvrRequest);
      if (!pvrDefinitelyOff || asked || decision.dryRun) {
        const reason = asked ? REASON_NO_PVR_REQUESTED : noPvrReason;
        hold(reason);
        push(
          c.repo,
          'held',
          decision.dryRun && !asked ? `${reason} (dry run: would ask owner)` : reason,
        );
        continue;
      }
      // Ask once, publicly, with no details (0102). Recorded BEFORE the POST: a crash can never
      // post a second issue, and any outcome (even a refusal) means this repo is never asked again.
      const at = iso();
      apply(setPvrRequest(ledger, key, { at }, at));
      await persist(ledger);
      dirty = false;
      let status = 0;
      let url: unknown;
      try {
        const r = await client.post(`/repos/${c.repo}/issues`, pvrEnableRequest());
        status = r.status;
        url = (r.json as { html_url?: unknown } | null)?.html_url;
      } catch (e) {
        status = e instanceof GitHubRateLimitError ? e.status : 0;
      }
      if (status === 201 && typeof url === 'string') {
        apply(setPvrRequest(ledger, key, { at, url }, iso()));
        hold(REASON_NO_PVR_REQUESTED);
        push(c.repo, 'requested');
      } else {
        apply(setPvrRequest(ledger, key, { at, failedStatus: status }, iso()));
        const reason = reasonPvrRequestFailed(status);
        hold(reason);
        push(c.repo, 'held', reason);
        if (isRateLimit(status))
          stoppedReason = `GitHub rate limit (HTTP ${status}) on PVR request`;
      }
      await persist(ledger);
      dirty = false;
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

  // 0105: close out request issues whose repo has nothing left pending.
  if (config.submitMode && !opts.killSwitch) {
    const holders = ledger.disclosures.filter(
      (d) => d.pvrRequest?.url !== undefined && d.pvrRequest.closedOutAt === undefined,
    );
    for (const cur of holders) {
      if (stoppedReason !== undefined) break;
      const req = cur.pvrRequest as PvrRequest & { url: string };
      const kind = closeOutKind(ledger, cur.repo);
      if (kind === undefined) continue;
      const used = budgetUsed(ledger, opts.now().getTime());
      if (used.hour >= config.throttle.perHour || used.day >= config.throttle.perDay) continue;
      const n = ISSUE_URL.exec(req.url)?.[1];
      if (n === undefined) continue;
      const key: DisclosureKey = { repo: cur.repo, findingIds: cur.findingIds };
      try {
        const issue = await client.get(`/repos/${cur.repo}/issues/${n}`);
        if (isRateLimit(issue.status)) {
          stoppedReason = `GitHub rate limit (HTTP ${issue.status}) on PVR request issue`;
          break;
        }
        // Only an issue we can see is still open gets a comment; one the owner closed is left be.
        if (issue.status !== 200 || !isObj(issue.json) || issue.json.state !== 'open') {
          if (isObj(issue.json) && issue.json.state === 'closed') {
            apply(setPvrRequest(ledger, key, { ...req, closedOutAt: iso() }, iso()));
          }
          continue;
        }
      } catch (e) {
        if (e instanceof GitHubRateLimitError) {
          stoppedReason = `GitHub rate limit (HTTP ${e.status}) on PVR request issue`;
          break;
        }
        continue;
      }
      // Recorded before the comment, so a crash can never post it twice.
      const at = iso();
      apply(setPvrRequest(ledger, key, { ...req, closedOutAt: at }, at));
      await persist(ledger);
      dirty = false;
      let status = 0;
      try {
        status = (
          await client.post(`/repos/${cur.repo}/issues/${n}/comments`, {
            body: pvrCloseOutComment(kind),
          })
        ).status;
        if (status === 201) {
          status = (
            await client.patch(`/repos/${cur.repo}/issues/${n}`, {
              state: 'closed',
              state_reason: 'completed',
            })
          ).status;
          if (status === 200) status = 0;
        }
      } catch (e) {
        status = e instanceof GitHubRateLimitError ? e.status : -1;
      }
      if (status !== 0) {
        apply(
          setPvrRequest(
            ledger,
            key,
            { ...req, closedOutAt: at, closeOutFailedStatus: status },
            iso(),
          ),
        );
        if (isRateLimit(status)) stoppedReason = `GitHub rate limit (HTTP ${status}) on close-out`;
      }
      await persist(ledger);
      dirty = false;
    }
  }

  if (dirty) await persist(ledger);

  const counts: Record<string, number> = {};
  for (const o of outcomes) counts[o.outcome] = (counts[o.outcome] ?? 0) + 1;
  return {
    ledger,
    summary: {
      counts,
      ownerReplies,
      carried: carriedCount,
      ...(stoppedReason !== undefined ? { stoppedReason } : {}),
    },
    outcomes,
  };
}
