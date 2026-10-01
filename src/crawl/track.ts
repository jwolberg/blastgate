/**
 * Advisory tracker (U6, R9, KTD6.2). For every `submitted` (and still-uncredited `fixed`)
 * disclosure, read the private repository advisory and move the ledger forward.
 *
 * API: GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}
 * https://docs.github.com/en/rest/security-advisories/repository-advisories
 * Fields used: `state` (draft | triage | published | closed | withdrawn), `credits`
 * ([{login, type}]) and `credits_detailed` ([{user: {login}, type, state:
 * accepted | declined | pending}]). The API has NO close-reason field.
 *
 * Tripwire decision: because the API cannot say WHY an advisory was closed, a
 * "false positive" cannot be told apart from "fixed quietly" or "not a vulnerability by
 * policy". The safe, deterministic rule is therefore: a `submitted` disclosure whose advisory
 * is `closed` or `withdrawn` becomes `declined` AND trips its archetype (back to held, even if
 * allowlisted). Over-tripping costs a slower rollout; under-tripping files more reports a
 * stranger already rejected. Jay re-admits an archetype by editing the ledger by hand.
 */

import type { GitHubClient } from './github';
import { type Disclosure, type Ledger, tripArchetype, transition } from './ledger';

export interface TrackOptions {
  ledger: Ledger;
  client: GitHubClient;
  /** Login the reports were filed as; a published credit for this login means "credited". */
  reporterLogin: string;
  /** ISO timestamp. */
  now: string;
  /** Finding ids still failing in the latest scan, per repo. A repo absent here was not rescanned. */
  currentFails?: ReadonlyMap<string, ReadonlySet<string>>;
}

export interface TrackResult {
  ledger: Ledger;
  /** Human-readable run-summary lines for disclosures that need a look (404, HTTP error, bad URL). */
  flagged: string[];
}

const ADVISORY_URL =
  /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)\/security\/advisories\/(GHSA(?:-[a-z0-9]{4}){3})$/;

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function hasCredit(adv: Record<string, unknown>, login: string): boolean {
  const want = login.toLowerCase();
  const same = (v: unknown): boolean => typeof v === 'string' && v.toLowerCase() === want;
  const detailed = Array.isArray(adv.credits_detailed) ? adv.credits_detailed : [];
  for (const c of detailed) {
    if (isObj(c) && isObj(c.user) && same(c.user.login) && c.state !== 'declined') return true;
  }
  const plain = Array.isArray(adv.credits) ? adv.credits : [];
  return plain.some((c) => isObj(c) && same(c.login));
}

export async function trackAll(opts: TrackOptions): Promise<TrackResult> {
  const { client, reporterLogin, now, currentFails } = opts;
  let ledger = opts.ledger;
  const flagged: string[] = [];

  // Snapshot: iterate the input list; each disclosure is updated by key.
  const targets = opts.ledger.disclosures.filter(
    (d) => d.state === 'submitted' || d.state === 'fixed',
  );
  for (const d of targets) {
    const key = { repo: d.repo, findingIds: d.findingIds };
    const m = d.reportUrl ? ADVISORY_URL.exec(d.reportUrl) : null;
    if (!m) {
      flagged.push(`${d.repo}: reportUrl is not a repository advisory URL`);
      continue;
    }
    const [, owner, name, ghsaId] = m;
    const res = await client.get(`/repos/${owner}/${name}/security-advisories/${ghsaId}`);
    if (res.status !== 200 || !isObj(res.json)) {
      flagged.push(`${d.repo}: advisory ${ghsaId} lookup failed (HTTP ${res.status})`);
      continue;
    }
    const adv = res.json;
    const state = adv.state;

    if (state === 'published') {
      if (hasCredit(adv, reporterLogin)) {
        ledger = transition(ledger, key, 'published-credited', { now, ghsaId });
      } else if (d.state === 'submitted') {
        ledger = transition(ledger, key, 'fixed', { now });
      }
    } else if (d.state === 'submitted') {
      if (state === 'closed' || state === 'withdrawn') {
        ledger = transition(ledger, key, 'declined', { now, reason: `advisory ${state}` });
        ledger = tripArchetype(ledger, d.archetype, now);
      } else if (stoppedFailing(d, currentFails)) {
        ledger = transition(ledger, key, 'fixed', { now });
      }
    }
  }
  return { ledger, flagged };
}

/** True only when the repo was rescanned and none of the disclosure's finding ids still fail. */
function stoppedFailing(
  d: Disclosure,
  currentFails: ReadonlyMap<string, ReadonlySet<string>> | undefined,
): boolean {
  const now = currentFails?.get(d.repo);
  return now !== undefined && !d.findingIds.some((id) => now.has(id));
}
