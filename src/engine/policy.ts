/**
 * Exception policy (0030) — the typed, auditable generalization of the
 * acknowledged.json override (U14 / KTD12). A committed `.blastgate/policy.json`
 * lists accept rules that downgrade a matching fail finding to a reported warn.
 *
 * It preserves the three invariants that keep the gate honest:
 * - **committed & diffable** — it is a file in the repo, visible in the diff and
 *   git history; there is no env kill switch.
 * - **specific** — a rule must name a concrete target (an exact finding `id` or a
 *   specific `sink` identity). Blanket/wildcard rules (`sink: "*"`, archetype-only,
 *   no reason) are rejected at parse time with a diagnostic — you cannot `allow *`.
 * - **self-approval-guarded** — the base-vs-head guard (0019, applied by the
 *   collector) means a rule introduced by the same change is ignored, so a PR
 *   cannot self-approve its own finding.
 *
 * The legacy `acknowledged.json` (id-only acks) still works — policy is a superset.
 */

import type { Diagnostic } from '../analyzers/types';
import type { EntryKind } from '../graph/types';
import type { Finding } from '../findings/finding';

/**
 * A reviewed exception: downgrade (fail→warn) any finding matching ALL of its
 * present selectors. At least one of `id` / `sink` must be concrete (the specificity
 * invariant); `archetype` only narrows and is never sufficient alone.
 */
export interface AcceptRule {
  /** Exact finding id (`<entry.id>=><sink.id>`) — back-compat with acknowledged.json. */
  id?: string;
  /** Exact sink identity, e.g. `AWS_SECRET_ACCESS_KEY`. */
  sink?: string;
  /** Narrow to a finding archetype (entry kind), e.g. `fork-pr`. Never sufficient alone. */
  archetype?: EntryKind;
  /** Why it was accepted — required for the audit trail. */
  reason: string;
  /** Optional review-by date (`YYYY-MM-DD`); the rule stops applying strictly after it. */
  expires?: string;
}

export interface PolicyParseResult {
  rules: AcceptRule[];
  /** Parse-time rejections (blanket/wildcard/no-reason rules), surfaced not silently dropped. */
  diagnostics: Diagnostic[];
}

/** A wildcard/glob character is never a "specific target". */
const WILDCARD = /[*?]/;

/** A concrete selector value: a non-empty string with no wildcard. */
function isConcrete(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0 && !WILDCARD.test(v);
}

/**
 * Parse `.blastgate/policy.json` (`{ "accept": [ rule, ... ] }`) tolerantly. Malformed
 * input yields no rules (never fails open). Each rule is validated for specificity and
 * a reason; a rejected rule produces a diagnostic rather than being silently ignored.
 */
export function parsePolicy(json: string | null | undefined): PolicyParseResult {
  const out: PolicyParseResult = { rules: [], diagnostics: [] };
  if (!json) {
    return out;
  }
  let data: { accept?: unknown };
  try {
    data = JSON.parse(json) as { accept?: unknown };
  } catch {
    return out;
  }
  const list = Array.isArray(data.accept) ? data.accept : [];
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') {
      continue;
    }
    const item = raw as Record<string, unknown>;
    const id = typeof item.id === 'string' ? item.id : undefined;
    const sink = typeof item.sink === 'string' ? item.sink : undefined;
    const archetype =
      typeof item.archetype === 'string' ? (item.archetype as EntryKind) : undefined;
    const expires = typeof item.expires === 'string' ? item.expires : undefined;
    const reason = typeof item.reason === 'string' ? item.reason.trim() : '';

    const label = id ?? sink ?? archetype ?? '(rule)';
    if (reason.length === 0) {
      out.diagnostics.push({
        level: 'warn',
        message: `policy rule "${label}" has no reason — every accepted exception needs an audit reason; ignored`,
      });
      continue;
    }
    // Specificity: must name a concrete id or sink. archetype-only / wildcard / empty
    // is a blanket rule — the exact thing the gate refuses to allow.
    if (!isConcrete(id) && !isConcrete(sink)) {
      out.diagnostics.push({
        level: 'warn',
        message:
          `policy rule "${label}" names no specific target — a rule must set a concrete ` +
          `finding id or sink identity (no wildcards, no archetype-only blanket); ignored`,
      });
      continue;
    }
    const rule: AcceptRule = { reason };
    if (id !== undefined) rule.id = id;
    if (sink !== undefined) rule.sink = sink;
    if (archetype !== undefined) rule.archetype = archetype;
    if (expires !== undefined) rule.expires = expires;
    out.rules.push(rule);
  }
  return out;
}

/** Identity for the 0019 base-vs-head guard: selectors + expiry, ignoring the reason. */
export function ruleKey(rule: AcceptRule): string {
  return JSON.stringify([rule.id ?? '', rule.sink ?? '', rule.archetype ?? '', rule.expires ?? '']);
}

/** True if `rule` has a review-by date strictly before `now` (both compared as YYYY-MM-DD). */
function isExpired(rule: AcceptRule, now: string | undefined): boolean {
  if (!rule.expires || !now) {
    return false;
  }
  return now.slice(0, 10) > rule.expires.slice(0, 10);
}

/** All present selectors match the finding (and the rule is not expired). */
function matches(rule: AcceptRule, f: Finding, now: string | undefined): boolean {
  if (isExpired(rule, now)) {
    return false;
  }
  if (rule.id !== undefined && rule.id !== f.id) {
    return false;
  }
  if (rule.sink !== undefined && rule.sink !== f.sink.identity) {
    return false;
  }
  if (rule.archetype !== undefined && rule.archetype !== f.entry.kind) {
    return false;
  }
  return true;
}

export interface PolicyOptions {
  /** Reference date (`YYYY-MM-DD` or ISO) for expiry; absent = expiry not enforced. */
  now?: string;
}

/**
 * Downgrade fail findings accepted by a policy rule to warn (recording the reason);
 * leave the rest. Same downgrade shape as `applyAcknowledgements`, so an accepted
 * finding is still reported — never silently dropped.
 */
export function applyPolicy(
  findings: Finding[],
  rules: AcceptRule[],
  opts: PolicyOptions,
): Finding[] {
  if (rules.length === 0) {
    return findings;
  }
  return findings.map((f) => {
    if (f.tier !== 'fail') {
      return f;
    }
    const hit = rules.find((r) => matches(r, f, opts.now));
    return hit ? { ...f, tier: 'warn' as const, acknowledged: hit.reason } : f;
  });
}
