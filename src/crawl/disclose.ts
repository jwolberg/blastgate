/**
 * Disclosure gate and report composer (U4, KTD6 steps 1/3/5, KTD7). Pure: no I/O.
 *
 * The report goes to a stranger's private advisory channel under Jay's name, and nearly every
 * string in it is attacker-influenced (workflow paths, job and step names, secret names).
 * So every repo-sourced field is made inert at ONE boundary (`inertFinding`) before it reaches
 * the shared per-finding markdown block, and the payload is stripped (`withoutPayload`).
 */

import { markdownFinding } from '../cli/render';
import { type Finding, withoutPayload } from '../findings/finding';
import type { CrawlConfig } from './config';
import type { Ledger } from './ledger';

export const THREAT_MODEL_URL =
  'https://github.com/jwolberg/blastgate/blob/main/docs/threat-model.md';

// ---------------------------------------------------------------- gate

/** What the gate needs to know about one fail to be reported. */
export interface GateInput {
  repo: string;
  archetype: string;
  findingIds: readonly string[];
}

export interface GateDecision {
  decision: 'allowed' | 'held';
  /** True while `submitMode` is off: the report is recorded, never sent. */
  dryRun: boolean;
  reason?: string;
}

/**
 * Allowlist first (KTD6.1), then the once-per-finding rule (KTD6.5): ids already covered by any
 * disclosure on that repo other than `resolved-before-report` are never re-filed. This mirrors
 * the ledger's own `createDisclosure` guard, so an `allowed` decision will not be refused there.
 */
export function gate(input: GateInput, config: CrawlConfig, ledger: Ledger): GateDecision {
  const dryRun = !config.submitMode;
  // Tripwire (KTD6.2) wins over the allowlist: a maintainer-rejected archetype stays held.
  if (ledger.trippedArchetypes?.includes(input.archetype)) {
    return { decision: 'held', dryRun, reason: 'archetype tripped by a false-positive report' };
  }
  if (!config.allowlist.includes(input.archetype)) {
    return { decision: 'held', dryRun, reason: 'archetype not allowlisted' };
  }
  const ids = new Set(input.findingIds);
  const dup = ledger.disclosures.some(
    (d) =>
      d.repo === input.repo &&
      d.state !== 'resolved-before-report' &&
      d.findingIds.some((id) => ids.has(id)),
  );
  if (dup) return { decision: 'held', dryRun, reason: 'duplicate' };
  return { decision: 'allowed', dryRun };
}

// ---------------------------------------------------------------- neutralizing repo text

const CAPS = {
  repo: 140,
  pathNode: 200,
  label: 300,
  identity: 200,
  file: 200,
  reason: 1000,
  remediation: 1000,
  short: 80,
} as const;

/** Truncate by code point so a cap never splits a surrogate pair. */
function cap(s: string, max: number): string {
  const cps = [...s];
  return cps.length <= max ? s : `${cps.slice(0, max - 1).join('')}…`;
}

/* eslint-disable no-control-regex */
const INVISIBLE =
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\ufeff]/g;
/* eslint-enable no-control-regex */

/**
 * Make a repo-sourced string inert in GitHub markdown, in BOTH plain-text and code-span
 * positions (the shared block uses both, and we do not control which a field lands in):
 *  - whitespace runs collapse to one space; control, bidi and zero-width chars are removed;
 *  - backticks become `'` so a value can never close or open a code span;
 *  - `<`/`>` become look-alike angle quotes, `[`/`]` become parentheses, so no HTML, image,
 *    link or reference syntax can form;
 *  - `@` becomes a full-width at-sign (no mention, no email autolink), `#<digit>` a full-width
 *    number sign (no issue ref), `://` and `www.` are defanged (no bare-URL autolink);
 *  - `|` becomes a broken bar so it cannot split a table cell.
 * The value stays readable; it just cannot be clicked, rendered, or notify anyone.
 */
export function inert(s: string, max: number): string {
  const cleaned = s.replace(/\s+/g, ' ').replace(INVISIBLE, '').trim();
  return cap(cleaned, max)
    .replace(/`/g, "'")
    .replace(/</g, '‹')
    .replace(/>/g, '›')
    .replace(/\[/g, '(')
    .replace(/\]/g, ')')
    .replace(/@/g, '＠')
    .replace(/#(?=\d)/g, '＃')
    .replace(/:\/\//g, ':∕∕')
    .replace(/www\./gi, 'www․')
    .replace(/\|/g, '¦');
}

/** A copy of the finding, payload removed and every string field made inert and length-capped. */
function inertFinding(input: Finding): Finding {
  const f = withoutPayload(input);
  const out: Finding = {
    ...f,
    id: inert(f.id, CAPS.label),
    path: f.path.map((n) => inert(n, CAPS.pathNode)),
    pathNodeIds: f.pathNodeIds.map((n) => inert(n, CAPS.pathNode)),
    entry: { ...f.entry, label: inert(f.entry.label, CAPS.label) },
    sink: { ...f.sink, identity: inert(f.sink.identity, CAPS.identity) },
    reason: inert(f.reason, CAPS.reason),
    remediation: inert(f.remediation, CAPS.remediation),
    labels: f.labels.map((l) => inert(l, CAPS.short)),
  };
  if (f.acknowledged !== undefined) out.acknowledged = inert(f.acknowledged, CAPS.reason);
  if (f.advisories) {
    out.advisories = f.advisories.map((a) => ({
      id: inert(a.id, CAPS.short),
      package: inert(a.package, CAPS.identity),
      ...(a.summary !== undefined ? { summary: inert(a.summary, CAPS.label) } : {}),
    }));
  }
  if (f.evidence) {
    out.evidence = {
      file: inert(f.evidence.file, CAPS.file),
      line: Number.isFinite(f.evidence.line) ? Math.trunc(f.evidence.line) : 0,
      capability: inert(f.evidence.capability, CAPS.identity),
    };
  }
  return out;
}

// ---------------------------------------------------------------- report

export interface ReportInput {
  /** `owner/repo`. */
  repo: string;
  /** Full 40-char commit SHA the findings were produced at. */
  sha: string;
  findings: readonly Finding[];
  blastgateVersion: string;
}

export interface Report {
  /** PVR summary, hard-capped at 1024 chars. */
  summary: string;
  description: string;
}

export const SUMMARY_MAX = 1024;
/** PVR description limit (GitHub caps the body at 65,535 characters). */
export const DESCRIPTION_MAX = 65_535;

/** Start of every composed summary; the submit job requires it (see `index.ts` validation). */
export function reportSummaryPrefix(repo: string): string {
  return `Blastgate: reachable attacker-controlled path to a secret in ${inert(repo, CAPS.repo)}`;
}

/** The exact header composeReport puts first, for `n` findings. */
export function reportHeader(repo: string, n: number): string {
  return header(inert(repo, CAPS.repo), n);
}

/** The exact footer composeReport puts last. */
export function reportFooter(version: string, sha: string): string {
  return footer(version, sha);
}

function header(repo: string, n: number): string {
  return [
    '## Blastgate automated security report',
    '',
    `This is an automated report from Blastgate, a scanner for attacker-to-secret paths in CI workflows. It is limited to proven paths: Blastgate only reports a fail when it can trace a reachable path from attacker-controllable input to a secret or credential in \`${repo}\`.`,
    '',
    `${n} reachable path${n === 1 ? '' : 's'} found. Each lists where the input enters, what it reaches, why, and how to break the path. How the scanner decides what is reportable: ${THREAT_MODEL_URL}`,
    '',
    '**How to respond:** if this is accurate, breaking any edge on a path (the fix lines below) closes it. If it is wrong, or you accept the risk, reply here or close this report to decline; no further report will be filed for these findings.',
    '',
    '**Disclosure:** we suggest a 90-day coordinated-disclosure window from the date of this report. Blastgate does not publish this finding; any advisory is yours to publish.',
  ].join('\n');
}

function footer(version: string, sha: string): string {
  return `_Scanned by Blastgate ${inert(version, CAPS.short)} at commit \`${inert(sha, 64)}\`._`;
}

/** Hard 1024 cap, code-point safe. */
function capSummary(s: string): string {
  const cps = [...s];
  return cps.length <= SUMMARY_MAX ? s : cps.slice(0, SUMMARY_MAX).join('');
}

/**
 * Compose the PVR report. The description is a disclosure header, each finding via the shared
 * per-finding markdown block (payload stripped, repo text inert), then a version + SHA footer.
 */
export function composeReport(input: ReportInput): Report {
  const repo = inert(input.repo, CAPS.repo);
  const findings = input.findings.map(inertFinding);
  const first = findings[0];
  const where = first?.evidence ? ` at ${first.evidence.file}:${first.evidence.line}` : '';
  const sinkText = first ? ` reaches ${first.sink.identity}` : '';
  const more = findings.length > 1 ? ` (+${findings.length - 1} more)` : '';
  const summary = capSummary(`${reportSummaryPrefix(input.repo)}${sinkText}${where}${more}`);
  const blocks = findings.map((f) => markdownFinding(f).join('\n'));
  const description = [
    header(repo, findings.length),
    ...blocks,
    footer(input.blastgateVersion, input.sha),
  ].join('\n\n---\n\n');
  return { summary, description };
}
