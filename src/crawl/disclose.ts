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
import { type CrawlConfig, SKEPTIC_PASS } from './config';
import {
  REASON_NOT_ALLOWLISTED,
  REASON_NOT_APPROVED,
  REASON_POSSIBLE_PAUSED,
  type Ledger,
} from './ledger';

export const THREAT_MODEL_URL =
  'https://github.com/jwolberg/blastgate/blob/main/docs/threat-model.md';

// ---------------------------------------------------------------- gate

/** What the gate needs to know about one fail to be reported. */
export interface GateInput {
  repo: string;
  /** Full sha of the commit the report names; approvals are pinned to it (0092). */
  sha: string;
  archetype: string;
  findingIds: readonly string[];
}

/** Report tier (0101): the skeptic could not refute it, or could not settle it either way. */
export type ReportTier = 'vulnerability' | 'possible';

export interface GateDecision {
  decision: 'allowed' | 'held';
  /** Set when allowed: which report to send. */
  tier?: ReportTier;
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
    return { decision: 'held', dryRun, reason: REASON_NOT_ALLOWLISTED };
  }
  // Per-fail approval (0092): every finding, this repo, this exact commit. A moved HEAD means a
  // new sha and so no approval: the fail is held until it is re-checked.
  const approvals = input.findingIds.map((id) =>
    config.approved.find((a) => a.repo === input.repo && a.sha === input.sha && a.findingId === id),
  );
  if (input.findingIds.length === 0 || approvals.some((a) => a === undefined)) {
    return { decision: 'held', dryRun, reason: REASON_NOT_APPROVED };
  }
  // Tier (0101): one finding the skeptic only doubted makes the whole report "possible".
  const tier: ReportTier = approvals.every((a) => a?.skeptic === SKEPTIC_PASS)
    ? 'vulnerability'
    : 'possible';
  if (tier === 'possible' && !config.sendPossible) {
    return { decision: 'held', dryRun, reason: REASON_POSSIBLE_PAUSED };
  }
  const ids = new Set(input.findingIds);
  const dup = ledger.disclosures.some(
    (d) =>
      d.repo === input.repo &&
      d.state !== 'resolved-before-report' &&
      d.findingIds.some((id) => ids.has(id)),
  );
  if (dup) return { decision: 'held', dryRun, reason: 'duplicate' };
  return { decision: 'allowed', dryRun, tier };
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

// ---------------------------------------------------------------- report tier (0101)

export interface TieredReport extends Report {
  severity: 'high' | 'medium';
}

/**
 * Re-head a composed report for its tier at send time. The scan job composes the findings; the
 * skeptic's result, known only once approved, decides how confidently the report speaks. Only the
 * summary prefix and the header change: every finding block and the commit footer are kept.
 */
export function tierReport(report: Report, tier: ReportTier, repoName: string): TieredReport {
  const cut = report.description.indexOf('\n\n---\n\n');
  const rest = cut === -1 ? '' : report.description.slice(cut);
  const repo = inert(repoName, CAPS.repo);
  const n = (rest.match(/\n\n---\n\n### /g) ?? []).length;
  const paths = `${n} path${n === 1 ? '' : 's'}`;
  const at = report.summary.indexOf(' reaches ');
  const detail = `attacker-controlled input ${at === -1 ? 'reaches a secret' : report.summary.slice(at + 1)}`;
  const label =
    tier === 'vulnerability' ? 'Security vulnerability' : 'Possible security vulnerability';
  const lead =
    tier === 'vulnerability'
      ? [
          `Blastgate, an automated scanner for CI workflows, found ${paths} in \`${repo}\` from attacker-controllable input to a secret or credential that we believe an outside attacker can use today. Before filing, an independent review tried to disprove each one against your workflow source and could not disprove it.`,
          '',
          `Each path below lists where the input enters, what it reaches, why, and how to break it. How the scanner decides what is reportable: ${THREAT_MODEL_URL}`,
          '',
          '**What we recommend:** fix it by breaking any edge on each path (the fix lines below). If the workflow has already run on untrusted input, rotate the named secret. If this is wrong, or you accept the risk, reply here or close this report; no further report will be filed for these findings.',
        ]
      : [
          `Blastgate, an automated scanner for CI workflows, found ${paths} in \`${repo}\` that may let an outside attacker reach a secret or credential. An independent review checked each one against your workflow source and could not rule it out, but could not confirm every step either: some steps depend on things only you can see, such as repository or environment settings, or another workflow.`,
          '',
          `Each path below lists where the input enters, what it reaches, why, and how to break it. How the scanner decides what is reportable: ${THREAT_MODEL_URL}`,
          '',
          '**Please investigate:** check each path below against your settings. If it holds, break any edge on it (the fix lines below). If it does not apply, close this report; no further report will be filed for these findings.',
        ];
  const head = [
    `## ${label} in \`${repo}\` (automated report)`,
    '',
    ...lead,
    '',
    '**Disclosure:** we suggest a 90-day coordinated-disclosure window from the date of this report. Blastgate does not publish this finding; any advisory is yours to publish.',
  ].join('\n');
  return {
    summary: capSummary(`${label} in ${repo}: ${detail}`),
    description: `${head}${rest}`,
    severity: tier === 'vulnerability' ? 'high' : 'medium',
  };
}

// ---------------------------------------------------------------- PVR enable request (0102)

export const PVR_DOCS_URL =
  'https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository';

/**
 * The public issue asking an owner to turn on private vulnerability reporting. It is fixed text:
 * nothing from the repo or the finding (no workflow, secret, file, tier) so nothing about the
 * vulnerability becomes public before the owner can see it privately.
 */
export function pvrEnableRequest(): { title: string; body: string } {
  return {
    title: 'Please enable private vulnerability reporting',
    body: [
      `Hi! An automated scan of this repository by [Blastgate](https://github.com/jwolberg/blastgate) found what looks like a security vulnerability. I would like to share the details privately rather than in a public issue.`,
      '',
      `Could you enable **private vulnerability reporting** for this repository? It is under Settings, in the Security section. GitHub's guide: ${PVR_DOCS_URL}`,
      '',
      'Once it is on, the details will be filed as a private report that only maintainers can see. Nothing about the issue will be posted here.',
      '',
      'If you would prefer to be contacted another way, reply here with how. If you do not want to hear about it, close this issue; no other public issue will be opened.',
    ].join('\n'),
  };
}
