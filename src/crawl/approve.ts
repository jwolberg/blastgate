/**
 * `crawl approve` (0100): the only intended way to write approvals. It reads review packets and
 * adds an `approved` entry to the ops config for each finding of a packet that BOTH passed the
 * adversarial skeptic (`skeptic: could-not-refute`) AND Jay confirmed (`verdict: confirmed`).
 * Every confirmed packet it does not approve is reported with the reason. It only adds; it never
 * removes an approval. The config parser independently rejects any approval without the skeptic
 * pass, so a hand-pasted entry cannot skip the skeptic either.
 */

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type Approval, SKEPTIC_PASS, parseCrawlConfig } from './config';

export interface ApproveArgs {
  /** Directory of review packets from `crawl review`. */
  packets: string;
  /** The ops config.json to add approvals to. */
  config: string;
}

export interface ApproveResult {
  added: Approval[];
  skipped: Array<{ packet: string; reason: string }>;
}

const NOT_PACKETS = new Set(['README.md', 'SUMMARY.md']);

function front(md: string): Record<string, string> {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(md);
  const out: Record<string, string> = {};
  for (const [, k, v] of (m?.[1] ?? '').matchAll(/^(\w+): (.*)$/gm)) out[k as string] = v as string;
  return out;
}

/** The packet's closing approval block: the last ```json fence in the file. */
function approvalBlock(md: string): unknown {
  const blocks = [...md.matchAll(/^(`{3,})json\n([\s\S]*?)\n\1$/gm)];
  const last = blocks[blocks.length - 1]?.[2];
  return last === undefined ? undefined : JSON.parse(last);
}

export function runApprove(args: ApproveArgs, deps: { log: (l: string) => void }): ApproveResult {
  const text = readFileSync(args.config, 'utf8');
  const config = parseCrawlConfig(text); // validates before we touch anything
  const raw = JSON.parse(text) as Record<string, unknown>;
  const result: ApproveResult = { added: [], skipped: [] };
  const key = (a: { repo: string; sha: string; findingId: string }): string =>
    JSON.stringify([a.repo, a.sha, a.findingId]);
  const have = new Set(config.approved.map(key));

  const files = readdirSync(args.packets)
    .filter((f) => f.endsWith('.md') && !NOT_PACKETS.has(f))
    .sort();
  for (const file of files) {
    const md = readFileSync(join(args.packets, file), 'utf8');
    const fm = front(md);
    if (fm.verdict !== 'confirmed') continue;
    if (fm.skeptic !== SKEPTIC_PASS) {
      result.skipped.push({ packet: file, reason: `skeptic: ${fm.skeptic ?? 'missing'}` });
      continue;
    }
    let entries: unknown;
    try {
      entries = approvalBlock(md);
    } catch {
      entries = undefined;
    }
    const valid =
      Array.isArray(entries) &&
      entries.length > 0 &&
      entries.every(
        (e) =>
          typeof e === 'object' &&
          e !== null &&
          (e as Record<string, unknown>).repo === fm.repo &&
          (e as Record<string, unknown>).sha === fm.sha &&
          typeof (e as Record<string, unknown>).findingId === 'string',
      );
    if (!valid) {
      result.skipped.push({
        packet: file,
        reason: 'approval block does not match the packet repo and commit',
      });
      continue;
    }
    for (const e of entries as Array<{ repo: string; sha: string; findingId: string }>) {
      const a: Approval = {
        repo: e.repo,
        sha: e.sha,
        findingId: e.findingId,
        skeptic: SKEPTIC_PASS,
      };
      if (have.has(key(a))) continue;
      have.add(key(a));
      result.added.push(a);
    }
  }

  if (result.added.length > 0) {
    const next = JSON.stringify(
      { ...raw, approved: [...config.approved, ...result.added] },
      null,
      2,
    );
    parseCrawlConfig(next); // never write a config the crawler would reject
    writeFileSync(args.config, `${next}\n`);
  }
  for (const a of result.added) deps.log(`approve: ${a.repo}@${a.sha.slice(0, 7)} ${a.findingId}`);
  for (const s of result.skipped) deps.log(`approve: skipped ${s.packet} (${s.reason})`);
  deps.log(
    `approve: ${result.added.length} added, ${result.skipped.length} confirmed but not approved`,
  );
  return result;
}

/**
 * Between the two skeptic stages (0100): stage one (cheap model) may only remove fails, so every
 * packet it did not refute goes to stage two. Reset those to a blank skeptic slot first, so stage
 * two never reads stage one's reasoning and cannot simply agree with it. Refuted packets are kept
 * as they are. Verdicts, findings, source and the approval block are never touched.
 */
export function resetSkeptic(packets: string): { reset: string[]; kept: string[] } {
  const out = { reset: [] as string[], kept: [] as string[] };
  const files = readdirSync(packets)
    .filter((f) => f.endsWith('.md') && !NOT_PACKETS.has(f))
    .sort();
  for (const file of files) {
    const p = join(packets, file);
    const md = readFileSync(p, 'utf8');
    if (front(md).skeptic === 'refuted') {
      out.kept.push(file);
      continue;
    }
    const next = md
      .replace(/^skeptic: .*$/m, 'skeptic: pending')
      .replace(/(\n## Skeptic\n\n)[\s\S]*?(\n## Findings\n)/, '$1Not run yet.\n$2');
    writeFileSync(p, next);
    out.reset.push(file);
  }
  return out;
}
