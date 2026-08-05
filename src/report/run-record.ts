/**
 * Historical run record (0037, dashboard phase 0) — the stable, versioned per-run
 * output a dashboard consumes. This is the integration seam: the core tool stays
 * stateless and offline, and the dashboard is a downstream consumer of these
 * records (never coupled to engine internals). `blastgate . --record <dir>` writes
 * one; `blastgate report <dir>` renders a trend over a directory of them.
 *
 * Phase 2 (a hosted, multi-tenant collaboration service) is deliberately OUT of
 * scope and demand-gated: a service aggregating many orgs' attack paths is itself a
 * high-value target, so it is a separate product decision, not part of this tool.
 */

import type { Finding, Verdict } from '../findings/finding';
import type { GateResult } from '../engine/gate';

export const RUN_RECORD_SCHEMA_VERSION = 1 as const;

export interface RunRecord {
  schemaVersion: typeof RUN_RECORD_SCHEMA_VERSION;
  /** ISO timestamp the run was recorded. */
  timestamp: string;
  repo?: string;
  base?: string;
  sha?: string;
  verdict: Verdict;
  findingCount: number;
  failCount: number;
  warnCount: number;
  /** The full findings, for drill-in. */
  findings: Finding[];
}

export interface RunMeta {
  timestamp: string;
  repo?: string;
  base?: string;
  sha?: string;
}

/** Build a versioned run record from a gate result and run metadata (pure). */
export function toRunRecord(result: GateResult, meta: RunMeta): RunRecord {
  return {
    schemaVersion: RUN_RECORD_SCHEMA_VERSION,
    timestamp: meta.timestamp,
    ...(meta.repo ? { repo: meta.repo } : {}),
    ...(meta.base ? { base: meta.base } : {}),
    ...(meta.sha ? { sha: meta.sha } : {}),
    verdict: result.verdict,
    findingCount: result.findings.length,
    failCount: result.findings.filter((f) => f.tier === 'fail').length,
    warnCount: result.findings.filter((f) => f.tier === 'warn').length,
    findings: result.findings,
  };
}

/** Parse a set of run-record JSON blobs tolerantly, dropping malformed ones, sorted oldest→newest. */
export function parseRunRecords(jsons: string[]): RunRecord[] {
  const records: RunRecord[] = [];
  for (const json of jsons) {
    try {
      const r = JSON.parse(json) as RunRecord;
      if (r && typeof r.timestamp === 'string' && typeof r.verdict === 'string') {
        records.push(r);
      }
    } catch {
      /* skip a malformed record — the report is best-effort over a directory */
    }
  }
  return records.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}
