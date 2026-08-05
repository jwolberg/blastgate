/**
 * Acknowledged-finding override (U14) — the auditable, per-finding way past the
 * gate (KTD12 / plan Open-Questions lean). A committed `.blastgate/acknowledged.json`
 * lists finding ids that a human has reviewed and accepted; a matching fail finding
 * is **downgraded to warn** (still reported, with the acknowledgement reason), never
 * silently dropped. There is deliberately no env kill switch — the only way past a
 * fail is to add its stable id to a file that shows up in the diff and git history.
 */

import type { Finding } from '../findings/finding';

export interface Acknowledgement {
  /** The stable `Finding.id` being accepted. */
  id: string;
  /** Why it was accepted (for the audit trail). */
  reason: string;
}

/** Parse `.blastgate/acknowledged.json` tolerantly — malformed input yields no acks. */
export function parseAcknowledgements(json: string | null | undefined): Acknowledgement[] {
  if (!json) {
    return [];
  }
  try {
    const data = JSON.parse(json) as { acknowledged?: unknown };
    const list = Array.isArray(data.acknowledged) ? data.acknowledged : [];
    const out: Acknowledgement[] = [];
    for (const item of list) {
      if (item && typeof item === 'object' && typeof (item as { id?: unknown }).id === 'string') {
        const record = item as { id: string; reason?: unknown };
        out.push({ id: record.id, reason: typeof record.reason === 'string' ? record.reason : '' });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Downgrade acknowledged fail findings to warn (recording the reason); leave the rest. */
export function applyAcknowledgements(findings: Finding[], acks: Acknowledgement[]): Finding[] {
  if (acks.length === 0) {
    return findings;
  }
  const reasonById = new Map(acks.map((a) => [a.id, a.reason]));
  return findings.map((f) =>
    f.tier === 'fail' && reasonById.has(f.id)
      ? { ...f, tier: 'warn' as const, acknowledged: reasonById.get(f.id) ?? '' }
      : f,
  );
}
