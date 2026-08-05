/**
 * Provenance-regression analyzer (U8, opt-in/network-gated per KTD6).
 *
 * For each dependency whose version changed between the base and head lockfiles,
 * compare npm provenance (`dist.attestations` presence) at the two versions. A
 * package that *had* attestations and *lost* them is a strong supply-chain
 * compromise signal (the CVE-2025-54313 shape) — emitted as an attacker-
 * controllable supply-chain `EntryNode` (like a new dependency) so the engine
 * ranks it if it reaches a sink. Absence at both versions is not a regression, and
 * a fetch failure is soft (no finding). Newly added packages have no prior version
 * to regress from.
 */

import type { AttackNode } from '../../graph/types';
import type { ProvenanceFetcher } from '../../registry/packument';
import { type AnalyzerResult, emptyResult } from '../types';
import { packageName, parsePackagesMap } from './lockfile';

export async function analyzeProvenance(
  baseLockfile: string | null | undefined,
  headLockfile: string,
  fetcher: ProvenanceFetcher,
): Promise<AnalyzerResult> {
  const result = emptyResult();
  if (!baseLockfile) {
    return result; // no baseline ⇒ nothing to regress from, and no network call
  }

  let base: Record<string, { version?: string }>;
  let head: Record<string, { version?: string }>;
  try {
    base = parsePackagesMap(baseLockfile);
    head = parsePackagesMap(headLockfile);
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `provenance: failed to parse a lockfile: ${(err as Error).message}`,
    });
    return result;
  }

  for (const [path, headEntry] of Object.entries(head)) {
    if (path === '') {
      continue;
    }
    const baseEntry = base[path];
    const baseVersion = baseEntry?.version;
    const headVersion = headEntry.version;
    if (!baseVersion || !headVersion || baseVersion === headVersion) {
      continue; // only version *changes* can regress
    }

    const pkg = packageName(path);
    const baseProv = await fetcher.hasProvenance(pkg, baseVersion);
    const headProv = await fetcher.hasProvenance(pkg, headVersion);
    if (baseProv !== true || headProv !== false) {
      continue; // regression only when it HAD attestations and now does NOT
    }

    const entryId = `entry:provenance:${pkg}`;
    const depId = `dep:${pkg}@${headVersion}`;
    const entry: AttackNode = {
      id: entryId,
      kind: 'entry',
      entryKind: 'new-dependency',
      exposure: 2,
      label: `provenance regression: ${pkg} lost npm attestations (${baseVersion} → ${headVersion})`,
    };
    result.nodes.push(entry);
    result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
    result.diagnostics.push({
      level: 'warn',
      message:
        `provenance regression: ${pkg} had npm attestations at ${baseVersion} but not at ` +
        `${headVersion} — a strong supply-chain compromise signal (cf. CVE-2025-54313).`,
    });
  }

  return result;
}
