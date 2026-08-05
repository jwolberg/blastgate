/**
 * CVE / advisory enrichment (0036) — the design-tension feature, scoped to keep the
 * moat intact: **enrichment, not gating.**
 *
 * Blastgate fails only on a reachable path. This pass runs AFTER findings are
 * assembled and only decorates an existing finding with known-vulnerability
 * advisories (OSV / GHSA / CVE) for the dependency on its path, bumping its rank so
 * a reachable-AND-known-vulnerable dependency surfaces first. It NEVER turns a pass
 * into a fail, never changes a tier, and a CVE on a dependency that is not on any
 * reachable path produces nothing (there is no finding to decorate). It is opt-in
 * (`--advisories`) and the only network touch besides `--provenance`; the core scan
 * is offline. The `AdvisorySource` port keeps it offline-testable.
 */

import type { Advisory, Finding } from '../findings/finding';

/** OSV ecosystem name (osv.dev's canonical spelling). */
type OsvEcosystem = 'npm' | 'RubyGems' | 'PyPI';

export interface DepRef {
  ecosystem: OsvEcosystem;
  name: string;
  version?: string;
}

/** A source of advisories for a package (osv.dev in production; a stub in tests). */
export interface AdvisorySource {
  query(name: string, ecosystem: OsvEcosystem, version?: string): Promise<Advisory[]>;
}

/** How much an advisory raises a finding's rank. Ranking only — never a tier change. */
const ADVISORY_SCORE_BUMP = 50;

/**
 * Parse a dependency graph-node id into an OSV package ref. Returns null for a node
 * that is not a named third-party package (a sink, an entry, or `setup.py` install
 * code that has no package name to look up).
 */
export function depFromNodeId(id: string): DepRef | null {
  let m: RegExpExecArray | null;
  if ((m = /^dep:ruby:(.+)@(.+)$/.exec(id))) {
    return { ecosystem: 'RubyGems', name: m[1]!, version: m[2]! };
  }
  if ((m = /^dep:python:pkg:(.+)$/.exec(id))) {
    return { ecosystem: 'PyPI', name: m[1]! };
  }
  if (/^dep:python:/.test(id)) {
    return null; // setup.py-style install code — no package name to query
  }
  if ((m = /^dep:(.+)@(.+)$/.exec(id))) {
    return { ecosystem: 'npm', name: m[1]!, version: m[2]! };
  }
  return null;
}

/** The first named dependency on a finding's path, if any. */
function dependencyOnPath(f: Finding): DepRef | null {
  for (const id of f.pathNodeIds) {
    const dep = depFromNodeId(id);
    if (dep) {
      return dep;
    }
  }
  return null;
}

/**
 * Decorate findings with advisories for the dependency on their path, then re-rank.
 * Purely additive: a finding's tier is never touched, so the whole-run verdict is
 * unchanged. Source errors are swallowed per-finding (enrichment must never break a
 * scan). Findings without a dependency, or whose dependency has no advisory, pass
 * through unchanged.
 */
export async function enrichWithAdvisories(
  findings: Finding[],
  source: AdvisorySource,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const f of findings) {
    const dep = dependencyOnPath(f);
    if (!dep) {
      out.push(f);
      continue;
    }
    let advisories: Advisory[] = [];
    try {
      advisories = await source.query(dep.name, dep.ecosystem, dep.version);
    } catch {
      advisories = []; // enrichment is best-effort; a source failure never breaks the scan
    }
    out.push(
      advisories.length > 0
        ? { ...f, advisories, score: f.score + ADVISORY_SCORE_BUMP * advisories.length }
        : f,
    );
  }
  // Re-rank: a reachable-and-known-vulnerable finding should sort first.
  return out.sort((a, b) => b.score - a.score);
}
