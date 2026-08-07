/**
 * yarn / pnpm install layer analyzer (0040, offline).
 *
 * Repos using yarn or pnpm carry no `package-lock.json`, so they got *zero*
 * dependency-layer analysis — invisible to the flagship cross-layer supply-chain
 * path. This analyzer parses `yarn.lock` / `pnpm-lock.yaml` into the same
 * `DependencyNode` shape the npm path emits, so the engine's `runs-in → job →
 * secret` synthesis (U7) works unchanged.
 *
 * Neither lockfile records npm's `hasInstallScript` flag, so — exactly like the
 * RubyGems analyzer — install execution cannot be ruled out offline and an
 * added/bumped dep is treated as install-capable (`hasInstallScript: true`).
 * Precision comes from reachability, not per-package script detection: the finding
 * only forms when the untrusted change adds/bumps the dep AND it is installed by a
 * fork-triggerable CI job that holds a secret. Attacker-controllability is
 * diff-gated — an existing lockfile is the maintainer's trusted state, so whole-repo
 * mode (no base ref) emits nothing.
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import { parsePnpmLock } from './pnpm-lock';
import { parseYarnLock } from './yarn-lock';

export type JsLockFormat = 'yarn' | 'pnpm';

export interface JsDepsInputs {
  /** Which lockfile format `headLockfile` / `baseLockfile` hold. */
  format: JsLockFormat;
  /** yarn.lock / pnpm-lock.yaml contents at head (required). */
  headLockfile: string;
  /** Lockfile at the base ref, or null when new at head; undefined = no diff (whole-repo). */
  baseLockfile?: string | null;
}

function parseFor(format: JsLockFormat, content: string): Map<string, string> {
  return format === 'yarn' ? parseYarnLock(content) : parsePnpmLock(content);
}

export function analyzeJsDeps(inputs: JsDepsInputs): AnalyzerResult {
  const result = emptyResult();
  // Whole-repo mode (no base): the committed lockfile is trusted maintainer state;
  // only a diff that adds/bumps a dep is attacker-controllable (RubyGems parity).
  if (inputs.baseLockfile === undefined) {
    return result;
  }

  let head: Map<string, string>;
  let base: Map<string, string>;
  try {
    head = parseFor(inputs.format, inputs.headLockfile);
    base = inputs.baseLockfile
      ? parseFor(inputs.format, inputs.baseLockfile)
      : new Map<string, string>();
  } catch (err) {
    // Fail closed (0020): an unparseable lockfile becomes an error diagnostic → UNKNOWN.
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse ${inputs.format} lockfile: ${(err as Error).message}`,
    });
    return result;
  }

  for (const [pkg, version] of head) {
    if (base.get(pkg) === version) {
      continue; // unchanged, trusted
    }
    const change = base.has(pkg) ? 'changed' : 'added';
    const depId = `dep:${pkg}@${version}`;
    result.nodes.push({
      id: depId,
      kind: 'dependency',
      pkg,
      version,
      isDirect: true,
      hasInstallScript: true,
      ecosystem: 'npm',
    } as AttackNode);

    const entryId = `entry:new-dep:${pkg}`;
    result.nodes.push({
      id: entryId,
      kind: 'entry',
      entryKind: 'new-dependency',
      exposure: 1,
      label: `${change} dependency ${pkg}@${version} (${inputs.format} lockfile; install-time execution)`,
    });
    result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
  }

  return result;
}
