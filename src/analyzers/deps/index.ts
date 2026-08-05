import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import { diffLockfiles } from './diff';
import { parseLockfile } from './lockfile';
import { diffNpmrc } from './npmrc';

export interface DependencyInputs {
  /** package-lock.json contents at head (required). */
  headLockfile: string;
  /** package-lock.json at the base ref, or null in whole-repo mode; undefined = no diff. */
  baseLockfile?: string | null;
  /** .npmrc contents at head, if present. */
  npmrc?: string | null;
  /** .npmrc contents at the base ref. */
  baseNpmrc?: string | null;
}

/**
 * Dependency/install layer analyzer (U4, offline). Emits a dependency node per
 * package (flagged when it declares install scripts), plus new-dependency entry
 * nodes from the base->head lockfile diff and from security-relevant .npmrc
 * changes. Cross-layer edges (a script running inside a CI job) are the engine's
 * job (U7); provenance (network) is U8.
 */
export function analyzeDependencies(inputs: DependencyInputs): AnalyzerResult {
  const result = emptyResult();

  let deps;
  try {
    deps = parseLockfile(inputs.headLockfile);
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse package-lock.json: ${(err as Error).message}`,
    });
    return result;
  }
  result.nodes.push(...deps);

  if (inputs.baseLockfile !== undefined) {
    for (const change of diffLockfiles(inputs.baseLockfile, inputs.headLockfile)) {
      const depId = `dep:${change.pkg}@${change.version}`;
      const entryId = `entry:new-dep:${change.pkg}`;
      const entry: AttackNode = {
        id: entryId,
        kind: 'entry',
        entryKind: 'new-dependency',
        exposure: 1,
        label: `${change.change} dependency ${change.pkg}@${change.version}`,
      };
      result.nodes.push(entry);
      result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
    }
  }

  for (const finding of diffNpmrc(inputs.baseNpmrc, inputs.npmrc)) {
    result.nodes.push({
      id: `entry:npmrc:${finding.key}`,
      kind: 'entry',
      entryKind: 'new-dependency',
      exposure: 2,
      label: `.npmrc ${finding.key} set or changed (supply-chain redirect signal)`,
    });
  }

  return result;
}
