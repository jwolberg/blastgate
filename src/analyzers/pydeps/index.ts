/**
 * Python install/build layer analyzer (0028, offline).
 *
 * A `setup.py` executes arbitrary code at `pip install` time — the vector behind
 * the AISI Mythos-5 run that seeded 145 repositories with a malicious installer
 * that ran inside ≥53 Dependabot containers. This is the Python analog of an npm
 * lifecycle script, so it reuses the same graph shape: a dependency node flagged
 * `hasInstallScript`, which the engine connects (`runs-in`) to any CI job that runs
 * an install step and is attacker-triggerable, reaching whatever secret that job
 * holds. The install-step detection for `pip install` lives in the CI analyzer.
 *
 * Attacker-controllability is diff-gated (like a newly-added npm dependency): the
 * dependency node is always emitted so the cross-layer edge can form, but the
 * `new-dependency` entry that makes it a *finding* is emitted only when the diff
 * introduces or changes the install-time code.
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';

/** Python manifests that execute code at install/build time (v1: setup.py). */
export const PYTHON_INSTALL_MANIFESTS = ['setup.py'];

export interface PyManifest {
  path: string;
  /** Contents at head, or null if absent. */
  head: string | null;
  /** Contents at the diff base, or null if absent (or no base). */
  base: string | null;
}

export interface PyDepsInputs {
  manifests: PyManifest[];
}

export function analyzePyDeps(inputs: PyDepsInputs): AnalyzerResult {
  const result = emptyResult();
  for (const m of inputs.manifests) {
    if (m.head === null) {
      continue;
    }
    const depId = `dep:python:${m.path}`;
    const dep: AttackNode = {
      id: depId,
      kind: 'dependency',
      pkg: m.path,
      version: 'install-time',
      isDirect: true,
      hasInstallScript: true,
      ecosystem: 'python',
    };
    result.nodes.push(dep);

    // Attacker-controllable only when an untrusted diff adds or changes the code.
    const introduced = m.base === null || m.base !== m.head;
    if (introduced) {
      const entryId = `entry:new-dep:python:${m.path}`;
      result.nodes.push({
        id: entryId,
        kind: 'entry',
        entryKind: 'new-dependency',
        exposure: 1,
        label: `${m.path} (Python install-time code) added or changed`,
      });
      result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
    }
  }
  return result;
}
