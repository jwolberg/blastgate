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
  /**
   * requirements.txt at head/base (0033). Chosen as the v1 dependency-diff target —
   * the most universal Python dependency file and the simplest to diff. `base` is
   * null when the file is new at head. An added/bumped package is install-capable
   * (a pip sdist runs `setup.py` at install), so it reaches a secret held by a
   * fork-triggerable `pip install` job — the RubyGems/npm model.
   */
  requirements?: { head: string | null; base: string | null };
}

/** Parse a requirements.txt to package → pinned version ('' if unpinned). Skips comments/options. */
export function parseRequirements(content: string): Map<string, string> {
  const pkgs = new Map<string, string>();
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith('-')) {
      continue; // blank, comment, or an option like `-r base.txt` / `-e .`
    }
    const m = /^([A-Za-z0-9_.-]+)\s*(?:==\s*([^\s;#]+))?/.exec(line);
    if (m) {
      pkgs.set(m[1]!.toLowerCase(), m[2] ?? '');
    }
  }
  return pkgs;
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

  // 0033: requirements.txt dependency diff — a package an untrusted change adds or
  // bumps is an install-capable dependency reaching a fork-triggerable install job.
  const req = inputs.requirements;
  if (req && req.head !== null) {
    const head = parseRequirements(req.head);
    const base = req.base ? parseRequirements(req.base) : new Map<string, string>();
    for (const [pkg, version] of head) {
      const baseVersion = base.get(pkg);
      if (baseVersion === version) {
        continue; // unchanged, trusted
      }
      const change = baseVersion === undefined ? 'added' : 'changed';
      const depId = `dep:python:pkg:${pkg}`;
      result.nodes.push({
        id: depId,
        kind: 'dependency',
        pkg,
        version: version || 'unpinned',
        isDirect: true,
        hasInstallScript: true,
        ecosystem: 'python',
      });
      const entryId = `entry:new-dep:python:pkg:${pkg}`;
      result.nodes.push({
        id: entryId,
        kind: 'entry',
        entryKind: 'new-dependency',
        exposure: 1,
        label: `${change} Python dependency ${pkg}${version ? `@${version}` : ''}`,
      });
      result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
    }
  }

  return result;
}
