/**
 * RubyGems install layer analyzer (0032, offline).
 *
 * A Ruby gem can execute arbitrary code at `bundle install` / `gem install` time —
 * native-extension `extconf.rb`, a Rakefile compile step, or a gem's own install
 * hooks. Bundler's `Gemfile.lock` does not record whether a gem runs install-time
 * code (unlike npm's `hasInstallScript`), so we cannot rule it out offline: an
 * added gem is treated as install-capable. Precision comes from reachability, not
 * per-gem script detection — the finding only forms when the untrusted change adds
 * the gem AND it is installed by a fork-triggerable CI job that holds a secret.
 *
 * This mirrors the npm/Python shape: a dependency node flagged `hasInstallScript`,
 * which the engine connects (`runs-in`) to an attacker-triggerable install job.
 * Attacker-controllability is diff-gated — a gem is only a finding when the
 * base→head diff introduces or bumps it (an existing Gemfile is trusted state).
 * The `bundle install` / `gem install` install-step detection lives in the CI
 * analyzer (`INSTALL_RE`).
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';

export interface RubyGemsInputs {
  /** Gemfile.lock contents at head (required). */
  headLockfile: string;
  /** Gemfile.lock at the base ref, or null when new at head; undefined = no diff (whole-repo). */
  baseLockfile?: string | null;
}

/**
 * Parse a `Gemfile.lock` to a map of resolved gem → version. Resolved specs are
 * indented exactly four spaces as `name (1.2.3)`; a gem's own dependency lines are
 * indented six spaces and its version is a constraint (`>= 1.0`), so a concrete,
 * digit-leading version at four-space indent isolates the resolved top-level gems.
 */
export function parseGemfileLock(content: string): Map<string, string> {
  const gems = new Map<string, string>();
  const re = /^ {4}([A-Za-z0-9_.-]+) \((\d[^()]*)\)\s*$/;
  for (const line of content.split(/\r?\n/)) {
    const m = re.exec(line);
    if (m) {
      gems.set(m[1]!, m[2]!);
    }
  }
  return gems;
}

export function analyzeRubyGems(inputs: RubyGemsInputs): AnalyzerResult {
  const result = emptyResult();
  // Whole-repo mode (no base): an existing Gemfile is the maintainer's trusted
  // state; only a diff that adds/bumps a gem is attacker-controllable.
  if (inputs.baseLockfile === undefined) {
    return result;
  }

  const head = parseGemfileLock(inputs.headLockfile);
  const base = inputs.baseLockfile
    ? parseGemfileLock(inputs.baseLockfile)
    : new Map<string, string>();

  for (const [gem, version] of head) {
    const baseVersion = base.get(gem);
    if (baseVersion === version) {
      continue; // unchanged, trusted
    }
    const change = baseVersion === undefined ? 'added' : 'changed';
    const depId = `dep:ruby:${gem}@${version}`;
    result.nodes.push({
      id: depId,
      kind: 'dependency',
      pkg: gem,
      version,
      isDirect: true,
      hasInstallScript: true,
      ecosystem: 'ruby',
    } as AttackNode);

    const entryId = `entry:new-dep:ruby:${gem}`;
    result.nodes.push({
      id: entryId,
      kind: 'entry',
      entryKind: 'new-dependency',
      exposure: 1,
      label: `${change} gem ${gem}@${version} (Ruby install-time execution)`,
    });
    result.edges.push({ from: entryId, to: depId, edge: { kind: 'controls' } });
  }

  return result;
}
