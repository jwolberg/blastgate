import { describe, expect, it } from 'vitest';
import { analyzeRubyGems, parseGemfileLock } from './index';

const LOCK = (gems: string) =>
  ['GEM', '  remote: https://rubygems.org/', '  specs:', gems, '', 'PLATFORMS', '  ruby', ''].join(
    '\n',
  );

describe('parseGemfileLock', () => {
  it('captures resolved top-level gems, not their dependency constraints', () => {
    const lock = LOCK(
      ['    rails (7.0.4)', '      actionpack (= 7.0.4)', '    rake (13.0.6)'].join('\n'),
    );
    const gems = parseGemfileLock(lock);
    expect(gems.get('rails')).toBe('7.0.4');
    expect(gems.get('rake')).toBe('13.0.6');
    // A 6-space dependency-constraint line is not a resolved gem.
    expect(gems.has('actionpack')).toBe(false);
  });
});

describe('analyzeRubyGems', () => {
  it('emits an install-capable ruby dep + new-dependency entry for an added gem', () => {
    const base = LOCK('    rake (13.0.6)');
    const head = LOCK(['    rake (13.0.6)', '    evil_gem (1.0.0)'].join('\n'));
    const r = analyzeRubyGems({ headLockfile: head, baseLockfile: base });

    const dep = r.nodes.find((n) => n.kind === 'dependency');
    expect(dep && dep.kind === 'dependency' && dep.ecosystem).toBe('ruby');
    expect(dep && dep.kind === 'dependency' && dep.hasInstallScript).toBe(true);
    expect(dep && dep.kind === 'dependency' && dep.pkg).toBe('evil_gem');
    expect(r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'new-dependency')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'controls')).toBe(true);
  });

  it('flags a version bump of an existing gem as changed', () => {
    const base = LOCK('    nokogiri (1.13.0)');
    const head = LOCK('    nokogiri (1.14.0)');
    const r = analyzeRubyGems({ headLockfile: head, baseLockfile: base });
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(true);
  });

  it('emits nothing for an unchanged lockfile (trusted existing state)', () => {
    const lock = LOCK('    rake (13.0.6)');
    expect(analyzeRubyGems({ headLockfile: lock, baseLockfile: lock }).nodes).toHaveLength(0);
  });

  it('emits nothing in whole-repo mode (no base diff)', () => {
    const lock = LOCK('    rake (13.0.6)');
    expect(analyzeRubyGems({ headLockfile: lock }).nodes).toHaveLength(0);
  });
});
