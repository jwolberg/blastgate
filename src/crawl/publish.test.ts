import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { publishSite } from './publish';

let base: string;
const run = (cwd: string, ...args: string[]): string =>
  execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'crawl-publish-'));
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', join(base, 'registry.git')]);
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const author = { name: 'Blastgate Registry', email: 'registry@example.invalid' };
const remote = (): string => join(base, 'registry.git');

function site(name: string, html: string, extra?: Record<string, string>): string {
  const dir = join(base, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'index.html'), html);
  for (const [f, c] of Object.entries(extra ?? {})) {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), c);
  }
  return dir;
}

describe('publishSite', () => {
  it('publishes the site as one parentless commit on the branch', async () => {
    await publishSite(site('s1', '<p>one</p>'), {
      remoteUrl: remote(),
      branch: 'gh-pages',
      author,
    });
    expect(run(remote(), 'rev-list', '--count', 'gh-pages')).toBe('1');
    expect(run(remote(), 'rev-list', '--parents', '-n1', 'gh-pages').split(' ')).toHaveLength(1);
    expect(run(remote(), 'show', 'gh-pages:index.html')).toBe('<p>one</p>');
    expect(run(remote(), 'log', '-1', '--format=%an <%ae>', 'gh-pages')).toBe(
      'Blastgate Registry <registry@example.invalid>',
    );
  });

  it('a second publish replaces the branch: still one commit, the first snapshot unreachable', async () => {
    await publishSite(site('s1', '<p>with removed-repo</p>'), {
      remoteUrl: remote(),
      branch: 'gh-pages',
      author,
    });
    const first = run(remote(), 'rev-parse', 'gh-pages');
    await publishSite(site('s2', '<p>without</p>'), {
      remoteUrl: remote(),
      branch: 'gh-pages',
      author,
    });
    expect(run(remote(), 'rev-list', '--count', 'gh-pages')).toBe('1');
    expect(run(remote(), 'rev-parse', 'gh-pages')).not.toBe(first);
    expect(run(remote(), 'rev-list', 'gh-pages')).not.toContain(first);
    expect(run(remote(), 'show', 'gh-pages:index.html')).toBe('<p>without</p>');
  });

  it('copies nested files, leaves no .git in the site dir, and touches no other branch', async () => {
    const dir = site('s1', 'x', { 'assets/a.txt': 'a' });
    await publishSite(dir, { remoteUrl: remote(), branch: 'gh-pages', author });
    expect(run(remote(), 'ls-tree', '-r', '--name-only', 'gh-pages').split('\n').sort()).toEqual([
      'assets/a.txt',
      'index.html',
    ]);
    expect(existsSync(join(dir, '.git'))).toBe(false);
    expect(run(remote(), 'branch', '--list').trim()).toBe('gh-pages');
  });

  it('rejects a missing or empty site dir and a bad branch name without pushing', async () => {
    await expect(
      publishSite(join(base, 'nope'), { remoteUrl: remote(), branch: 'gh-pages', author }),
    ).rejects.toThrow(/site/);
    const empty = join(base, 'empty');
    mkdirSync(empty);
    await expect(
      publishSite(empty, { remoteUrl: remote(), branch: 'gh-pages', author }),
    ).rejects.toThrow(/empty/);
    await expect(
      publishSite(site('s1', 'x'), { remoteUrl: remote(), branch: '--force', author }),
    ).rejects.toThrow(/branch/);
    expect(readFileSync(join(remote(), 'HEAD'), 'utf8')).toContain('main');
    expect(run(remote(), 'branch', '--list')).toBe('');
  });
});
