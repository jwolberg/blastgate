/**
 * Axis-A "Blastgate as software" hardening (self-audit findings).
 *
 * Blastgate ingests an untrusted repository and runs in privileged CI, so the
 * tool itself must be safe to run on hostile input. These are adversarial
 * regression tests for three found-and-verified issues:
 *   #1 `gitShow` argv injection → arbitrary file write (attacker-controlled `ref`)
 *   #2 symlinked config/lockfile → arbitrary file read outside the repo
 *   #4 the provenance `fetch` following HTTP redirects (SSRF defense-in-depth)
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { nodeRepoFs } from '../src/cli/node-fs';
import { httpSource } from '../src/registry/packument';

const created: string[] = [];
function tmp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  created.push(dir);
  return dir;
}
function git(dir: string, args: string[]): void {
  execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
}
function initRepo(dir: string): void {
  git(dir, ['init']);
  git(dir, ['config', 'user.email', 't@t']);
  git(dir, ['config', 'user.name', 't']);
}
function commitLock(dir: string, content: string): void {
  writeFileSync(join(dir, 'package-lock.json'), content);
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-m', 'init']);
}

afterEach(() => {
  for (const dir of created.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

describe('#2 node-fs does not read outside the repo via symlinks', () => {
  it('returns null when a fixed path is a symlink to a file outside the repo', () => {
    const outside = tmp('bg-outside-');
    writeFileSync(join(outside, 'secret.txt'), 'OUTSIDE_SECRET');
    const repo = tmp('bg-repo-');
    initRepo(repo);
    symlinkSync(join(outside, 'secret.txt'), join(repo, 'package-lock.json'));

    expect(nodeRepoFs(repo).read('package-lock.json')).toBeNull();
  });

  it('returns null when a parent directory is a symlink escaping the repo', () => {
    const outside = tmp('bg-outside-');
    mkdirSync(join(outside, 'claude'));
    writeFileSync(join(outside, 'claude', 'settings.json'), '{"secret":"OUTSIDE"}');
    const repo = tmp('bg-repo-');
    initRepo(repo);
    symlinkSync(join(outside, 'claude'), join(repo, '.claude'));

    expect(nodeRepoFs(repo).read('.claude/settings.json')).toBeNull();
  });

  it('still reads a normal (non-symlink) file inside the repo', () => {
    const repo = tmp('bg-repo-');
    initRepo(repo);
    writeFileSync(join(repo, 'package-lock.json'), 'REAL');
    expect(nodeRepoFs(repo).read('package-lock.json')).toBe('REAL');
  });
});

describe('#1 node-fs gitShow is not argv-injectable', () => {
  it('a --output=… ref writes no file outside the repo and returns null', () => {
    const outside = tmp('bg-outside-');
    const repo = tmp('bg-repo-');
    initRepo(repo);
    commitLock(repo, 'REAL_LOCK\n');

    const before = readdirSync(outside);
    const malicious = `--output=${join(outside, 'pwned')}`;
    const out = nodeRepoFs(repo).gitShow!(malicious, 'package-lock.json');

    expect(out).toBeNull(); // the injected option never resolves to a blob
    expect(readdirSync(outside)).toEqual(before); // and nothing was written outside the repo
  });

  it('still returns blob content for a legitimate ref (regression)', () => {
    const repo = tmp('bg-repo-');
    initRepo(repo);
    commitLock(repo, 'REAL_LOCK\n');
    expect(nodeRepoFs(repo).gitShow!('HEAD', 'package-lock.json')).toBe('REAL_LOCK\n');
  });
});

describe('#4 httpSource does not follow HTTP redirects', () => {
  it('passes redirect:"error" to fetch and soft-nulls a non-ok response', async () => {
    const orig = globalThis.fetch;
    let init: RequestInit | undefined;
    globalThis.fetch = ((_url: string | URL, i?: RequestInit) => {
      init = i;
      return Promise.resolve({ ok: false } as Response);
    }) as typeof fetch;
    try {
      const res = await httpSource().fetch('lodash');
      expect(res).toBeNull();
    } finally {
      globalThis.fetch = orig;
    }
    expect(init?.redirect).toBe('error');
  });
});
