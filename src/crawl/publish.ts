/**
 * Site publisher (U8, KTD8, R5). Each publish builds a throwaway repo around the site directory,
 * commits it as a single PARENTLESS commit, and force-pushes it to the registry's Pages branch.
 * No earlier snapshot stays reachable from the branch, so a repo dropped from the list leaves no
 * removal diff in the published history. The ops ledger keeps the audit trail privately.
 *
 * Auth is whatever the environment gives git (the workflow sets up an ssh-agent with the registry
 * deploy key for this step only); nothing here reads or stores a credential.
 */

import { execFile } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface PublishOptions {
  /** Registry remote: an ssh/https URL, or a local path in tests. */
  remoteUrl: string;
  /** Pages branch, normally `gh-pages`. */
  branch: string;
  author: { name: string; email: string };
  /** Defaults to running `git` with a terminal prompt disabled. */
  exec?: (args: string[], cwd: string) => Promise<string>;
}

const BRANCH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$/;

const defaultExec = (args: string[], cwd: string): Promise<string> =>
  new Promise((resolve, reject) => {
    execFile(
      'git',
      args,
      { cwd, timeout: 120_000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } },
      (err, stdout, stderr) =>
        err ? reject(new Error(`git ${args[0]} failed: ${stderr}`)) : resolve(stdout),
    );
  });

export async function publishSite(siteDir: string, opts: PublishOptions): Promise<void> {
  if (!BRANCH_RE.test(opts.branch) || opts.branch.includes('..')) {
    throw new Error(`invalid branch name: ${opts.branch}`);
  }
  let entries: string[];
  try {
    if (!statSync(siteDir).isDirectory()) throw new Error('not a directory');
    entries = readdirSync(siteDir);
  } catch {
    throw new Error(`site directory not found: ${siteDir}`);
  }
  if (entries.length === 0) throw new Error(`site directory is empty: ${siteDir}`);

  const exec = opts.exec ?? defaultExec;
  const tmp = mkdtempSync(join(tmpdir(), 'blastgate-publish-'));
  try {
    cpSync(siteDir, tmp, { recursive: true, filter: (src) => !src.endsWith('/.git') });
    await exec(['init', '-q'], tmp);
    // Orphan by construction: a fresh repo has no history to inherit.
    await exec(['checkout', '-q', '--orphan', opts.branch], tmp);
    await exec(['add', '-A'], tmp);
    await exec(
      [
        '-c',
        `user.name=${opts.author.name}`,
        '-c',
        `user.email=${opts.author.email}`,
        'commit',
        '-q',
        '--no-gpg-sign',
        '-m',
        'Publish registry snapshot',
      ],
      tmp,
    );
    await exec(['push', '--force', opts.remoteUrl, `HEAD:refs/heads/${opts.branch}`], tmp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
