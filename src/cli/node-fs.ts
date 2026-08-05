/**
 * The Node `RepoFs` adapter — the only filesystem/git implementation, shared by
 * the CLI and the GitHub Action bins so both surfaces read a repo identically
 * (structural parity, KTD10). Pure ports live in `collect.ts`; this is the one
 * place that touches `node:fs` and `git`.
 *
 * It is gitignore-aware (ticket 0016): Blastgate reasons about the repo's shipped
 * surface (KD6), so a path matched by `.gitignore` — e.g. a developer's local
 * `.claude/settings.json` — is never read and never becomes a finding. An
 * untracked-but-not-ignored file (an in-flight change a hook fires on) is still
 * scanned. When the target is not a git work tree, it falls back to reading the
 * working tree unfiltered.
 */

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RepoFs } from './collect';

function isGitWorkTree(root: string): boolean {
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

/** Build a `RepoFs` rooted at `root`. Missing files read as null; git failures are soft. */
export function nodeRepoFs(root: string): RepoFs {
  const gitAware = isGitWorkTree(root);
  const ignoreCache = new Map<string, boolean>();

  // `git check-ignore -q` exits 0 when the path is ignored, 1 when it is not.
  const isIgnored = (rel: string): boolean => {
    if (!gitAware) {
      return false;
    }
    let hit = ignoreCache.get(rel);
    if (hit === undefined) {
      try {
        execFileSync('git', ['check-ignore', '-q', '--', rel], { cwd: root, stdio: 'ignore' });
        hit = true;
      } catch {
        hit = false;
      }
      ignoreCache.set(rel, hit);
    }
    return hit;
  };

  return {
    read(rel) {
      if (isIgnored(rel)) {
        return null;
      }
      try {
        return readFileSync(join(root, rel), 'utf8');
      } catch {
        return null;
      }
    },
    listWorkflows() {
      const dir = join(root, '.github', 'workflows');
      try {
        return readdirSync(dir)
          .filter((f) => /\.ya?ml$/.test(f))
          .map((f) => `.github/workflows/${f}`)
          .filter((rel) => !isIgnored(rel));
      } catch {
        return [];
      }
    },
    gitShow(ref, rel) {
      try {
        return execFileSync('git', ['show', `${ref}:${rel}`], {
          cwd: root,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        });
      } catch {
        return null;
      }
    },
  };
}
