/**
 * The Node `RepoFs` adapter — the only filesystem/git implementation, shared by
 * the CLI and the GitHub Action bins so both surfaces read a repo identically
 * (structural parity, KTD10). Pure ports live in `collect.ts`; this is the one
 * place that touches `node:fs` and `git`.
 */

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RepoFs } from './collect';

/** Build a `RepoFs` rooted at `root`. Missing files read as null; git failures are soft. */
export function nodeRepoFs(root: string): RepoFs {
  return {
    read(rel) {
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
          .map((f) => `.github/workflows/${f}`);
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
