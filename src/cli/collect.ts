/**
 * CLI — repo → EngineInputs collection (U9).
 *
 * Reads the files each layer analyzer needs from a repo checkout. The filesystem
 * (and `git show <ref>:<path>` for `--base` diff signals, KTD5) is behind the
 * `RepoFs` port so the collector is pure and offline-testable; the bin injects a
 * Node fs/git adapter.
 */

import type { DependencyInputs } from '../analyzers/deps/index';
import { parseAcknowledgements } from '../engine/acknowledge';
import type { EngineInputs } from '../engine/build';

/** Filesystem port: relative paths from the repo root; `read` returns null if absent. */
export interface RepoFs {
  read(relPath: string): string | null;
  /** Workflow file paths under `.github/workflows` (`.yml`/`.yaml`). */
  listWorkflows(): string[];
  /** `git show <ref>:<relPath>`; null if the file did not exist at `ref` (or no git). */
  gitShow?(ref: string, relPath: string): string | null;
}

export interface CollectOptions {
  /** A git ref to diff against for change signals (new deps, `.npmrc` changes). */
  base?: string;
}

/** Collect per-layer inputs from a repo checkout. Layers with no source files are omitted. */
export function collectInputs(fs: RepoFs, opts: CollectOptions = {}): EngineInputs {
  const inputs: EngineInputs = {};

  const headLock = fs.read('package-lock.json');
  if (headLock !== null) {
    const deps: DependencyInputs = { headLockfile: headLock };
    const npmrc = fs.read('.npmrc');
    if (npmrc !== null) {
      deps.npmrc = npmrc;
    }
    if (opts.base && fs.gitShow) {
      // null base lockfile ⇒ the file is new at head; the diff treats every dep as added.
      deps.baseLockfile = fs.gitShow(opts.base, 'package-lock.json');
      deps.baseNpmrc = fs.gitShow(opts.base, '.npmrc');
    }
    inputs.deps = deps;
  }

  const workflows = fs
    .listWorkflows()
    .map((path) => ({ path, content: fs.read(path) ?? '' }))
    .filter((w) => w.content !== '');
  if (workflows.length > 0) {
    inputs.ci = { workflows };
  }

  const mcpJson = fs.read('.mcp.json');
  const claudeSettings = fs.read('.claude/settings.json');
  const cursorMcpJson = fs.read('.cursor/mcp.json');
  if (mcpJson !== null || claudeSettings !== null || cursorMcpJson !== null) {
    inputs.agent = {
      mcpJson: mcpJson ?? undefined,
      claudeSettings: claudeSettings ?? undefined,
      cursorMcpJson: cursorMcpJson ?? undefined,
    };
  }

  const acknowledged = parseAcknowledgements(fs.read('.blastgate/acknowledged.json'));
  if (acknowledged.length > 0) {
    inputs.acknowledged = acknowledged;
  }

  return inputs;
}
