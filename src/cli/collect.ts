/**
 * CLI — repo → EngineInputs collection (U9).
 *
 * Reads the files each layer analyzer needs from a repo checkout. The filesystem
 * (and `git show <ref>:<path>` for `--base` diff signals, KTD5) is behind the
 * `RepoFs` port so the collector is pure and offline-testable; the bin injects a
 * Node fs/git adapter.
 */

import type { DependencyInputs } from '../analyzers/deps/index';
import type { ExecInputs, ExecScript } from '../analyzers/exec/index';
import { parseAcknowledgements } from '../engine/acknowledge';
import type { EngineInputs } from '../engine/build';

/** npm lifecycle + build scripts where install-time execution concealment lives (0021). */
const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublishOnly',
  'build',
];

/** Extract repo-local file paths a script command invokes (`node scripts/x.js`, `bash ./y.sh`). */
function referencedLocalFiles(cmd: string): string[] {
  const files = new Set<string>();
  const re = /(?:^|[\s'"=(])(\.{0,2}\/?[\w.\-/]+\.(?:js|cjs|mjs|ts|sh|py))\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd)) !== null) {
    files.add(m[1]!.replace(/^\.\//, ''));
  }
  return [...files];
}

/**
 * Gather the repo's OWN install/build lifecycle scripts (and the local files they
 * invoke) as sources to scan for CI-divergent execution (0021). A malformed
 * package.json yields no exec inputs; the deps analyzer surfaces the parse error.
 */
function collectExec(fs: RepoFs): ExecInputs | undefined {
  const raw = fs.read('package.json');
  if (raw === null) {
    return undefined;
  }
  let scripts: Record<string, unknown> = {};
  try {
    scripts = (JSON.parse(raw) as { scripts?: Record<string, unknown> }).scripts ?? {};
  } catch {
    return undefined;
  }
  const out: ExecScript[] = [];
  for (const name of LIFECYCLE_SCRIPTS) {
    const cmd = scripts[name];
    if (typeof cmd !== 'string') {
      continue;
    }
    out.push({ name, source: cmd });
    for (const rel of referencedLocalFiles(cmd)) {
      const content = fs.read(rel);
      if (content !== null) {
        out.push({ name: `${name} → ${rel}`, source: content });
      }
    }
  }
  return out.length > 0 ? { scripts: out } : undefined;
}

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

  const exec = collectExec(fs);
  if (exec) {
    inputs.exec = exec;
  }

  const acknowledged = parseAcknowledgements(fs.read('.blastgate/acknowledged.json'));
  if (acknowledged.length > 0) {
    inputs.acknowledged = acknowledged;
  }

  return inputs;
}
