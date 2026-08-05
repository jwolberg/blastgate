/**
 * CLI — repo → EngineInputs collection (U9).
 *
 * Reads the files each layer analyzer needs from a repo checkout. The filesystem
 * (and `git show <ref>:<path>` for `--base` diff signals, KTD5) is behind the
 * `RepoFs` port so the collector is pure and offline-testable; the bin injects a
 * Node fs/git adapter.
 */

import { AGENT_INSTRUCTION_PATHS, type AgentDiffInputs } from '../analyzers/agent/config-diff';
import type { DependencyInputs } from '../analyzers/deps/index';
import { GATE_CONFIG_PATHS } from '../analyzers/integrity/self-integrity';
import { PYTHON_INSTALL_MANIFESTS } from '../analyzers/pydeps/index';
import type { ExecInputs, ExecScript } from '../analyzers/exec/index';
import { parseAcknowledgements } from '../engine/acknowledge';
import { parsePolicy, ruleKey } from '../engine/policy';
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
  /** Reference date (`YYYY-MM-DD`) for policy-rule expiry (0030); the bin supplies today. */
  now?: string;
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

  // 0028: Python install-time execution (setup.py). Head+base per manifest when a base
  // ref is set, so a fork PR that adds/changes install-time code is attacker-controllable.
  if (opts.base && fs.gitShow) {
    const manifests = PYTHON_INSTALL_MANIFESTS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow!(opts.base!, path),
    }));
    if (manifests.some((m) => m.head !== null)) {
      inputs.pydeps = { manifests };
    }
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

  // 0023: agent instruction files introduced/changed by the diff (needs a base ref;
  // a repo's own committed CLAUDE.md is not a finding). Head+base per watched path.
  if (opts.base && fs.gitShow) {
    const files = AGENT_INSTRUCTION_PATHS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow!(opts.base!, path),
    }));
    const agentDiff: AgentDiffInputs = { files };
    if (files.some((f) => f.head !== null)) {
      inputs.agentDiff = agentDiff;
    }
  }

  // 0024: gate-config files diffed to detect Blastgate's own enforcement being removed
  // (an agent disabling the gate before doing the blocked thing). Needs a base ref, and
  // only fires when the gate was wired at base (a repo that never used Blastgate is safe).
  if (opts.base && fs.gitShow) {
    const files = GATE_CONFIG_PATHS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow!(opts.base!, path),
    }));
    if (files.some((f) => f.base !== null)) {
      inputs.selfIntegrity = { files };
    }
  }

  // 0019: only honor acknowledgements already on the trusted base ref — a PR must not
  // self-approve its own findings by committing an ack in the same diff. Head-introduced
  // acks are ignored and surfaced. Without a base (a local whole-repo scan of your own
  // repo), honor the committed head acks as before.
  const headAcks = parseAcknowledgements(fs.read('.blastgate/acknowledged.json'));
  if (opts.base && fs.gitShow) {
    const baseAcks = parseAcknowledgements(fs.gitShow(opts.base, '.blastgate/acknowledged.json'));
    const baseIds = new Set(baseAcks.map((a) => a.id));
    const ignored = headAcks.filter((a) => !baseIds.has(a.id));
    if (baseAcks.length > 0) {
      inputs.acknowledged = baseAcks;
    }
    if (ignored.length > 0) {
      inputs.acknowledgedIgnored = ignored;
    }
  } else if (headAcks.length > 0) {
    inputs.acknowledged = headAcks;
  }

  // 0030: the typed exception policy — same base-vs-head self-approval guard as acks
  // (0019). Parse-time rejections (blanket/wildcard/no-reason) are always surfaced.
  const headPolicy = parsePolicy(fs.read('.blastgate/policy.json'));
  if (headPolicy.diagnostics.length > 0) {
    inputs.policyDiagnostics = headPolicy.diagnostics;
  }
  if (opts.base && fs.gitShow) {
    const basePolicy = parsePolicy(fs.gitShow(opts.base, '.blastgate/policy.json'));
    const baseKeys = new Set(basePolicy.rules.map(ruleKey));
    const honored = headPolicy.rules.filter((r) => baseKeys.has(ruleKey(r)));
    const ignored = headPolicy.rules.filter((r) => !baseKeys.has(ruleKey(r)));
    if (honored.length > 0) {
      inputs.policy = { rules: honored };
    }
    if (ignored.length > 0) {
      inputs.policyIgnored = ignored;
    }
  } else if (headPolicy.rules.length > 0) {
    inputs.policy = { rules: headPolicy.rules };
  }

  if (opts.now !== undefined) {
    inputs.now = opts.now;
  }

  return inputs;
}
