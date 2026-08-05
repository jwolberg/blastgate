#!/usr/bin/env node
/**
 * blastgate CLI (U9) — the entrypoint the GitHub Action, plugin hooks, and MCP
 * self-check all ride. One engine, one Finding shape, multiple surfaces (KTD10).
 *
 *   blastgate [path] [--base <ref>] [--json]   scan a repo for reachable paths
 *   blastgate check --gate <phase>             plugin hook gate (hook JSON on stdin)
 *   blastgate mcp                              stdio MCP self-check server (U13)
 *
 * `runCli` is pure over an injected `CliEnv` (filesystem, stdin, output sinks) so
 * the whole surface is offline-testable; the bin at the bottom wires the Node
 * adapters and is the only part with real process I/O.
 */

import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { analyzeProvenance } from '../analyzers/deps/provenance';
import { type EngineInputs } from '../engine/build';
import { runEngine, type GateResult } from '../engine/gate';
import { VERSION } from '../index';
import { runStdioServer } from '../mcp/server';
import { cachedFetcher, httpSource } from '../registry/packument';
import { osvHttpSource } from '../registry/osv';
import { enrichWithAdvisories } from '../enrichment/advisories';
import { collectInputs, type RepoFs } from './collect';
import { bypassOutput, hookOutput } from './gate';
import { nodeRepoFs } from './node-fs';
import { classifyShellCommand } from './shell-guard';
import { renderJson, renderMarkdown, renderText, scanExitCode } from './render';

/** The injected environment `runCli` runs against (real I/O lives only in the bin). */
export interface CliEnv {
  fs: RepoFs;
  stdin: () => Promise<string>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  /** Today's date (`YYYY-MM-DD`) for policy-rule expiry (0030); the bin injects a real clock. */
  now?: () => string;
}

const VALUE_FLAGS = new Set(['--base', '--since', '--gate', '--format']);

/** `--base <ref>`, or its `/blastgate` slash-command alias `--since <ref>`. */
function baseRef(argv: string[]): string | undefined {
  return flagValue(argv, '--base') ?? flagValue(argv, '--since');
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : undefined;
}

type OutputFormat = 'text' | 'json' | 'markdown';

/** Pick the output renderer from flags. `--json`/`--md` are shorthands for `--format`. */
function outputFormat(argv: string[]): OutputFormat {
  const fmt = flagValue(argv, '--format');
  if (argv.includes('--json') || fmt === 'json') {
    return 'json';
  }
  if (argv.includes('--md') || fmt === 'md' || fmt === 'markdown') {
    return 'markdown';
  }
  return 'text';
}

/** Render a gate result in the format the flags asked for (text is the default). */
function renderResult(result: GateResult, argv: string[]): string {
  switch (outputFormat(argv)) {
    case 'json':
      return renderJson(result);
    case 'markdown':
      return renderMarkdown(result);
    default:
      return renderText(result);
  }
}

function usage(): string {
  return [
    `blastgate ${VERSION} — cross-layer attack-path gate`,
    '',
    'Usage:',
    '  blastgate [path] [--base <ref>] [--json]   scan a repo for reachable attacker→sink paths',
    '  blastgate check --gate <phase>             plugin hook gate (reads hook JSON on stdin)',
    '  blastgate mcp                              stdio MCP self-check server',
    '',
    'Flags:',
    '  --base <ref>       diff against a git ref for change signals (new deps, .npmrc changes)',
    '  --format <fmt>     output format: text (default), json, or md (human-readable report)',
    '  --json / --md      shorthands for --format json / --format md',
    '  --provenance       opt-in npm provenance-regression check (network; needs --base)',
    '  --advisories       opt-in CVE/advisory enrichment of reachable deps (network; OSV; never gates)',
    '  --version          print version',
    '',
  ].join('\n');
}

/**
 * Compute the opt-in provenance-regression result (U8). Returns undefined unless
 * `--provenance` is set — this is the ONLY path that touches the network (KTD6);
 * the core scan/gate is fully offline. Needs a base ref for a version baseline.
 */
async function provenanceResult(
  argv: string[],
  env: CliEnv,
  base: string | undefined,
): Promise<EngineInputs['provenance']> {
  if (!argv.includes('--provenance')) {
    return undefined;
  }
  if (!base) {
    env.stderr('blastgate: --provenance needs --base <ref> for a version baseline; skipping.\n');
    return undefined;
  }
  const headLock = env.fs.read('package-lock.json');
  if (headLock === null) {
    return undefined;
  }
  const baseLock = env.fs.gitShow ? env.fs.gitShow(base, 'package-lock.json') : null;
  return analyzeProvenance(baseLock, headLock, cachedFetcher(httpSource()));
}

async function scanMode(argv: string[], env: CliEnv): Promise<number> {
  const base = baseRef(argv);
  const inputs = collectInputs(env.fs, {
    ...(base !== undefined ? { base } : {}),
    now: env.now?.(),
  });
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);
  // 0036: opt-in CVE/advisory enrichment. Enrichment only — decorates findings and
  // re-ranks; it never changes the verdict, so scanExitCode(result) is unaffected.
  if (argv.includes('--advisories')) {
    result.findings = await enrichWithAdvisories(result.findings, osvHttpSource());
  }
  env.stdout(renderResult(result, argv));
  return scanExitCode(result);
}

async function checkMode(argv: string[], env: CliEnv): Promise<number> {
  const phase = flagValue(argv, '--gate');
  // Hook JSON (tool_input.command / .file_path) is read for scoping and, for the
  // shell-guard phases, command classification. Parse defensively — a slash-command
  // invocation may not be hook JSON.
  const raw = await env.stdin();
  let hook: { tool_input?: { command?: string } } | undefined;
  if (raw) {
    try {
      hook = JSON.parse(raw) as { tool_input?: { command?: string } };
    } catch {
      /* not hook JSON; ignore */
    }
  }

  // Shell-guard phases (0025): inspect the ACTUAL command rather than trust a literal
  // matcher, so a wrapped/chained commit or a hook-disabling bypass can't route
  // around the gate. `ignore` → allow fast (no engine run); `bypass` → deny; `gate`
  // → fall through and run the engine as usual.
  if (phase === 'shell-pre' || phase === 'shell-post') {
    const command = hook?.tool_input?.command;
    const cls = command ? classifyShellCommand(command) : 'ignore';
    if (cls === 'ignore') {
      return 0;
    }
    if (cls === 'bypass') {
      const out = bypassOutput(phase, command ?? '');
      if (out.stdout) {
        env.stdout(out.stdout);
      }
      if (out.stderr) {
        env.stderr(out.stderr);
      }
      return out.exitCode;
    }
  }

  // A hook fires on an in-flight change, so diff the working tree against HEAD to
  // light up new-dependency / changed-config signals (KTD5).
  const base = baseRef(argv) ?? 'HEAD';
  const inputs = collectInputs(env.fs, { base, now: env.now?.() });
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);

  if (phase === undefined) {
    // `check` with no --gate is the slash-command scan surface.
    env.stdout(renderResult(result, argv));
    return scanExitCode(result);
  }

  const { stdout, stderr, exitCode } = hookOutput(phase, result);
  if (stdout) {
    env.stdout(stdout);
  }
  if (stderr) {
    env.stderr(stderr);
  }
  return exitCode;
}

/** Dispatch a parsed argv against an injected environment. */
export async function runCli(argv: string[], env: CliEnv): Promise<number> {
  if (argv.includes('--version') || argv.includes('-v')) {
    env.stdout(`blastgate ${VERSION}\n`);
    return 0;
  }
  const cmd = argv[0];
  if (cmd === '--help' || cmd === '-h' || cmd === 'help') {
    env.stdout(usage());
    return 0;
  }
  if (cmd === 'check') {
    return checkMode(argv, env);
  }
  if (cmd === 'mcp') {
    // The stdio server needs the real process streams; the bin's main() runs it.
    env.stderr('blastgate mcp: run via the bin (needs stdio streams).\n');
    return 0;
  }
  return scanMode(argv, env);
}

// ---- Node bin wiring (the only part with real process I/O) ----

function firstPositional(argv: string[]): string | undefined {
  const subcommands = new Set(['check', 'mcp', 'help']);
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]!;
    if (tok.startsWith('-')) {
      if (VALUE_FLAGS.has(tok)) {
        i++;
      }
      continue;
    }
    if (subcommands.has(tok)) {
      continue;
    }
    return tok;
  }
  return undefined;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    // Fallback so a hook that leaves stdin open never hangs the gate.
    setTimeout(() => resolve(data), 250);
  });
}

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];

  // `blastgate mcp` runs the long-lived stdio self-check server, scoped to the
  // project dir the plugin passes (BLASTGATE_PROJECT_DIR / CLAUDE_PROJECT_DIR).
  if (cmd === 'mcp') {
    const projectDir = process.env.BLASTGATE_PROJECT_DIR ?? process.env.CLAUDE_PROJECT_DIR ?? '.';
    await runStdioServer({ fs: nodeRepoFs(projectDir), base: 'HEAD' });
    return 0;
  }

  const root = cmd === 'check' ? '.' : (firstPositional(argv) ?? '.');
  if (!existsSync(root)) {
    process.stderr.write(`blastgate: path not found: ${root}\n`);
    return 2;
  }
  return runCli(argv, {
    fs: nodeRepoFs(root),
    stdin: readStdin,
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    now: () => new Date().toISOString().slice(0, 10),
  });
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (invokedDirectly) {
  void main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err: unknown) => {
      process.stderr.write(`blastgate: ${(err as Error).message}\n`);
      process.exit(1);
    });
}
