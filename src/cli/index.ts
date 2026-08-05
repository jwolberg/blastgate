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
import { runEngine } from '../engine/gate';
import { VERSION } from '../index';
import { runStdioServer } from '../mcp/server';
import { cachedFetcher, httpSource } from '../registry/packument';
import { collectInputs, type RepoFs } from './collect';
import { hookOutput } from './gate';
import { nodeRepoFs } from './node-fs';
import { renderJson, renderText, scanExitCode } from './render';

/** The injected environment `runCli` runs against (real I/O lives only in the bin). */
export interface CliEnv {
  fs: RepoFs;
  stdin: () => Promise<string>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
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

function wantsJson(argv: string[]): boolean {
  return argv.includes('--json') || flagValue(argv, '--format') === 'json';
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
    '  --base <ref>    diff against a git ref for change signals (new deps, .npmrc changes)',
    '  --json          emit the findings array as JSON',
    '  --provenance    opt-in npm provenance-regression check (network; needs --base)',
    '  --version       print version',
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
  const inputs = collectInputs(env.fs, base !== undefined ? { base } : {});
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);
  env.stdout(wantsJson(argv) ? renderJson(result) : renderText(result));
  return scanExitCode(result);
}

async function checkMode(argv: string[], env: CliEnv): Promise<number> {
  const phase = flagValue(argv, '--gate');
  // Hook JSON (tool_input.command / .file_path) is read for scoping; v1 scopes to
  // the working tree. Parse defensively — slash-command input may not be hook JSON.
  const raw = await env.stdin();
  if (raw) {
    try {
      JSON.parse(raw);
    } catch {
      /* not hook JSON; ignore */
    }
  }
  // A hook fires on an in-flight change, so diff the working tree against HEAD to
  // light up new-dependency / changed-config signals (KTD5).
  const base = baseRef(argv) ?? 'HEAD';
  const inputs = collectInputs(env.fs, { base });
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);

  if (phase === undefined) {
    // `check` with no --gate is the slash-command scan surface.
    env.stdout(wantsJson(argv) ? renderJson(result) : renderText(result));
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
