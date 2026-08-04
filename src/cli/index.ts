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

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runEngine } from '../engine/gate';
import { VERSION } from '../index';
import { collectInputs, type RepoFs } from './collect';
import { hookOutput } from './gate';
import { renderJson, renderText, scanExitCode } from './render';

/** The injected environment `runCli` runs against (real I/O lives only in the bin). */
export interface CliEnv {
  fs: RepoFs;
  stdin: () => Promise<string>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const VALUE_FLAGS = new Set(['--base', '--gate', '--format']);

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
    '  --provenance    (not yet available — U8, network-gated)',
    '  --version       print version',
    '',
  ].join('\n');
}

function scanMode(argv: string[], env: CliEnv): number {
  if (argv.includes('--provenance')) {
    env.stderr(
      'blastgate: --provenance is not available yet (U8, network-gated); running offline.\n',
    );
  }
  const base = flagValue(argv, '--base');
  const inputs = collectInputs(env.fs, base !== undefined ? { base } : {});
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
  const base = flagValue(argv, '--base') ?? 'HEAD';
  const result = runEngine(collectInputs(env.fs, { base }));

  if (phase === undefined) {
    // `check` with no --gate is the slash-command scan surface.
    env.stdout(wantsJson(argv) ? renderJson(result) : renderText(result));
    return scanExitCode(result);
  }

  const { stdout, exitCode } = hookOutput(phase, result);
  if (stdout) {
    env.stdout(stdout);
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
    env.stderr('blastgate mcp: self-check server not wired yet (U13).\n');
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

function nodeRepoFs(root: string): RepoFs {
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
  const root = cmd === 'check' || cmd === 'mcp' ? '.' : (firstPositional(argv) ?? '.');
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
