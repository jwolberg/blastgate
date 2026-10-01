import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * 0066: scripts/eval-scan.sh must never report an incomplete clone as a clean 0/0. A cached
 * clone whose checkout is missing tracked files is re-cloned; a clone that cannot be made
 * complete is an error row. Runs offline against a local file:// "GitHub" and a stub CLI.
 */
const SCRIPT = join(__dirname, '..', 'scripts', 'eval-scan.sh');
let base: string;

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

function scan(list: string[]): string[] {
  writeFileSync(join(base, 'list.txt'), list.join('\n'));
  execFileSync('bash', [SCRIPT, join(base, 'work'), join(base, 'out'), join(base, 'list.txt')], {
    env: {
      ...process.env,
      EVAL_REMOTE_BASE: `file://${join(base, 'remote')}`,
      BLASTGATE_CLI: join(base, 'stub-cli.js'),
      JOBS: '1',
    },
    encoding: 'utf8',
  });
  return readFileSync(join(base, 'out', 'index.tsv'), 'utf8')
    .trim()
    .split('\n');
}

beforeAll(() => {
  base = mkdtempSync(join(tmpdir(), 'eval-scan-'));
  const repo = join(base, 'remote', 'acme', 'app.git');
  mkdirSync(join(repo, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(repo, '.github', 'workflows', 'ci.yml'), 'on: push\njobs: {}\n');
  writeFileSync(join(repo, 'package.json'), '{"name":"app"}\n');
  git(repo, 'init', '-q', '-b', 'main');
  git(repo, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
  git(repo, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init');
  git(repo, 'config', 'uploadpack.allowFilter', 'true');
  // A stub scanner: reports one warn for any repo that has a workflow, so an empty
  // checkout (no .github/) is distinguishable from a real scan.
  writeFileSync(
    join(base, 'stub-cli.js'),
    "const fs=require('fs'),p=require('path');" +
      "const has=fs.existsSync(p.join(process.argv[2],'.github','workflows','ci.yml'));" +
      "process.stdout.write(JSON.stringify(has?[{tier:'warn'}]:[]));",
  );
});

afterAll(() => rmSync(base, { recursive: true, force: true }));

describe('eval-scan.sh — incomplete clones (0066)', () => {
  it('scans a fresh clone (precondition)', () => {
    const [row] = scan(['acme/app']);
    expect(row?.split('\t')).toEqual([
      'acme/app',
      expect.stringMatching(/^[0-9a-f]{7}/),
      '0',
      '0',
      '1',
    ]);
  });

  it('re-clones a cached clone whose checkout lost tracked files, instead of scanning it clean', () => {
    const cached = join(base, 'work', 'acme__app');
    rmSync(join(cached, '.github'), { recursive: true, force: true });
    const [row] = scan(['acme/app']);
    expect(row?.split('\t')[4]).toBe('1');
    expect(existsSync(join(cached, '.github', 'workflows', 'ci.yml'))).toBe(true);
  });

  it('reports a repo that cannot be cloned as an error row, not 0/0', () => {
    const rows = scan(['acme/missing']);
    expect(rows[0]?.split('\t')).toEqual(['acme/missing', '-', 'clone-failed', '-', '-']);
  });
});
