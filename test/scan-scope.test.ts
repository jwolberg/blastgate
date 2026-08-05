import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { collectInputs } from '../src/cli/collect';
import { nodeRepoFs } from '../src/cli/node-fs';
import { runEngine } from '../src/engine/gate';

/** A committed `type: command` hook — an over-baseline shell grant (warn-tier). */
const SETTINGS_WITH_HOOK = JSON.stringify({
  hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'x.sh' }] }] },
});

const created: string[] = [];
function tmpRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'bg-scope-'));
  created.push(dir);
  return dir;
}
function git(dir: string, args: string[]): void {
  execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
}
function writeSettings(dir: string): void {
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), SETTINGS_WITH_HOOK);
}
function scan(dir: string) {
  return runEngine(collectInputs(nodeRepoFs(dir), {}));
}

afterEach(() => {
  for (const dir of created.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

describe('scan scope is gitignore-aware (ticket 0016)', () => {
  it('does not scan a gitignored .claude/settings.json — clean pass', () => {
    const dir = tmpRepo();
    git(dir, ['init']);
    writeFileSync(join(dir, '.gitignore'), '.claude/\n');
    writeSettings(dir);

    const result = scan(dir);
    expect(result.verdict).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });

  it('still warns on a tracked (non-ignored) .claude/settings.json command hook', () => {
    const dir = tmpRepo();
    git(dir, ['init']); // no .gitignore → the file is part of the repo surface
    writeSettings(dir);

    const result = scan(dir);
    expect(result.verdict).toBe('warn');
    expect(result.findings.some((f) => f.sink.kind === 'privileged-capability')).toBe(true);
  });

  it('falls back to scanning the working tree when the target is not a git repo', () => {
    const dir = tmpRepo(); // no `git init`
    writeSettings(dir);

    const result = scan(dir);
    expect(result.verdict).toBe('warn'); // no git → no ignore filtering, scanned as before
  });
});
