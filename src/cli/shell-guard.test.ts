import { describe, expect, it } from 'vitest';
import { classifyShellCommand } from './shell-guard';

/**
 * The plugin's PreToolUse matchers keyed on literal `Bash(git commit *)` prefixes,
 * so `bash -c '…'`, `git -c core.hooksPath=/dev/null commit`, and chained commands
 * routed around the gate (0025). This classifier inspects the actual command and
 * defaults to gating verbs it recognizes and DENYING gate-disabling bypasses,
 * rather than allowing whatever the glob didn't anticipate.
 */
describe('classifyShellCommand (0025 hook-evasion hardening)', () => {
  // ── gate: a mutating verb we must run the engine on, however it is wrapped ──
  it.each([
    'git commit -m x',
    'git push origin main',
    "bash -c 'git commit -m sneaky'", // wrapped in a subshell
    'sh -c "git push"',
    'git add . && git commit -m x', // chained
    'ls; git commit -m x', // chained after an unrelated command
    'git -c user.name=x commit -m y', // benign -c is still a commit
    'npm install evil-pkg',
    'npm i',
    'npm ci',
    'pnpm add foo',
    'yarn add foo',
  ])('gates: %s', (cmd) => {
    expect(classifyShellCommand(cmd)).toBe('gate');
  });

  // ── bypass: actively disabling commit/push verification → deny, not allow ──
  it.each([
    'git commit --no-verify -m x',
    'git push --no-verify',
    'git -c core.hooksPath=/dev/null commit -m x',
    "bash -c 'git -c core.hooksPath=/dev/null commit'",
    'git commit -n -m x', // -n is the --no-verify short flag
  ])('flags as bypass: %s', (cmd) => {
    expect(classifyShellCommand(cmd)).toBe('bypass');
  });

  // ── ignore: no mutating verb, no bypass → allow fast ──
  it.each([
    'ls -la',
    'git status',
    'git log --oneline',
    'npm test',
    'npm run build',
    'cat package.json',
    'echo hello',
  ])('ignores: %s', (cmd) => {
    expect(classifyShellCommand(cmd)).toBe('ignore');
  });
});
