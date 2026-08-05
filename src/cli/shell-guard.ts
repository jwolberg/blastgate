/**
 * Shell-command classifier for the plugin gate (0025).
 *
 * The plugin's PreToolUse matchers keyed on literal `Bash(git commit *)` prefixes,
 * so a mutating command wrapped in `bash -c '…'`, prefixed with
 * `git -c core.hooksPath=/dev/null`, or chained after another command routed around
 * the gate. This inspects the actual command string and:
 *  - `gate`   — a commit/push/install verb we must run the engine on (however wrapped)
 *  - `bypass` — an attempt to DISABLE verification (deny, do not allow)
 *  - `ignore` — anything else (allow fast, no engine run)
 *
 * A deterministic string heuristic, not a shell parser: tuned to fail closed on the
 * evasions that route around a naive matcher rather than allow what it didn't expect.
 */

export type ShellClass = 'gate' | 'bypass' | 'ignore';

// A git subcommand anywhere in a single command segment (stops at a shell separator),
// so `bash -c 'git commit'`, `ls; git commit`, and `git add . && git commit` all match.
const GIT_COMMIT = /\bgit\b[^|;&\n]*\bcommit\b/;
const GIT_PUSH = /\bgit\b[^|;&\n]*\bpush\b/;
const NPM_INSTALL = /\bnpm\s+(?:install|i|ci|add)\b/;
const YARN_PNPM_INSTALL = /\b(?:yarn|pnpm)\s+(?:add|install)\b/;

// Disabling git hooks entirely — a bypass regardless of the surrounding verb.
const HOOKS_DISABLED = /core\.hooksPath\s*=/;
// Skipping verification hooks on a commit/push: `--no-verify` or its `-n` short flag.
const NO_VERIFY = /--no-verify\b/;
const SHORT_NO_VERIFY = /(?:^|\s)-n(?=\s|$)/;

export function classifyShellCommand(command: string): ShellClass {
  const gitMutating = GIT_COMMIT.test(command) || GIT_PUSH.test(command);

  // Bypass takes precedence over gate: actively disabling verification must be denied,
  // not merely evaluated.
  if (HOOKS_DISABLED.test(command)) {
    return 'bypass';
  }
  if (gitMutating && (NO_VERIFY.test(command) || SHORT_NO_VERIFY.test(command))) {
    return 'bypass';
  }

  if (gitMutating || NPM_INSTALL.test(command) || YARN_PNPM_INSTALL.test(command)) {
    return 'gate';
  }
  return 'ignore';
}
