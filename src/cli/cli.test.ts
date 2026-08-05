import { describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import type { RepoFs } from './collect';
import { hookOutput } from './gate';
import { renderJson, renderMarkdown, renderText, scanExitCode } from './render';
import type { GateResult } from '../engine/gate';
import { runCli } from './index';

/** package-lock.json head that adds `evil-pkg@1.0.0` with a lifecycle script. */
const HEAD_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true },
  },
});
const BASE_LOCK = JSON.stringify({ packages: { '': { name: 'app' } } });

/** AE1/AE5 workflow: fork-triggerable job that runs `npm ci` and holds the AWS secret. */
const WORKFLOW = [
  'on:',
  '  pull_request:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');

/** In-memory RepoFs. `base` (if given) backs `gitShow` for --base diff signals. */
function memFs(files: Record<string, string>, base?: Record<string, string>): RepoFs {
  return {
    read: (p) => (p in files ? files[p]! : null),
    listWorkflows: () =>
      Object.keys(files).filter((p) => /^\.github\/workflows\/.*\.ya?ml$/.test(p)),
    gitShow: base ? (_ref, p) => (p in base ? base[p]! : null) : undefined,
  };
}

/** A repo whose committed state fails the gate (AE1/AE5 shape). */
function failingFs(): RepoFs {
  return memFs(
    { 'package-lock.json': HEAD_LOCK, '.github/workflows/ci.yml': WORKFLOW },
    { 'package-lock.json': BASE_LOCK },
  );
}

/** A clean repo: no workflows, no lockfile → nothing reachable. */
function cleanFs(): RepoFs {
  return memFs({ 'package.json': '{"name":"app"}' });
}

interface Captured {
  code: number;
  out: string;
  err: string;
}
async function invoke(argv: string[], fs: RepoFs, stdin = ''): Promise<Captured> {
  let out = '';
  let err = '';
  const code = await runCli(argv, {
    fs,
    stdin: () => Promise.resolve(stdin),
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

describe('renderText', () => {
  it('renders each ranked path with sink, why, fix, and label', () => {
    const finding: Finding = {
      id: 'e=>s',
      tier: 'fail',
      score: 311,
      path: [
        'added dependency evil-pkg@1.0.0',
        'evil-pkg@1.0.0',
        'ci.yml#test',
        'AWS_SECRET_ACCESS_KEY',
      ],
      pathNodeIds: [
        'entry:new-dep:evil-pkg',
        'dep:evil-pkg@1.0.0',
        'job:ci.yml#test',
        'sink:secret:AWS_SECRET_ACCESS_KEY',
      ],
      hops: 3,
      entry: { kind: 'new-dependency', label: 'added dependency evil-pkg@1.0.0' },
      sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
      reason: 'install script executes in a fork job holding the secret',
      remediation: 'gate lifecycle scripts',
      owasp: { agentic: 'ASI04', mcp: 'MCP04' },
      labels: ['ASI04:2026', 'MCP04:2025'],
    };
    const text = renderText({ verdict: 'fail', findings: [finding], diagnostics: [] });
    expect(text).toContain('evil-pkg@1.0.0');
    expect(text).toContain('AWS_SECRET_ACCESS_KEY');
    expect(text).toContain('install script executes');
    expect(text).toContain('gate lifecycle scripts');
    expect(text).toContain('ASI04:2026');
    expect(text).toContain('→');
  });

  it('prints a green pass line for a clean repo', () => {
    const text = renderText({ verdict: 'pass', findings: [], diagnostics: [] });
    expect(text.toUpperCase()).toContain('PASS');
  });
});

describe('scanExitCode', () => {
  it('is non-zero on fail and zero on warn/pass', () => {
    expect(scanExitCode({ verdict: 'fail', findings: [], diagnostics: [] })).not.toBe(0);
    expect(scanExitCode({ verdict: 'warn', findings: [], diagnostics: [] })).toBe(0);
    expect(scanExitCode({ verdict: 'pass', findings: [], diagnostics: [] })).toBe(0);
  });
});

describe('blastgate scan (runCli default)', () => {
  it('renders the ranked path and exits non-zero on a fail verdict', async () => {
    const { code, out } = await invoke(['.', '--base', 'HEAD'], failingFs());
    expect(code).not.toBe(0);
    expect(out).toContain('AWS_SECRET_ACCESS_KEY');
    expect(out).toContain('evil-pkg@1.0.0'); // the cross-layer postinstall path is shown
  });

  it('prints a pass line and exits 0 on a clean repo', async () => {
    const { code, out } = await invoke(['.'], cleanFs());
    expect(code).toBe(0);
    expect(out.toUpperCase()).toContain('PASS');
  });

  it('--json emits the full findings array as valid JSON', async () => {
    const { code, out } = await invoke(['.', '--base', 'HEAD', '--json'], failingFs());
    expect(code).not.toBe(0);
    const parsed = JSON.parse(out);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed.every((f: Finding) => f.sink && f.path && f.remediation)).toBe(true);
  });

  it('--format md emits a human-readable markdown report (not JSON), exits non-zero on fail', async () => {
    const { code, out } = await invoke(['.', '--base', 'HEAD', '--format', 'md'], failingFs());
    expect(code).not.toBe(0);
    expect(out).toMatch(/^#/m); // markdown headings
    expect(out).toMatch(/where this runs/i);
    expect(out).toContain('AWS_SECRET_ACCESS_KEY');
    expect(() => JSON.parse(out)).toThrow(); // it is a report, not the JSON array
  });

  it('--md is an alias for --format md', async () => {
    const { out } = await invoke(['.', '--base', 'HEAD', '--md'], failingFs());
    expect(out).toMatch(/^#/m);
    expect(out).toContain('AWS_SECRET_ACCESS_KEY');
  });

  it('--format markdown is accepted as well as md', async () => {
    const { out } = await invoke(['.', '--base', 'HEAD', '--format', 'markdown'], cleanFs());
    expect(out.toUpperCase()).toContain('PASS');
    expect(out).toMatch(/^#/m);
  });
});

describe('renderJson', () => {
  it('produces valid JSON of the findings array', () => {
    const json = renderJson({ verdict: 'pass', findings: [], diagnostics: [] });
    expect(JSON.parse(json)).toEqual([]);
  });
});

/** A reachable-secret finding for the markdown-report tests (AE1 install-script shape). */
function secretFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'entry:new-dep:evil-pkg=>sink:secret:AWS_SECRET_ACCESS_KEY',
    tier: 'fail',
    score: 311,
    path: [
      'added dependency evil-pkg@1.0.0',
      'evil-pkg@1.0.0',
      'ci.yml#test',
      'AWS_SECRET_ACCESS_KEY',
    ],
    pathNodeIds: ['entry:new-dep:evil-pkg', 'dep:evil-pkg@1.0.0', 'job:ci.yml#test', 'sink:secret'],
    hops: 3,
    entry: { kind: 'new-dependency', label: 'added dependency evil-pkg@1.0.0' },
    sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
    reason: 'install script executes in a fork job holding the secret',
    remediation: 'gate lifecycle scripts (npm ci --ignore-scripts)',
    owasp: { agentic: 'ASI04', mcp: 'MCP04' },
    labels: ['ASI04:2026', 'MCP04:2025'],
    ...overrides,
  };
}

describe('renderMarkdown (--format md report)', () => {
  it('renders a fail run: verdict badge, workflow guidance, the path, why, fix, and labels', () => {
    const result: GateResult = { verdict: 'fail', findings: [secretFinding()], diagnostics: [] };
    const md = renderMarkdown(result);
    expect(md).toContain('Blastgate');
    expect(md).toContain('FAIL');
    // "Where this runs" workflow guidance is embedded in the report (U9 / in-output guidance).
    expect(md).toMatch(/where this runs/i);
    // The full attacker→sink path is shown with arrows.
    expect(md).toContain('→');
    expect(md).toContain('evil-pkg@1.0.0');
    expect(md).toContain('AWS_SECRET_ACCESS_KEY');
    expect(md).toContain('install script executes');
    expect(md).toContain('gate lifecycle scripts');
    expect(md).toContain('ASI04:2026');
    // It is markdown, not the plain-text renderer.
    expect(md).toMatch(/^#/m);
  });

  it('renders a clean pass run with guidance and no scary FAIL badge', () => {
    const md = renderMarkdown({ verdict: 'pass', findings: [], diagnostics: [] });
    expect(md.toUpperCase()).toContain('PASS');
    expect(md).toMatch(/where this runs/i);
    // A clean report must not read like a failure.
    expect(md).not.toContain('blocks the gate');
    expect(md).not.toContain('❌');
  });

  it('labels a warn run as WARN, not FAIL', () => {
    const warn = secretFinding({
      tier: 'warn',
      sink: { kind: 'privileged-capability', identity: 'filesystem:/' },
      labels: ['ASI01:2026'],
    });
    const md = renderMarkdown({ verdict: 'warn', findings: [warn], diagnostics: [] });
    expect(md).toContain('WARN');
    expect(md).not.toMatch(/—.*FAIL/);
  });

  it('shows an acknowledged finding with its accepted reason', () => {
    const ack = secretFinding({
      tier: 'warn',
      acknowledged: 'reviewed 2026-08-05 — scoped, accepted by @you',
    });
    const md = renderMarkdown({ verdict: 'warn', findings: [ack], diagnostics: [] });
    expect(md).toContain('reviewed 2026-08-05');
  });

  it('marks an unknown (un-evaluable) run as blocking, not a pass', () => {
    const md = renderMarkdown({
      verdict: 'unknown',
      findings: [],
      diagnostics: [{ level: 'error', message: 'could not parse package-lock.json' }],
    });
    expect(md).toContain('UNKNOWN');
    expect(md).toMatch(/block/i);
    expect(md).toContain('could not parse package-lock.json');
  });
});

describe('hookOutput (gate mode payloads)', () => {
  const failResult = () => {
    const finding: Finding = {
      id: 'e=>s',
      tier: 'fail',
      score: 333,
      path: ['fork PR reaches job test', 'ci.yml#test', 'AWS_SECRET_ACCESS_KEY'],
      pathNodeIds: ['entry:fork-pr', 'job', 'sink'],
      hops: 2,
      entry: { kind: 'fork-pr', label: 'fork PR reaches job test' },
      sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
      reason: 'job is fork-triggerable and holds the secret',
      remediation: 'remove the secret from the untrusted job',
      owasp: { agentic: 'ASI03' },
      labels: ['ASI03:2026'],
    };
    return { verdict: 'fail' as const, findings: [finding], diagnostics: [] };
  };

  it('pre-commit on a reachable path emits a PreToolUse deny with the ranked-path reason', () => {
    const { stdout, exitCode } = hookOutput('pre-commit', failResult());
    const payload = JSON.parse(stdout);
    expect(payload.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('AWS_SECRET_ACCESS_KEY');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('remove the secret');
    expect(exitCode).toBe(0);
  });

  it('dependency-install emits a PostToolUse block (react-only), not a PreToolUse deny', () => {
    const { stdout } = hookOutput('dependency-install', failResult());
    const payload = JSON.parse(stdout);
    expect(payload.decision).toBe('block');
    expect(payload.reason).toContain('AWS_SECRET_ACCESS_KEY');
    expect(payload.hookSpecificOutput).toBeUndefined();
  });

  it('emits no deny/block on a clean (pass) result', () => {
    const clean = { verdict: 'pass' as const, findings: [], diagnostics: [] };
    expect(hookOutput('pre-commit', clean).stdout).toBe('');
    expect(hookOutput('dependency-install', clean).stdout).toBe('');
  });
});

describe('blastgate check --gate (runCli hook mode)', () => {
  it('pre-commit over the AE5 fixture emits a deny on stdout and exits 0', async () => {
    const hookJson = JSON.stringify({ tool_input: { command: 'git commit -m x' } });
    const { code, out } = await invoke(['check', '--gate', 'pre-commit'], failingFs(), hookJson);
    const payload = JSON.parse(out);
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('AWS_SECRET_ACCESS_KEY');
    expect(code).toBe(0);
  });

  it('pre-commit over a clean repo allows (no deny output)', async () => {
    const hookJson = JSON.stringify({ tool_input: { command: 'git commit -m x' } });
    const { code, out } = await invoke(['check', '--gate', 'pre-commit'], cleanFs(), hookJson);
    expect(out).toBe('');
    expect(code).toBe(0);
  });

  it('dependency-install over the AE5 fixture emits a PostToolUse block', async () => {
    const hookJson = JSON.stringify({ tool_input: { command: 'npm install evil-pkg' } });
    const { out } = await invoke(['check', '--gate', 'dependency-install'], failingFs(), hookJson);
    const payload = JSON.parse(out);
    expect(payload.decision).toBe('block');
  });
});
