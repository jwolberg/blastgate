import { describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import type { EngineInputs } from './build';
import { runEngine } from './gate';

/**
 * 0048 / plan R1, R5, R7, R8, KTD5–KTD6: a finding is `fail` only when it is a proven
 * exploit — attacker input reaches an execution sink in a privileged job that holds a
 * secret or code-write access — and it carries its proof (file, line, capability,
 * payload). Everything else that is reachable is at most `warn`.
 */

const WF = '.github/workflows/t.yml';
const gh = (lines: string[]): EngineInputs => ({
  ci: { workflows: [{ path: WF, content: lines.join('\n') }] },
});
const issueJob = (steps: string[]): EngineInputs =>
  gh(['on:', '  issues:', 'jobs:', '  triage:', '    steps:', ...steps]);

const fails = (fs: Finding[]): Finding[] => fs.filter((f) => f.tier === 'fail');

describe('fail contract (0048)', () => {
  it('AE1: shell-interpolated issue title + secret in a later step → fail with full evidence', () => {
    const result = runEngine(
      issueJob([
        '      - run: echo "${{ github.event.issue.title }}"', // 6
        '      - run: ./deploy.sh', // 7
        '        env:', // 8
        '          K: ${{ secrets.DEPLOY_KEY }}', // 9
      ]),
    );
    const f = fails(result.findings).find((x) => x.sink.identity === 'DEPLOY_KEY');
    expect(f, 'a fail on DEPLOY_KEY').toBeDefined();
    expect(f!.evidence?.file).toBe(WF);
    expect(f!.evidence?.line).toBe(6);
    expect(f!.evidence?.capability).toBe('DEPLOY_KEY');
    expect(f!.evidence?.payload?.length).toBeGreaterThan(0);
  });

  it('AE3: shell interpolation but only a pull-requests: write token → warn', () => {
    const result = runEngine(
      gh([
        'on:',
        '  pull_request_target:',
        'permissions:',
        '  pull-requests: write',
        'jobs:',
        '  label:',
        '    steps:',
        '      - run: echo "${{ github.event.pull_request.title }}"',
      ]),
    );
    expect(result.findings.length).toBeGreaterThan(0);
    expect(fails(result.findings)).toHaveLength(0);
    expect(result.verdict).toBe('warn');
  });

  it('AE4: a coding agent reading an issue comment with an API key → warn naming agent ingestion', () => {
    const result = runEngine(
      gh([
        'on:',
        '  issue_comment:',
        'jobs:',
        '  agent:',
        '    steps:',
        '      - uses: anthropics/claude-code-action@v1',
        '        with:',
        '          prompt: ${{ github.event.comment.body }}',
        '        env:',
        '          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
      ]),
    );
    const f = result.findings.find((x) => x.sink.identity === 'ANTHROPIC_API_KEY');
    expect(f?.tier).toBe('warn');
    expect(f?.reason.toLowerCase()).toContain('agent');
  });

  it('AE5: issue title into a third-party action input with a webhook secret → warn', () => {
    const result = runEngine(
      issueJob([
        '      - uses: some/notify-action@v1',
        '        with:',
        '          text: ${{ github.event.issue.title }}',
        '          webhook: ${{ secrets.DINGTALK_WEBHOOK }}',
      ]),
    );
    const f = result.findings.find((x) => x.sink.identity === 'DINGTALK_WEBHOOK');
    expect(f?.tier).toBe('warn');
    expect(f?.evidence?.payload).toBeUndefined();
  });

  const forkJob = (afterCheckout: string[]): EngineInputs =>
    gh([
      'on:',
      '  pull_request_target:',
      'jobs:',
      '  test:',
      '    steps:',
      '      - uses: actions/checkout@v4', // 6
      '        with:', // 7
      '          ref: ${{ github.event.pull_request.head.sha }}', // 8
      ...afterCheckout,
    ]);

  it('fork PR: untrusted checkout then npm test holding AWS key → fail, evidence at npm test', () => {
    const result = runEngine(
      forkJob([
        '      - run: npm test', // 9
        '        env:',
        '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
      ]),
    );
    const f = fails(result.findings).find((x) => x.entry.kind === 'fork-pr');
    expect(f).toBeDefined();
    expect(f!.evidence?.line).toBe(9);
    expect(f!.evidence?.capability).toBe('AWS_SECRET_ACCESS_KEY');
  });

  it('fork PR: nothing runs after the untrusted checkout → warn (no proven execution)', () => {
    const result = runEngine(
      gh([
        'on:',
        '  pull_request_target:',
        'jobs:',
        '  test:',
        '    steps:',
        '      - uses: some/lint-action@v1',
        '        env:',
        '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
      ]),
    );
    expect(result.findings.some((f) => f.entry.kind === 'fork-pr')).toBe(true);
    expect(fails(result.findings)).toHaveLength(0);
  });

  it('install script in a fork-triggerable job → fail, evidence at the install step', () => {
    const lock = (withDep: boolean): string =>
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          ...(withDep
            ? { 'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true } }
            : {}),
        },
      });
    const inputs = forkJob([
      '      - run: npm ci', // 9
      '        env:',
      '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
    ]);
    inputs.deps = { headLockfile: lock(true), baseLockfile: lock(false) };
    const f = fails(runEngine(inputs).findings).find((x) => x.entry.kind === 'new-dependency');
    expect(f).toBeDefined();
    expect(f!.evidence?.line).toBe(9);
    expect(f!.evidence?.payload?.length).toBeGreaterThan(0);
  });

  it('GitLab MR-triggerable job holding a secret → fail, evidence at the job definition', () => {
    const result = runEngine({
      gitlabci: {
        content: [
          'stages: [test]', // 1
          '', // 2
          'deploy:', // 3
          '  script:', // 4
          '    - echo "$AWS_SECRET_ACCESS_KEY" > /tmp/creds', // 5
          '  rules:', // 6
          `    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'`, // 7
        ].join('\n'),
      },
    });
    const f = fails(result.findings)[0];
    expect(f).toBeDefined();
    expect(f!.evidence).toMatchObject({ file: '.gitlab-ci.yml', line: 3 });
  });

  it('an acknowledged fail becomes warn but keeps its evidence', () => {
    const inputs = issueJob([
      '      - run: echo "${{ github.event.issue.title }}"',
      '        env:',
      '          K: ${{ secrets.DEPLOY_KEY }}',
    ]);
    const id = fails(runEngine(inputs).findings)[0]!.id;
    const acked = runEngine({ ...inputs, acknowledged: [{ id, reason: 'accepted risk' }] });
    const f = acked.findings.find((x) => x.id === id);
    expect(f?.tier).toBe('warn');
    expect(f?.evidence?.line).toBe(6);
  });

  it('no fail finding anywhere lacks complete evidence', () => {
    const result = runEngine(
      issueJob([
        '      - run: echo "${{ github.event.issue.body }}"',
        '        env:',
        '          A: ${{ secrets.ONE }}',
        '          B: ${{ secrets.TWO_TOKEN }}',
      ]),
    );
    expect(fails(result.findings).length).toBeGreaterThan(0);
    for (const f of fails(result.findings)) {
      expect(f.evidence?.file).toBeTruthy();
      expect(f.evidence?.line).toBeGreaterThan(0);
      expect(f.evidence?.capability).toBeTruthy();
      expect(f.evidence?.payload).toBeTruthy();
    }
  });

  it('a warn finding on the same path never carries a payload', () => {
    // Same artifact splice reaches a secret (fail) and a PR-only token (warn).
    const result = runEngine(
      gh([
        'on:',
        '  workflow_run:',
        "    workflows: ['CI']",
        'permissions:',
        '  pull-requests: write',
        'jobs:',
        '  comment:',
        '    steps:',
        '      - uses: actions/download-artifact@v4',
        '      - run: gh pr comment $(<PRurl)',
        '        env:',
        '          T: ${{ secrets.GH_SESSION }}',
      ]),
    );
    const warn = result.findings.find((f) => f.sink.identity.startsWith('GITHUB_TOKEN'));
    expect(warn?.tier).toBe('warn');
    expect(warn?.evidence?.line).toBe(10);
    expect(warn?.evidence?.payload).toBeUndefined();
    expect(fails(result.findings)[0]?.evidence?.payload).toBeTruthy();
  });
});

/**
 * Agent-in-CI U5 (0059; R6, R7, R9, R10; KTD6): an agent path fails only when all three
 * Rule-of-Two legs hold, the profile covers the version, and the path's sink is a
 * credential the agent can read. Every other agent finding warns, naming each leg.
 */
describe('agent verdict (0059)', () => {
  const claude = (opts: { bypass?: boolean; args?: string; scrubOff?: boolean; ref?: string }) =>
    gh([
      'on: issue_comment', // 1
      'permissions:', // 2
      '  issues: write', // 3
      'jobs:', // 4
      '  claude:', // 5
      '    steps:', // 6
      `      - uses: anthropics/claude-code-action@${opts.ref ?? 'v1'}`, // 7
      '        env:',
      `          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: ${opts.scrubOff === false ? 1 : 0}`,
      '        with:',
      '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
      '          github_token: ${{ secrets.GITHUB_TOKEN }}',
      ...(opts.bypass === false ? [] : ["          allowed_non_write_users: '*'"]),
      `          claude_args: '${opts.args ?? '--allowedTools Bash'}'`,
    ]);
  const onKey = (r: ReturnType<typeof runEngine>) =>
    r.findings.find((f) => f.sink.identity === 'ANTHROPIC_API_KEY');

  it('AE1: claude bypass *, Bash, scrub off, API key → fail with evidence at the agent step', () => {
    const f = onKey(runEngine(claude({})));
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.file).toBe(WF);
    expect(f?.evidence?.line).toBe(7);
    expect(f?.evidence?.capability).toBe('ANTHROPIC_API_KEY');
    expect(f?.evidence?.payload).toContain('attacker.example');
  });

  it('AE2: without the bypass → warn naming indirect injection', () => {
    const f = onKey(runEngine(claude({ bypass: false })));
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toMatch(/indirect/i);
    expect(f?.evidence?.payload).toBeUndefined();
  });

  it('0084: a scoped Bash(gh issue view:*) cannot expand the API key in claude → warn, not fail', () => {
    // Claude Code denies any command containing a variable, even under a matching wildcard rule
    // (verified on CLI 2.1.287); supersedes the docs-only 0063 reading.
    const f = onKey(runEngine(claude({ args: '--allowedTools "Bash(gh issue view:*)"' })));
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toMatch(/sensitive access: missing/i);
  });

  it('0064: an exact-match Bash(npm test) with the scrub off and a key in env → no fail', () => {
    const f = onKey(runEngine(claude({ args: '--allowedTools "Bash(npm test)"' })));
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toMatch(/sensitive access: missing/i);
  });

  it('AE5: a pinned version outside every profile → warn naming the version', () => {
    const f = onKey(runEngine(claude({ ref: 'v0.0.17' })));
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toContain('v0.0.17');
  });

  it('scrub default: the scrubbed API key warns while the persisted code-write token fails', () => {
    const result = runEngine(
      gh([
        'on: issue_comment',
        'permissions:',
        '  contents: write',
        'jobs:',
        '  claude:',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '      - uses: anthropics/claude-code-action@v1', // 8
        '        with:',
        '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
        '          github_token: ${{ secrets.GITHUB_TOKEN }}',
        "          allowed_non_write_users: '*'",
        "          claude_args: '--allowedTools Bash'",
      ]),
    );
    expect(onKey(result)?.tier).toBe('warn');
    const token = result.findings.find((f) => f.sink.identity.startsWith('GITHUB_TOKEN'));
    expect(token?.tier).toBe('fail');
    expect(token?.evidence?.line).toBe(8);
  });

  it('a warn reason names each leg as held, missing, or unknown (R10)', () => {
    const f = onKey(runEngine(claude({ bypass: false })));
    expect(f?.reason).toMatch(/direct trigger: missing/i);
    expect(f?.reason).toMatch(/sensitive access: held/i);
    expect(f?.reason).toMatch(/exfiltration: held/i);
  });

  it('a tool-less LLM step never fails (R8)', () => {
    const result = runEngine(
      gh([
        'on: issues',
        'permissions:',
        '  contents: write',
        'jobs:',
        '  label:',
        '    steps:',
        '      - uses: actions/ai-inference@v2',
        '        with:',
        '          prompt: ${{ github.event.issue.body }}',
        '          token: ${{ secrets.MODELS_PAT }}',
      ]),
    );
    expect(result.findings.length).toBeGreaterThan(0);
    expect(fails(result.findings)).toHaveLength(0);
  });

  it('no agent finding fails without all three legs recorded as held (sweep)', () => {
    let sawFail = false;
    for (const bypass of [true, false]) {
      for (const args of [
        '--allowedTools Bash',
        '--allowedTools Read',
        '--allowedTools "Bash(gh issue view:*)"',
      ]) {
        for (const scrubOff of [true, false]) {
          for (const ref of ['v1', 'v0.0.17', 'main']) {
            for (const f of fails(runEngine(claude({ bypass, args, scrubOff, ref })).findings)) {
              sawFail = true;
              expect(f.reason).toMatch(/direct trigger: held/);
              expect(f.reason).toMatch(/sensitive access: held/);
              expect(f.reason).toMatch(/exfiltration: held/);
              expect(f.evidence?.payload).toBeTruthy();
            }
          }
        }
      }
    }
    expect(sawFail).toBe(true);
  });

  // Hardened counterparts of the U6 incident fixtures (R11, KTD8): each warns or passes.
  const promptPwnd = (cliVersion: string) =>
    gh([
      'on:',
      '  issues:',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  triage:',
      '    steps:',
      '      - uses: google-github-actions/run-gemini-cli@v0.1.21',
      '        env:',
      '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
      '        with:',
      '          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}',
      `          gemini_cli_version: '${cliVersion}'`,
      `          settings: '{"tools":{"core":["run_shell_command(gh issue edit)"]}}'`,
      '          prompt: ${{ github.event.issue.body }}',
    ]);

  it('PromptPwnd hardened: a patched Gemini CLI enforces the gh-only allowlist → warn', () => {
    // An old CLI auto-trusts the repo's .gemini/settings.json, so its tools are unknown → warn.
    expect(fails(runEngine(promptPwnd('0.38.0')).findings)).toHaveLength(0);
    const hardened = runEngine(promptPwnd('latest'));
    expect(hardened.findings.length).toBeGreaterThan(0);
    expect(fails(hardened.findings)).toHaveLength(0);
  });

  it('gemini OIDC hardened: an author_association guard → no fail', () => {
    const result = runEngine(
      gh([
        'on:',
        '  issues:',
        'permissions:',
        '  id-token: write',
        'jobs:',
        '  triage:',
        '    if: contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.issue.author_association)',
        '    steps:',
        '      - uses: google-github-actions/run-gemini-cli@v0',
        '        with:',
        '          gcp_workload_identity_provider: ${{ vars.GCP_WIF_PROVIDER }}',
        '          prompt: Triage this issue.',
      ]),
    );
    expect(fails(result.findings)).toHaveLength(0);
  });

  it('an acknowledged agent fail → warn with evidence kept', () => {
    const inputs = claude({});
    const id = onKey(runEngine(inputs))!.id;
    const acked = runEngine({ ...inputs, acknowledged: [{ id, reason: 'accepted risk' }] });
    const f = acked.findings.find((x) => x.id === id);
    expect(f?.tier).toBe('warn');
    expect(f?.evidence?.line).toBe(7);
  });
});

/** PR #39 review fixes at the engine level. */
describe('agent verdict — PR #39 review fixes', () => {
  it('a secret held only by another step never fails on the agent path', () => {
    const result = runEngine(
      gh([
        'on: issue_comment',
        'jobs:',
        '  claude:',
        '    steps:',
        '      - uses: anthropics/claude-code-action@v1',
        '        env:',
        '          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0',
        '        with:',
        '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
        '          github_token: ${{ secrets.GITHUB_TOKEN }}',
        "          allowed_non_write_users: '*'",
        "          claude_args: '--allowedTools Bash'",
        '      - run: ./deploy.sh',
        '        env:',
        '          DEPLOY: ${{ secrets.DEPLOY_KEY }}',
      ]),
    );
    expect(result.findings.find((f) => f.sink.identity === 'ANTHROPIC_API_KEY')?.tier).toBe('fail');
    expect(result.findings.find((f) => f.sink.identity === 'DEPLOY_KEY')?.tier).toBe('warn');
  });

  it('a tool-less LLM step ahead of a fail-capable agent does not mask its fail', () => {
    const result = runEngine(
      gh([
        'on: issue_comment',
        'jobs:',
        '  triage:',
        '    steps:',
        '      - uses: actions/ai-inference@v2',
        '        with:',
        '          prompt: ${{ github.event.comment.body }}',
        '      - uses: anthropics/claude-code-action@v1', // 8
        '        env:',
        '          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0',
        '        with:',
        '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
        '          github_token: ${{ secrets.GITHUB_TOKEN }}',
        "          allowed_non_write_users: '*'",
        "          claude_args: '--allowedTools Bash'",
      ]),
    );
    const f = result.findings.find((x) => x.sink.identity === 'ANTHROPIC_API_KEY');
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.line).toBe(8);
  });
});

/**
 * 0067: an agent job on `workflow_run` whose upstream workflow (by `name:`, transitively)
 * starts on attacker-authored text ingests that text by design (it fetches the issue it is
 * handed), so it is judged against the Rule of Two with the relayed events as its trigger.
 */
describe('agent steps reached through a workflow_run relay (0067)', () => {
  const upstream = (on: string[]) => ({
    path: '.github/workflows/triage.yml',
    content: [
      'name: Issue Triage',
      'on:',
      ...on,
      'jobs:',
      '  capture:',
      '    steps:',
      '      - run: echo ok',
    ].join('\n'),
  });
  const relay = (withLines: string[], workflows = 'Issue Triage', name = 'Issue Triage Run') => ({
    path: '.github/workflows/triage-run.yml',
    content: [
      `name: ${name}`,
      'on:',
      '  workflow_run:',
      `    workflows: ["${workflows}"]`,
      '    types: [completed]',
      'permissions:',
      '  issues: write',
      'jobs:',
      '  triage:',
      '    steps:',
      '      - uses: anthropics/claude-code-action@v1', // 11
      '        env:',
      '          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0',
      '        with:',
      '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
      '          github_token: ${{ secrets.GITHUB_TOKEN }}',
      ...withLines.map((l) => `          ${l}`),
    ].join('\n'),
  });
  const keyFinding = (wfs: { path: string; content: string }[]) =>
    runEngine({ ci: { workflows: wfs } }).findings.find(
      (f) => f.sink.identity === 'ANTHROPIC_API_KEY',
    );
  const BYPASS = ["allowed_non_write_users: '*'", "claude_args: '--allowedTools Bash'"];

  it('an issues-triggered upstream relayed to a bypassed claude with Bash → fail at the agent step', () => {
    const f = keyFinding([upstream(['  issues:', '    types: [opened]']), relay(BYPASS)]);
    expect(f?.tier).toBe('fail');
    expect(f?.evidence).toMatchObject({ file: '.github/workflows/triage-run.yml', line: 11 });
    expect(f?.reason).toMatch(/workflow_run/);
  });

  it('a named allowed_bots relay (pytorch claude-issue-triage-run shape) → warn, direct missing', () => {
    const f = keyFinding([
      upstream(['  issues:', '    types: [opened]']),
      relay(["allowed_bots: 'pytorch-bot'", "claude_args: '--allowedTools Bash'"]),
    ]);
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toMatch(/direct trigger: missing/i);
  });

  it('an upstream that only runs on push relays no attacker text → no finding', () => {
    expect(keyFinding([upstream(['  push:']), relay(BYPASS)])).toBeUndefined();
  });

  it('a two-hop chain (issues → run → downstream) still relays the text', () => {
    const middle = { ...relay([]), path: '.github/workflows/mid.yml' };
    middle.content = middle.content
      .replace('jobs:', 'jobs:')
      .replace(/ {6}- uses:[\s\S]*$/, '      - run: echo ok');
    const downstream = relay(BYPASS, 'Issue Triage Run', 'Downstream');
    downstream.path = '.github/workflows/down.yml';
    const f = keyFinding([upstream(['  issues:', '    types: [opened]']), middle, downstream]);
    expect(f?.tier).toBe('fail');
  });

  it('a workflow_run cycle terminates', () => {
    const a = relay(BYPASS, 'B', 'A');
    const b = { ...relay(BYPASS, 'A', 'B'), path: '.github/workflows/b.yml' };
    expect(() => runEngine({ ci: { workflows: [a, b] } })).not.toThrow();
    expect(keyFinding([a, b])).toBeUndefined();
  });
});

/** 0068: a fork-PR warn says which proof is missing instead of claiming exfiltration. */
describe('fork-PR warn reasons name the missing proof (0068)', () => {
  const fork = (afterCheckout: string[], perms: string[] = []) =>
    gh([
      'on:',
      '  pull_request_target:',
      ...perms,
      'jobs:',
      '  test:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      ...afterCheckout,
    ]);

  it('checkout but no step that runs it → warn saying no execution was found', () => {
    const f = runEngine(
      fork([
        '      - uses: some/lint-action@v1',
        '        env:',
        '          K: ${{ secrets.DEPLOY_KEY }}',
      ]),
    ).findings.find((x) => x.sink.identity === 'DEPLOY_KEY');
    expect(f?.tier).toBe('warn');
    expect(f?.reason).not.toMatch(/exfiltratable/);
    expect(f?.reason).toMatch(/no later step/i);
  });

  it('PR code runs but the token only writes PRs → warn naming the privileged capability', () => {
    const f = runEngine(
      fork(['      - run: npm test'], ['permissions:', '  pull-requests: write']),
    ).findings.find((x) => x.sink.identity.startsWith('GITHUB_TOKEN'));
    expect(f?.tier).toBe('warn');
    expect(f?.reason).not.toMatch(/exfiltratable/);
    expect(f?.reason).toMatch(/privileged capability/i);
  });

  it('PR code runs with a secret → fail, reason says the PR code can read it', () => {
    const f = runEngine(
      fork(['      - run: npm test', '        env:', '          K: ${{ secrets.DEPLOY_KEY }}']),
    ).findings.find((x) => x.sink.identity === 'DEPLOY_KEY');
    expect(f?.tier).toBe('fail');
    expect(f?.reason).toMatch(/runs PR code/i);
  });
});

/**
 * 0096: the report's `at:` line is the step that runs the PR's code (its `run:` line), the
 * secret is cited where the job exposes it, and steps that only run git or shell builtins
 * do not count as running PR code.
 */
describe('evidence names the executing step and the secret exposure (0096)', () => {
  const fork = (afterCheckout: string[], on: string[] = ['  pull_request_target:']) =>
    gh([
      'on:', // 1
      ...on,
      'jobs:',
      '  test:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      ...afterCheckout,
    ]);
  const keyFinding = (inputs: EngineInputs): Finding | undefined =>
    runEngine(inputs).findings.find((x) => x.sink.identity === 'DEPLOY_KEY');

  it('skips a git-only step and cites the run: line of the step that builds the PR', () => {
    const f = keyFinding(
      fork([
        '      - name: Sync with base', // 9
        '        run: |', // 10
        '          git remote add upstream https://example.invalid/base.git', // 11
        '          git fetch upstream', // 12
        '          git checkout -B main upstream/main && git checkout -', // 13
        '      - uses: actions/setup-java@v4', // 14
        '      - name: Build', // 15
        '        run: ./gradlew check', // 16
        '        env:', // 17
        '          DEPLOY: ${{ secrets.DEPLOY_KEY }}', // 18
      ]),
    );
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.line).toBe(16);
    expect(f?.reason).toContain(`${WF}:16`);
    expect(f?.reason).toContain(`exposed at ${WF}:18`);
  });

  it('cites the step that runs build tooling over an earlier step it cannot prove inert', () => {
    const f = keyFinding(
      fork([
        '      - run: echo "${{ steps.meta.outputs.label }}"', // 9
        '      - run: npm test', // 10
        '        env:', // 11
        '          DEPLOY: ${{ secrets.DEPLOY_KEY }}', // 12
      ]),
    );
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.line).toBe(10);
  });

  it('falls back to the first step it cannot prove inert when nothing runs build tooling', () => {
    const f = keyFinding(
      fork([
        '      - run: echo "${{ steps.meta.outputs.label }}"', // 9
        '      - uses: some/lint-action@v1', // 10
        '        env:', // 11
        '          K: ${{ secrets.DEPLOY_KEY }}', // 12
      ]),
    );
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.line).toBe(9);
  });

  it('a job whose steps after the checkout only run git and builtins is not a fail', () => {
    const f = keyFinding(
      fork([
        '      - run: |',
        '          git log -1 --format=%H',
        '          echo "done" && date',
        '      - uses: some/lint-action@v1',
        '        env:',
        '          K: ${{ secrets.DEPLOY_KEY }}',
      ]),
    );
    expect(f?.tier).toBe('warn');
    expect(f?.reason).toMatch(/no later step/i);
  });

  it('a builtin that runs a command substitution still counts as running PR code', () => {
    const f = keyFinding(
      fork([
        '      - run: echo "$(./scripts/version.sh)"',
        '        env:',
        '          K: ${{ secrets.DEPLOY_KEY }}',
      ]),
    );
    expect(f?.tier).toBe('fail');
  });

  it('names only the untrusted triggers, not push', () => {
    const f = keyFinding(
      fork(
        ['      - run: npm test', '        env:', '          K: ${{ secrets.DEPLOY_KEY }}'],
        ['  push:', '    branches: [main]', '  pull_request_target:'],
      ),
    );
    expect(f?.tier).toBe('fail');
    expect(f?.reason).toContain('(pull_request_target)');
    expect(f?.reason).not.toMatch(/\bpush\b/);
  });

  it('a shell injection cites where a later step is handed the secret', () => {
    const f = runEngine(
      issueJob([
        '      - run: echo "${{ github.event.issue.title }}"', // 6
        '      - uses: some/assistant-action@v1', // 7
        '        with:', // 8
        '          api_key: ${{ secrets.DEPLOY_KEY }}', // 9
      ]),
    ).findings.find((x) => x.sink.identity === 'DEPLOY_KEY');
    expect(f?.tier).toBe('fail');
    expect(f?.evidence?.line).toBe(6);
    expect(f?.reason).toContain(`exposed at ${WF}:9`);
  });
});

/**
 * 0097: a quoted artifact read used only in a string comparison is not injection, even when
 * later quoting (quotes inside a `$( )` inside double quotes) is complex; and a workflow_run
 * job gated to push-triggered upstream runs is not reachable by an outsider.
 */
describe('artifact comparisons and push-only workflow_run (0097)', () => {
  const artifactJob = (script: string[], jobIf: string[] = []) =>
    gh([
      'on:',
      '  workflow_run:',
      '    workflows: [CI]',
      '    types: [completed]',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  publish:',
      ...jobIf,
      '    steps:',
      '      - uses: actions/download-artifact@v4',
      '      - run: |',
      ...script.map((l) => `          ${l}`),
      '        env:',
      '          K: ${{ secrets.DEPLOY_KEY }}',
    ]);
  const LATER_NESTED_QUOTES =
    'NAME="$(grep -m1 title meta.txt | sed \'s/.*"\\([^"]*\\)".*/\\1/\')"';
  const keyFail = (inputs: EngineInputs): Finding | undefined =>
    fails(runEngine(inputs).findings).find((x) => x.sink.identity === 'DEPLOY_KEY');

  it('a quoted $(< file) compared in [[ ]] is not a splice, despite later nested quotes', () => {
    expect(
      keyFail(artifactJob(['[[ "$(< ref.txt)" == "$EXPECTED" ]]', LATER_NESTED_QUOTES])),
    ).toBeUndefined();
  });

  it('control: an unquoted splice is still a fail after the same nested quotes', () => {
    expect(
      keyFail(artifactJob([LATER_NESTED_QUOTES, 'gh pr comment $(<pr.txt) --body ok'])),
    ).toBeDefined();
  });

  const forkRun = (jobIf: string[]) =>
    gh([
      'on:',
      '  workflow_run:',
      '    workflows: [CI]',
      '    types: [completed]',
      '  workflow_dispatch:',
      'jobs:',
      '  build:',
      ...jobIf,
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.workflow_run.head_sha }}',
      '      - run: npm ci',
      '        env:',
      '          K: ${{ secrets.DEPLOY_KEY }}',
    ]);

  it('control: an ungated workflow_run job that runs the head commit fails', () => {
    expect(keyFail(forkRun([]))).toBeDefined();
  });

  it('a job gated to push-triggered upstream runs is not a fail', () => {
    expect(keyFail(forkRun(["    if: github.event.workflow_run.event == 'push'"]))).toBeUndefined();
  });

  it('every branch of the if: excluding outsiders (dispatch, or push-only run) is not a fail', () => {
    expect(
      keyFail(
        forkRun([
          '    if: >-',
          "      (github.event_name == 'workflow_dispatch') ||",
          "      (github.event.workflow_run.conclusion == 'success' &&",
          "       github.event.workflow_run.event == 'push')",
        ]),
      ),
    ).toBeUndefined();
  });

  it('one branch that lets a pull_request run through still fails', () => {
    expect(
      keyFail(
        forkRun([
          "    if: github.event.workflow_run.event == 'push' || github.event.workflow_run.conclusion == 'success'",
        ]),
      ),
    ).toBeDefined();
  });

  it.each([
    "github.event.workflow_run.event != 'pull_request'",
    "!(github.event.workflow_run.event == 'pull_request')",
    "always() || github.event.workflow_run.event == 'push'",
    "github.event.workflow_run.event == 'push' || true",
  ])('an if: that does not prove a push-only run still fails: %s', (cond) => {
    expect(keyFail(forkRun([`    if: ${cond}`]))).toBeDefined();
  });

  it('a ${{ }}-wrapped push-only gate is not a fail', () => {
    expect(
      keyFail(forkRun(["    if: ${{ github.event.workflow_run.event == 'push' }}"])),
    ).toBeUndefined();
  });

  it('a branches: filter alone does not gate (a fork can name its branch main)', () => {
    const inputs = forkRun([]);
    const content = inputs.ci!.workflows[0]!.content.replace(
      '    types: [completed]',
      '    types: [completed]\n    branches: [main]',
    );
    expect(keyFail({ ci: { workflows: [{ path: WF, content }] } })).toBeDefined();
  });
});
