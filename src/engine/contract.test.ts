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

  it('AE3: tools restricted to Bash(gh issue view:*) → warn naming the missing access leg', () => {
    const f = onKey(runEngine(claude({ args: '--allowedTools "Bash(gh issue view:*)"' })));
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

/**
 * 0062: a gh-aw-compiled job (github/gh-aw-actions/setup) runs its own runtime from
 * `${RUNNER_TEMP}/gh-aw` and `/tmp/gh-aw` after checking out the PR head. Those steps never
 * run PR code, so they are not 0048 execution evidence. A user's own step in that job is.
 */
describe('gh-aw runtime steps are not PR-code execution (0062)', () => {
  const ghAw = (extra: string[] = [], setup = true) =>
    gh([
      'on:',
      '  workflow_run:',
      "    workflows: ['trigger']",
      '    types: [completed]',
      'jobs:',
      '  agent:',
      '    steps:',
      ...(setup ? ['      - uses: github/gh-aw-actions/setup@v0.88.2'] : []),
      '      - uses: actions/checkout@v4',
      '        with:',
      '          persist-credentials: false',
      '      - run: git fetch origin "refs/pull/${PR_NUMBER}/head" && git checkout FETCH_HEAD',
      '      - run: bash "${RUNNER_TEMP}/gh-aw/actions/configure_git_credentials.sh"',
      '        env:',
      '          GH_TOKEN: ${{ secrets.GH_AW_GITHUB_TOKEN }}',
      '      - run: |',
      '          mkdir -p /tmp/gh-aw/safeoutputs',
      '          bash "${RUNNER_TEMP}/gh-aw/actions/run_awf.sh" -- awf -- copilot --prompt-file /tmp/gh-aw/prompt.txt',
      ...extra,
    ]);

  it('only gh-aw runtime steps after the PR checkout → no fail', () => {
    const result = runEngine(ghAw());
    expect(fails(result.findings)).toHaveLength(0);
  });

  it("a user's own step in the gh-aw job still runs PR code → fail", () => {
    const result = runEngine(ghAw(['      - run: npm ci']));
    expect(fails(result.findings).length).toBeGreaterThan(0);
  });

  it.each([
    ['bash "${RUNNER_TEMP}/gh-aw/actions/x.sh" && ./scripts/build.sh'],
    ['make test # see /tmp/gh-aw/ docs'],
    // PR #39 round-3 review: tokenizer bypasses fail closed at the engine level too.
    ['bash /tmp/gh-aw/r.sh; "./scripts/build.sh"'],
    ['bash /tmp/gh-aw/r.sh; echo `./scripts/build.sh`'],
  ])("a user's step that only mentions a gh-aw path still runs PR code → fail: %s", (run) => {
    const result = runEngine(ghAw([`      - run: '${run}'`]));
    expect(fails(result.findings).length).toBeGreaterThan(0);
  });

  it('the same gh-aw-path steps without gh-aw setup still count → fail', () => {
    const result = runEngine(ghAw([], false));
    expect(fails(result.findings).length).toBeGreaterThan(0);
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
