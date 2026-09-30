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
