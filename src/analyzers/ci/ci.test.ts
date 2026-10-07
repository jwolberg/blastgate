import { describe, expect, it } from 'vitest';
import { analyzeCi } from './index';
import {
  isPinnedAction,
  normalizeTriggers,
  resolvePermissions,
  runsWorkspaceCode,
  untrustedTriggers,
  type JobSpec,
  type StepSpec,
  type WorkflowSpec,
} from './parse';

// The canonical cross-layer path: the dangerous fork-triggerable event is
// `pull_request_target` (base-repo context, so secrets + a writable token are present).
// A plain `pull_request` fork job gets a read-only token and no secrets — see the
// dedicated "read-only token" test below.
const AE1 = [
  'on:',
  '  pull_request_target:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - uses: actions/checkout@v4',
  '        with:',
  '          ref: ${{ github.event.pull_request.head.sha }}',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');

const AE2 = ['on:', '  push:', 'jobs:', '  build:', '    steps:', '      - run: npm ci'].join('\n');

describe('trigger normalization', () => {
  it('normalizes string, array and map on: forms', () => {
    expect(normalizeTriggers('push')).toEqual(['push']);
    expect(normalizeTriggers(['push', 'pull_request'])).toEqual(['push', 'pull_request']);
    expect(normalizeTriggers({ pull_request_target: null, workflow_dispatch: null })).toEqual([
      'pull_request_target',
      'workflow_dispatch',
    ]);
  });

  it('flags only the untrusted trigger set', () => {
    expect(untrustedTriggers(['push', 'pull_request_target'])).toEqual(['pull_request_target']);
  });
});

describe('isPinnedAction', () => {
  it('treats a 40-hex SHA as pinned and a tag as unpinned', () => {
    expect(isPinnedAction(`actions/checkout@${'a'.repeat(40)}`)).toBe(true);
    expect(isPinnedAction('actions/checkout@v4')).toBe(false);
    expect(isPinnedAction('./.github/actions/local')).toBe(true);
  });
});

describe('analyzeCi', () => {
  it('emits a fork-triggerable secret-bearing job with sink and entry (AE1 shape)', () => {
    const r = analyzeCi({ workflows: [{ path: '.github/workflows/ci.yml', content: AE1 }] });
    const job = r.nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.forkTriggerable).toBe(true);
    expect(r.nodes.some((n) => n.kind === 'sink' && n.identity === 'AWS_SECRET_ACCESS_KEY')).toBe(
      true,
    );
    expect(r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'holds')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'triggers')).toBe(true);
    expect(r.diagnostics.some((d) => d.message.includes('pwn-request'))).toBe(true);
    expect(r.diagnostics.some((d) => d.message.includes('unpinned'))).toBe(true);
  });

  it('tags every ci-job node with its provider (github) for multi-provider support', () => {
    const r = analyzeCi({ workflows: [{ path: '.github/workflows/ci.yml', content: AE1 }] });
    const job = r.nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.provider).toBe('github');
  });

  it('emits no entry or sink for a secretless, non-fork job (AE2 shape)', () => {
    const r = analyzeCi({ workflows: [{ path: 'ci.yml', content: AE2 }] });
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'sink')).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'ci-job')).toBe(true);
  });

  it('does not treat a plain fork pull_request job as credential-reachable (read-only token, no secrets)', () => {
    // GitHub runs fork PRs on `pull_request` with a READ-ONLY GITHUB_TOKEN and withholds
    // repo secrets, so a write permission or `secrets.X` in a pull_request-only job is NOT
    // reachable by a fork. Treating it as a fork-pr entry was the false positive — a declared
    // permission mistaken for a reachable path. Only privileged events reach a credential.
    const forkPr = [
      'on:',
      '  pull_request:',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  j:',
      '    steps:',
      '      - run: gh pr checkout 123',
      '      - run: echo ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
    ].join('\n');
    const r = analyzeCi({ workflows: [{ path: 'w', content: forkPr }] });
    const job = r.nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.forkTriggerable).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(false);
    expect(r.diagnostics.some((d) => d.message.includes('pwn-request'))).toBe(false);

    // The SAME job on `pull_request_target` runs privileged (base-repo context) → reachable.
    const target = forkPr.replace('  pull_request:', '  pull_request_target:');
    const r2 = analyzeCi({ workflows: [{ path: 'w', content: target }] });
    expect(r2.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(true);
  });

  it('does not report an injection→credential path on a plain fork pull_request (read-only token)', () => {
    // An injection into a plain `pull_request` job is a code-execution risk on the runner,
    // but the token is read-only and no secrets are present — it is NOT a credential
    // exfiltration path (the sink we model), so it must not create an injection entry.
    const injecting = (event: string): string =>
      [
        'on:',
        `  ${event}:`,
        'jobs:',
        '  j:',
        '    steps:',
        '      - uses: anthropics/claude-code-action@v1',
        '        env:',
        '          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
      ].join('\n');
    const isInjEntry = (r: ReturnType<typeof analyzeCi>): boolean =>
      r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'untrusted-text-injection');
    expect(
      isInjEntry(analyzeCi({ workflows: [{ path: 'w', content: injecting('pull_request') }] })),
    ).toBe(false);
    // A privileged untrusted-text event (issue_comment) DOES carry secrets → injection path stands.
    expect(
      isInjEntry(analyzeCi({ workflows: [{ path: 'w', content: injecting('issue_comment') }] })),
    ).toBe(true);
  });

  it('gates the fork-pr credential entry on an untrusted PR-head checkout (0041)', () => {
    // A privileged label bot (github-script on event metadata, a writable token + secret, but
    // NO untrusted checkout) is the safe, standard pattern — attacker code can never run, so it
    // is not a finding. This is the 14/16 false-positive class the top-25 assessment surfaced.
    const mk = (checkoutStep: string[]): string =>
      [
        'on:',
        '  pull_request_target:',
        'permissions:',
        '  pull-requests: write',
        'jobs:',
        '  label:',
        '    steps:',
        ...checkoutStep,
        '      - uses: actions/github-script@v7',
        '        env:',
        '          T: ${{ secrets.MY_SECRET }}',
      ].join('\n');
    const bot = analyzeCi({ workflows: [{ path: 'w', content: mk([]) }] });
    const botJob = bot.nodes.find((n) => n.kind === 'ci-job');
    expect(botJob && botJob.kind === 'ci-job' && botJob.forkTriggerable).toBe(false);
    expect(bot.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(false);

    // Add an untrusted PR-head checkout → attacker code can run → it IS a finding.
    const dangerous = analyzeCi({
      workflows: [{ path: 'w', content: mk(['      - run: gh pr checkout 123']) }],
    });
    expect(dangerous.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(true);
  });

  it('flags workflow_run artifact injection but not a safe artifact consumer (0042)', () => {
    const mk = (runLine: string): string =>
      [
        'on:',
        '  workflow_run:',
        "    workflows: ['CI']",
        '    types: [completed]',
        'permissions:',
        '  pull-requests: write',
        'jobs:',
        '  comment:',
        '    steps:',
        '      - uses: actions/download-artifact@v4',
        `      - run: ${runLine}`,
        '        env:',
        '          T: ${{ secrets.GH_SESSION }}',
      ].join('\n');
    const hasInj = (content: string): boolean =>
      analyzeCi({ workflows: [{ path: 'w', content }] }).nodes.some(
        (n) => n.kind === 'entry' && n.entryKind === 'untrusted-text-injection',
      );
    // splicing the downloaded artifact's contents into a shell → injection
    expect(hasInj(mk('gh pr comment $(<PRurl)'))).toBe(true);
    // passing it as a quoted argument to a trusted committed script → safe
    expect(hasInj(mk('python3 scripts/publish.py --dir "$RUNNER_TEMP/a"'))).toBe(false);
  });

  it('flags over-broad write-all permissions but not contents: read', () => {
    const writeAll = [
      'on: [pull_request]',
      'permissions: write-all',
      'jobs:',
      '  j:',
      '    steps:',
      '      - run: echo hi',
    ].join('\n');
    const readOnly = [
      'on: [pull_request]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  j:',
      '    steps:',
      '      - run: echo hi',
    ].join('\n');
    expect(
      analyzeCi({ workflows: [{ path: 'w', content: writeAll }] }).diagnostics.some((d) =>
        d.message.includes('over-broad'),
      ),
    ).toBe(true);
    expect(
      analyzeCi({ workflows: [{ path: 'w', content: readOnly }] }).diagnostics.some((d) =>
        d.message.includes('over-broad'),
      ),
    ).toBe(false);
  });

  it('detects secrets referenced via format(...) and the bulk toJSON(secrets)', () => {
    const wf = [
      'on: [push]',
      'jobs:',
      '  j:',
      '    steps:',
      "      - run: echo ${{ format('{0}', secrets.NPM_TOKEN) }}",
      '      - run: echo ${{ toJSON(secrets) }}',
    ].join('\n');
    const r = analyzeCi({ workflows: [{ path: 'w', content: wf }] });
    expect(r.nodes.some((n) => n.kind === 'sink' && n.identity === 'NPM_TOKEN')).toBe(true);
    expect(r.diagnostics.some((d) => d.message.includes('full secret set'))).toBe(true);
  });

  it('flags secrets: inherit', () => {
    const wf = [
      'on: [push]',
      'jobs:',
      '  j:',
      '    uses: ./.github/workflows/reusable.yml',
      '    secrets: inherit',
    ].join('\n');
    expect(
      analyzeCi({ workflows: [{ path: 'w', content: wf }] }).diagnostics.some((d) =>
        d.message.includes('full secret set'),
      ),
    ).toBe(true);
  });

  it('returns a parse-error diagnostic and still analyzes the other workflows', () => {
    const r = analyzeCi({
      workflows: [
        { path: 'bad.yml', content: 'on: [push\njobs: {' },
        { path: 'good.yml', content: AE2 },
      ],
    });
    expect(r.diagnostics.some((d) => d.level === 'error')).toBe(true);
    expect(r.nodes.some((n) => n.kind === 'ci-job' && n.job === 'build')).toBe(true);
  });
});

/**
 * 0047 / plan R3, KTD4: only a token that can change repo code (or mint cloud
 * credentials) is a credential sink. PR/issue/comment/label write scopes are real but
 * are not repo-code compromise, so they become a privileged-capability sink (warn).
 */
describe('code-write GITHUB_TOKEN scoping (0047)', () => {
  const perms = (p: unknown, jobP?: unknown) =>
    resolvePermissions({ permissions: p } as WorkflowSpec, { permissions: jobP } as JobSpec);

  it('treats contents: write and write-all as code-write', () => {
    expect(perms({ contents: 'write' }).codeWrite).toBe(true);
    expect(perms('write-all').codeWrite).toBe(true);
  });

  it('does not treat PR/issue write scopes as code-write', () => {
    const p = perms({ 'pull-requests': 'write', issues: 'write' });
    expect(p.overBroad).toBe(true);
    expect(p.codeWrite).toBe(false);
    expect(p.mintsCredentials).toBe(false);
  });

  it('treats id-token: write as credential-minting (OIDC → cloud credentials)', () => {
    const p = perms({ 'id-token': 'write', contents: 'read' });
    expect(p.codeWrite).toBe(false);
    expect(p.mintsCredentials).toBe(true);
  });

  it('lets job-level permissions override workflow-level for codeWrite', () => {
    expect(perms({ contents: 'write' }, { contents: 'read' }).codeWrite).toBe(false);
    expect(perms({ contents: 'read' }, { contents: 'write' }).codeWrite).toBe(true);
  });

  it('keeps read-all and absent permissions free of code-write', () => {
    expect(perms('read-all').codeWrite).toBe(false);
    expect(perms(undefined).codeWrite).toBe(false);
  });

  const tokenSink = (permissionLines: string[]) =>
    analyzeCi({
      workflows: [
        {
          path: 'w',
          content: [
            'on:',
            '  pull_request_target:',
            'permissions:',
            ...permissionLines,
            'jobs:',
            '  j:',
            '    steps:',
            '      - run: echo hi',
          ].join('\n'),
        },
      ],
    }).nodes.find((n) => n.kind === 'sink' && n.identity.startsWith('GITHUB_TOKEN'));

  it('emits a code-write token as a credential sink', () => {
    const sink = tokenSink(['  contents: write']);
    expect(sink && sink.kind === 'sink' && sink.sinkKind).toBe('credential');
  });

  it('emits an id-token: write token as a credential sink', () => {
    const sink = tokenSink(['  id-token: write']);
    expect(sink && sink.kind === 'sink' && sink.sinkKind).toBe('credential');
  });

  it('emits a PR-only write token as a privileged-capability sink', () => {
    const sink = tokenSink(['  pull-requests: write']);
    expect(sink && sink.kind === 'sink' && sink.sinkKind).toBe('privileged-capability');
  });
});

/** 0046: the untrusted-text entry carries its sink class and file:line evidence. */
describe('untrusted-text entry classification (0046)', () => {
  const entryOf = (content: string) =>
    analyzeCi({ workflows: [{ path: '.github/workflows/t.yml', content }] }).nodes.find(
      (n) => n.kind === 'entry' && n.entryKind === 'untrusted-text-injection',
    );
  const issueJob = (steps: string[]): string =>
    [
      'on:', // 1
      '  issues:', // 2
      'jobs:', // 3
      '  triage:', // 4
      '    steps:', // 5
      ...steps,
    ].join('\n');

  it('a run: interpolation is an execution sink with evidence at that line', () => {
    const entry = entryOf(
      issueJob([
        '      - uses: actions/checkout@v4', // 6
        '      - run: echo "${{ github.event.issue.title }}"', // 7
        '      - run: ./deploy.sh', // 8
        '        env:', // 9
        '          K: ${{ secrets.DEPLOY_KEY }}', // 10
      ]),
    );
    expect(entry && entry.kind === 'entry' && entry.sinkClass).toBe('execution');
    expect(entry && entry.kind === 'entry' && entry.evidence).toEqual({
      file: '.github/workflows/t.yml',
      line: 7,
    });
  });

  it('text passed only via env: produces no untrusted-text entry', () => {
    const entry = entryOf(
      issueJob([
        '      - run: echo "$TITLE"',
        '        env:',
        '          TITLE: ${{ github.event.issue.title }}',
        '          K: ${{ secrets.DEPLOY_KEY }}',
      ]),
    );
    expect(entry).toBeUndefined();
  });

  it('a coding-agent step is an agent-ingested entry', () => {
    const entry = entryOf(
      issueJob([
        '      - uses: anthropics/claude-code-action@v1', // 6
        '        env:',
        '          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
      ]),
    );
    expect(entry && entry.kind === 'entry' && entry.sinkClass).toBe('agent-ingested');
    expect(entry && entry.kind === 'entry' && entry.evidence?.line).toBe(6);
  });

  it('an actor-guarded job produces no entry (R6)', () => {
    const entry = entryOf(
      [
        'on:',
        '  issues:',
        'jobs:',
        '  triage:',
        "    if: github.event.issue.author_association == 'OWNER'",
        '    steps:',
        '      - run: echo "${{ github.event.issue.title }}"',
        '        env:',
        '          K: ${{ secrets.DEPLOY_KEY }}',
      ].join('\n'),
    );
    expect(entry).toBeUndefined();
  });

  it('a workflow_run artifact splice is an execution sink with evidence at the splice', () => {
    const entry = entryOf(
      [
        'on:', // 1
        '  workflow_run:', // 2
        "    workflows: ['CI']", // 3
        'jobs:', // 4
        '  comment:', // 5
        '    steps:', // 6
        '      - uses: actions/download-artifact@v4', // 7
        '      - run: gh pr comment $(<PRurl)', // 8
        '        env:', // 9
        '          T: ${{ secrets.GH_SESSION }}', // 10
      ].join('\n'),
    );
    expect(entry && entry.kind === 'entry' && entry.sinkClass).toBe('execution');
    expect(entry && entry.kind === 'entry' && entry.evidence?.line).toBe(8);
  });
});

// 0089: actions/checkout resolves a branch NAME against `repository:` (default: the base repo),
// so a fork's branch name is either absent or a same-named base branch, never fork code.
// A commit SHA is different: GitHub serves fork PR commits from the base repo.
describe('untrusted checkout: branch name vs SHA (0089)', () => {
  const wf = (trigger: string, checkoutWith: string[]): string =>
    [
      'on:',
      `  ${trigger}:`,
      'jobs:',
      '  fix:',
      '    permissions:',
      '      contents: write',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      ...checkoutWith.map((l) => `          ${l}`),
      '      - run: make fix',
      '        env:',
      '          TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
    ].join('\n');
  const forkPr = (content: string): boolean => {
    const r = analyzeCi({ workflows: [{ path: '.github/workflows/w.yml', content }] });
    return r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr');
  };

  it('a head branch name without repository: is base-repo code, not a fork checkout', () => {
    expect(forkPr(wf('workflow_run', ['ref: ${{ github.event.workflow_run.head_branch }}']))).toBe(
      false,
    );
    expect(forkPr(wf('pull_request_target', ['ref: ${{ github.head_ref }}']))).toBe(false);
    expect(
      forkPr(wf('pull_request_target', ['ref: ${{ github.event.pull_request.head.ref }}'])),
    ).toBe(false);
  });

  it('a head branch name with repository: github.repository is still the base repo', () => {
    expect(
      forkPr(
        wf('workflow_run', [
          'repository: ${{ github.repository }}',
          'ref: ${{ github.event.workflow_run.head_branch }}',
        ]),
      ),
    ).toBe(false);
  });

  it('a head branch name with repository: the head repo IS fork code', () => {
    expect(
      forkPr(
        wf('workflow_run', [
          'repository: ${{ github.event.workflow_run.head_repository.full_name }}',
          'ref: ${{ github.event.workflow_run.head_branch }}',
        ]),
      ),
    ).toBe(true);
    expect(
      forkPr(
        wf('pull_request_target', [
          'repository: ${{ github.event.pull_request.head.repo.full_name }}',
          'ref: ${{ github.head_ref }}',
        ]),
      ),
    ).toBe(true);
  });

  it('a head branch name with any other repository: (e.g. a step output) counts as fork code', () => {
    // fail closed: the head repo is often resolved by an earlier step (gh api pulls/N)
    expect(
      forkPr(
        wf('pull_request_target', [
          'repository: ${{ steps.pr.outputs.head_repo }}',
          'ref: ${{ steps.pr.outputs.head_ref }}',
        ]),
      ),
    ).toBe(true);
  });

  it('a head commit SHA is fork code with or without repository:', () => {
    expect(forkPr(wf('workflow_run', ['ref: ${{ github.event.workflow_run.head_sha }}']))).toBe(
      true,
    );
    expect(
      forkPr(wf('pull_request_target', ['ref: ${{ github.event.pull_request.head.sha }}'])),
    ).toBe(true);
    expect(
      forkPr(wf('pull_request_target', ['ref: refs/pull/${{ github.event.number }}/merge'])),
    ).toBe(true);
    expect(
      forkPr(wf('pull_request_target', ['ref: ${{ github.event.pull_request.merge_commit_sha }}'])),
    ).toBe(true);
  });

  it('a ref that mixes a branch name and a SHA counts as the SHA (fork code)', () => {
    expect(
      forkPr(
        wf('pull_request_target', [
          'ref: ${{ github.event.pull_request.head.sha || github.head_ref }}',
        ]),
      ),
    ).toBe(true);
  });
});

// 0090: a run step that exits for fork PRs (head repo != base repo) BEFORE fetching the PR ref
// only ever fetches same-repo PRs, which come from collaborators, so it is not an untrusted checkout.
describe('same-repo guard before a PR-ref fetch (0090)', () => {
  const wf = (script: string[]): string =>
    [
      'on:',
      '  issue_comment:',
      'jobs:',
      '  verify:',
      '    permissions:',
      '      contents: read',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - id: ctx',
      '        env:',
      '          REPO: ${{ github.repository }}',
      '          PR: ${{ github.event.issue.number }}',
      '        run: |',
      ...script.map((l) => `          ${l}`),
      '      - run: make verify',
      '        env:',
      '          TOKEN: ${{ secrets.AGENT_TOKEN }}',
    ].join('\n');
  const forkPr = (content: string): boolean => {
    const r = analyzeCi({ workflows: [{ path: '.github/workflows/w.yml', content }] });
    return r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr');
  };
  const lookup = 'head_repo="$(gh api "repos/${REPO}/pulls/${PR}" --jq .head.repo.full_name)"';
  const fetch = 'git fetch origin "+refs/pull/${PR}/head:refs/remotes/origin/pr"';

  it('an exit when the head repo differs from the base repo, before the fetch, is a guard', () => {
    expect(
      forkPr(wf([lookup, 'if [[ "${head_repo}" != "${REPO}" ]]; then', '  exit 0', 'fi', fetch])),
    ).toBe(false);
    // operands reversed, single brackets, GITHUB_REPOSITORY
    expect(
      forkPr(wf([lookup, 'if [ "$GITHUB_REPOSITORY" != "$head_repo" ]; then exit 0; fi', fetch])),
    ).toBe(false);
  });

  it('no guard: the PR-ref fetch is an untrusted checkout', () => {
    expect(forkPr(wf([lookup, fetch]))).toBe(true);
  });

  it('a guard that exits when the repos are EQUAL does not protect', () => {
    expect(
      forkPr(wf([lookup, 'if [[ "${head_repo}" == "${REPO}" ]]; then', '  exit 0', 'fi', fetch])),
    ).toBe(true);
  });

  it('a guard placed after the fetch does not protect', () => {
    expect(
      forkPr(wf([lookup, fetch, 'if [[ "${head_repo}" != "${REPO}" ]]; then', '  exit 0', 'fi'])),
    ).toBe(true);
  });

  it('a mismatch branch that does not exit does not protect', () => {
    expect(
      forkPr(
        wf([lookup, 'if [[ "${head_repo}" != "${REPO}" ]]; then', '  echo fork', 'fi', fetch]),
      ),
    ).toBe(true);
  });
});

describe('runsWorkspaceCode (0096)', () => {
  it('git and plain builtins run nothing from the checkout', () => {
    expect(runsWorkspaceCode({ run: 'git fetch origin\ngit checkout -B x origin/x' })).toBe(false);
    expect(runsWorkspaceCode({ run: 'if git rev-parse -q --verify v1; then echo yes; fi' })).toBe(
      false,
    );
    expect(runsWorkspaceCode({ run: 'REF=${{ github.ref }} echo "$REF" > /dev/null' })).toBe(false);
  });

  it('anything else, or anything it cannot read, counts as running code', () => {
    expect(runsWorkspaceCode({ run: 'npm test' })).toBe(true);
    expect(runsWorkspaceCode({ run: 'git status && make' })).toBe(true);
    expect(runsWorkspaceCode({ run: 'echo `./x.sh`' })).toBe(true);
    expect(runsWorkspaceCode({ run: 'for f in *.sh; do echo $f; done' })).toBe(true);
    expect(runsWorkspaceCode({ run: 'print(1)', shell: 'python' })).toBe(true);
    expect(runsWorkspaceCode({ uses: 'actions/setup-node@v4' })).toBe(false);
  });
});

describe('runsWorkspaceCode: commands that look inert but run repo code (0096 review)', () => {
  const runs = (run: string): boolean => runsWorkspaceCode({ run });

  it.each([
    'git bisect run ./test.sh',
    'git rebase -x ./check.sh main',
    'git submodule foreach ./build.sh',
    'git difftool -x ./d.sh HEAD~1',
    "git filter-branch --tree-filter './t.sh' HEAD",
    'git -c core.hooksPath=.githooks commit -m x',
    "git -c alias.x='!./evil.sh' x",
    'git config core.fsmonitor ./mon.sh\ngit status',
    'git x-custom-subcommand',
    'cp hooks/post-checkout .git/hooks/\ngit checkout main',
    'echo "#!/bin/sh" > .git/hooks/pre-commit',
    'cat conf > ~/.gitconfig\ngit fetch',
    'export PATH="$PWD/bin:$PATH"\ngit fetch',
    'PATH=./bin git fetch',
    'export BASH_ENV=./env.sh',
    'cat vars >> $GITHUB_ENV',
    'echo "$PWD/bin" >> "$GITHUB_PATH"',
    'echo hi & ./evil.sh',
    'cat <(./evil.sh)',
    'echo a > >(./x)',
  ])('%s runs repo code', (run) => {
    expect(runs(run)).toBe(true);
  });

  it.each([
    'git fetch origin\ngit checkout -B main origin/main',
    'git remote add upstream https://example.invalid/r.git && git fetch upstream',
    'git log -1 --format=%H > /dev/null 2>&1',
    'echo "sha=$SHA" >> "$GITHUB_OUTPUT"',
    'git tag -f v1 "$SHA" && git push -f origin refs/tags/v1',
    'echo "::notice::moved v1 -> ${SHA:0:8}; done & ok"',
  ])('%s does not', (run) => {
    expect(runs(run)).toBe(false);
  });
});

describe('runsWorkspaceCode: quoting and git directory tricks (0096 re-review)', () => {
  const runs = (run: string, extra: Partial<StepSpec> = {}): boolean =>
    runsWorkspaceCode({ run, ...extra });

  it.each([
    "# don't cache\nnpm test\n# it's done",
    'echo \\"hi\\"; npm test; echo "done"',
    "echo it\\'s; ./x.sh; echo 'z'",
    "echo $'a\\'b'; ./x; echo $'c\\'d'",
    'echo "unterminated\nnpm test',
    'git -C docs fetch origin',
    'git --git-dir=docs fetch origin',
    'git --work-tree docs status',
    'cd docs && git fetch origin',
    'pushd docs\ngit status',
    'export "PATH=$PWD/bin:$PATH"',
  ])('%j runs repo code', (run) => {
    expect(runs(run)).toBe(true);
  });

  it('git in a step with a working-directory runs repo config', () => {
    expect(runs('git fetch origin', { 'working-directory': 'docs' })).toBe(true);
  });

  it.each([
    "# don't run anything here\ngit fetch origin # it's fine",
    'git config --global --add safe.directory "*"',
    'git config http.https://example.invalid/.extraheader "AUTHORIZATION: basic x"',
    'git config core.sparseCheckout true',
  ])('%j does not', (run) => {
    expect(runs(run)).toBe(false);
  });
});

describe('runsWorkspaceCode: expressions and builtins (0096 third review)', () => {
  const runs = (run: string): boolean => runsWorkspaceCode({ run });

  it.each([
    'echo "${{ github.head_ref }}"',
    'echo ${{ github.event.pull_request.title }}',
    'echo ${{ steps.a.outputs.msg }}',
    'git checkout ${{ github.event.workflow_run.head_branch }}',
    '[[ "$X" -eq 1 ]] && echo one',
    "PS4='+ ' ; set -x; echo hi",
    "printf -v PATH '%s' ./bin; cat f",
    'git fetch "$REMOTE"',
    'git ls-remote $URL',
  ])('%j runs repo code', (run) => {
    expect(runs(run)).toBe(true);
  });

  it.each([
    'git fetch origin ${{ github.event.pull_request.head.sha }}',
    'git remote add upstream ${{ github.event.repository.clone_url }}',
    'git checkout -B ${{ github.event.pull_request.base.ref }} upstream/${{ github.base_ref }}',
    'echo "run ${{ github.run_id }} for ${{ github.repository }}"',
    'set -euo pipefail\necho same',
    'git checkout "$BRANCH"',
  ])('%j does not', (run) => {
    expect(runs(run)).toBe(false);
  });
});

describe('runsWorkspaceCode: minimal allowlist (0096 fourth review)', () => {
  const runs = (run: string): boolean => runsWorkspaceCode({ run });

  it.each([
    'echo ${{ fromJSON(needs.a.outputs.pr).number }}',
    'git checkout -B ${{ fromJson(steps.pr.outputs.data).base.ref }}',
    'echo ${{ FROMJSON(steps.x.outputs.y).NUMBER }}',
    '[ -v "$T" ] && echo set',
    'test -v "$T"',
    '[[ -v $T ]]',
    'echo "${A:$T}"',
    'echo "${arr[$T]}"',
    "printf -vPATH '%s' ./bin",
    'cat notes.txt',
  ])('%j runs repo code', (run) => {
    expect(runs(run)).toBe(true);
  });

  it('a literal substring offset stays inert', () => {
    expect(runs('echo "short ${SHA:0:8}"')).toBe(false);
  });
});
