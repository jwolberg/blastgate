import { describe, expect, it } from 'vitest';
import { analyzeCi } from './index';
import { isPinnedAction, normalizeTriggers, untrustedTriggers } from './parse';

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
