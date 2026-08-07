import { describe, expect, it } from 'vitest';
import { runEngine } from '../../engine/gate';
import { analyzeCi } from './index';
import { hasActorGuard, hasScriptPermissionGuard, isLabelGated, type JobSpec } from './parse';

/** A comment-triggered job whose `if:` gates only on an @claude mention (volscan shape). */
const MENTION_ONLY = [
  'on:',
  '  issue_comment:',
  '    types: [created]',
  'jobs:',
  '  claude:',
  "    if: contains(github.event.comment.body, '@claude')",
  '    permissions:',
  '      contents: write',
  '    steps:',
  '      - run: gh pr checkout 123',
  '      - run: echo hi',
  '        env:',
  '          KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
].join('\n');

/** Same job, but the `if:` also requires a trusted author_association. */
const ACTOR_GATED = [
  'on:',
  '  issue_comment:',
  '    types: [created]',
  'jobs:',
  '  claude:',
  '    if: >',
  "      contains(github.event.comment.body, '@claude') &&",
  '      contains(fromJSON(\'["OWNER","MEMBER","COLLABORATOR"]\'), github.event.comment.author_association)',
  '    permissions:',
  '      contents: write',
  '    steps:',
  '      - run: gh pr checkout 123',
  '      - run: echo hi',
  '        env:',
  '          KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
].join('\n');

describe('hasActorGuard', () => {
  it('recognizes an author_association restricted to trusted roles', () => {
    expect(
      hasActorGuard({
        if: "github.event.comment.author_association == 'OWNER'",
      }),
    ).toBe(true);
    expect(
      hasActorGuard({
        if: 'contains(fromJSON(\'["MEMBER","COLLABORATOR"]\'), github.event.issue.author_association)',
      }),
    ).toBe(true);
  });

  it('recognizes a github.actor allowlist / comparison', () => {
    expect(hasActorGuard({ if: "github.actor == 'trusted-bot'" })).toBe(true);
    expect(
      hasActorGuard({ if: 'contains(fromJSON(\'["a","b"]\'), github.triggering_actor)' }),
    ).toBe(true);
  });

  it('does NOT treat an @claude-mention filter as a guard (fail-closed)', () => {
    expect(hasActorGuard({ if: "contains(github.event.comment.body, '@claude')" })).toBe(false);
  });

  it('is false when there is no if: condition', () => {
    expect(hasActorGuard({})).toBe(false);
  });
});

describe('analyzeCi marks the fork-pr entry guarded', () => {
  it('sets guarded=false for a mention-only if:', () => {
    const r = analyzeCi({ workflows: [{ path: 'w.yml', content: MENTION_ONLY }] });
    const entry = r.nodes.find((n) => n.kind === 'entry' && n.entryKind === 'fork-pr');
    expect(entry && entry.kind === 'entry' && entry.guarded).toBeFalsy();
  });

  it('sets guarded=true for an actor-gated if:', () => {
    const r = analyzeCi({ workflows: [{ path: 'w.yml', content: ACTOR_GATED }] });
    const entry = r.nodes.find((n) => n.kind === 'entry' && n.entryKind === 'fork-pr');
    expect(entry && entry.kind === 'entry' && entry.guarded).toBe(true);
  });
});

describe('the engine downgrades a guarded untrusted-trigger finding', () => {
  it('an ungated (mention-only) secret path FAILS', () => {
    const result = runEngine({ ci: { workflows: [{ path: 'w.yml', content: MENTION_ONLY }] } });
    expect(result.verdict).toBe('fail');
  });

  it('an actor-gated secret path WARNS (reported, not failed) — least privilege still applies', () => {
    const result = runEngine({ ci: { workflows: [{ path: 'w.yml', content: ACTOR_GATED }] } });
    expect(result.verdict).toBe('warn');
    const f = result.findings[0]!;
    expect(f.tier).toBe('warn');
    expect(f.reason.toLowerCase()).toContain('actor-gated');
  });
});

// ---- 0044: injection precision — in-step actor guards + safe handling ----

describe('isLabelGated (0044)', () => {
  it('true when if: keys on github.event.label.name (applying a label needs triage/write)', () => {
    expect(isLabelGated({ if: "github.event.label.name == 'flaky-test'" })).toBe(true);
    expect(isLabelGated({ if: "contains(github.event.label.name, 'triage')" })).toBe(true);
  });
  it('false for a content filter, an actor guard, or no if:', () => {
    expect(isLabelGated({ if: "contains(github.event.issue.body, 'x')" })).toBe(false);
    expect(isLabelGated({ if: "github.actor == 'bot'" })).toBe(false);
    expect(isLabelGated({})).toBe(false);
  });
});

describe('hasScriptPermissionGuard (0044)', () => {
  const script = (body: string): JobSpec => ({
    steps: [{ uses: 'actions/github-script@v7', with: { script: body } }],
  });
  it('true: a github-script step that checks collaborator permission AND throws (halts the job)', () => {
    expect(
      hasScriptPermissionGuard(
        script(
          'const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username });\n' +
            'if (!data.user.permissions.triage) { throw new Error("User lacks permission"); }',
        ),
      ),
    ).toBe(true);
  });
  it('false: checks permission but only sets an output (non-halting → fail-closed)', () => {
    expect(
      hasScriptPermissionGuard(
        script(
          'const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username });\n' +
            'core.setOutput("allowed", data.user.permissions.triage);',
        ),
      ),
    ).toBe(false);
  });
  it('false: a github-script step with no permission check, even if it throws', () => {
    expect(hasScriptPermissionGuard(script('if (x) throw new Error("boom")'))).toBe(false);
  });
});

describe('analyzeCi neutralizes a guarded / safely-handled injection job (0044)', () => {
  const job = (extra: string[]): string =>
    [
      'on:',
      '  issues:',
      '    types: [labeled]',
      'jobs:',
      '  j:',
      ...extra,
      '    steps:',
      '      - run: echo "${{ github.event.issue.body }}"',
      '        env:',
      '          K: ${{ secrets.APP_KEY }}',
    ].join('\n');
  const hasInj = (content: string): boolean =>
    analyzeCi({ workflows: [{ path: 'w', content }] }).nodes.some(
      (n) => n.kind === 'entry' && n.entryKind === 'untrusted-text-injection',
    );

  it('unguarded body-injection job → an injection entry (still a finding)', () => {
    expect(hasInj(job([]))).toBe(true);
  });
  it('label-gated job → no injection entry', () => {
    expect(hasInj(job(["    if: github.event.label.name == 'needs-triage'"]))).toBe(false);
  });
  it('github-script permission-check-with-throw job → no injection entry', () => {
    const content = [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  j:',
      '    steps:',
      '      - uses: actions/github-script@v7',
      '        with:',
      '          script: |',
      '            const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username });',
      '            if (!data.user.permissions.triage) throw new Error("no perm");',
      '      - run: echo "${{ github.event.comment.body }}"',
      '        env:',
      '          K: ${{ secrets.APP_KEY }}',
    ].join('\n');
    expect(hasInj(content)).toBe(false);
  });
  it('boolean-matched only (body ref lives solely inside contains()) → no injection entry', () => {
    const content = [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  j:',
      "    if: contains(github.event.comment.body, '/deploy')",
      '    steps:',
      '      - run: echo running',
      '        env:',
      '          K: ${{ secrets.APP_KEY }}',
    ].join('\n');
    expect(hasInj(content)).toBe(false);
  });
});
