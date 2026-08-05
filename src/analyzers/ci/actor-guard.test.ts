import { describe, expect, it } from 'vitest';
import { runEngine } from '../../engine/gate';
import { analyzeCi } from './index';
import { hasActorGuard } from './parse';

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
