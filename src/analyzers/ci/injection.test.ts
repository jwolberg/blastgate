import { describe, expect, it } from 'vitest';
import { agentActionsUsed, injectableTextRefs, isInjectableAgentJob } from './injection';
import type { JobSpec } from './parse';

/**
 * The AISI Mythos-5 injection was planted in a GitHub issue and read by an AI
 * triage agent. The deterministic, offline signal Blastgate can see is the
 * *workflow configuration* that creates the path: a job on an untrusted-text
 * event that pipes attacker-authored body/title text into a step, or runs a
 * coding-agent action that ingests the event by design (0022).
 */
describe('injectableTextRefs — attacker-authored event text piped into a step', () => {
  it('finds an issue body reference in a run step', () => {
    const job: JobSpec = { steps: [{ run: 'echo "${{ github.event.issue.body }}"' }] };
    expect(injectableTextRefs(job)).toContain('github.event.issue.body');
  });
  it('finds a comment body reference in a with: input', () => {
    const job: JobSpec = {
      steps: [{ uses: 'x/y@v1', with: { prompt: '${{ github.event.comment.body }}' } }],
    };
    expect(injectableTextRefs(job)).toContain('github.event.comment.body');
  });
  it('finds a PR title reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.pull_request.title }}' }] };
    expect(injectableTextRefs(job).length).toBeGreaterThan(0);
  });
  it('does not match a non-text event field (e.g. number)', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.issue.number }}' }] };
    expect(injectableTextRefs(job)).toHaveLength(0);
  });
});

describe('agentActionsUsed — a coding agent that ingests the event context', () => {
  it('detects anthropics/claude-code-action', () => {
    const job: JobSpec = { steps: [{ uses: 'anthropics/claude-code-action@v1' }] };
    expect(agentActionsUsed(job)).toHaveLength(1);
  });
  it('ignores an ordinary action', () => {
    const job: JobSpec = { steps: [{ uses: 'actions/checkout@v4' }] };
    expect(agentActionsUsed(job)).toHaveLength(0);
  });
});

describe('isInjectableAgentJob — untrusted-text trigger + an injectable surface', () => {
  it('true: issue_comment trigger + a body reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.comment.body }}' }] };
    expect(isInjectableAgentJob(job, ['issue_comment'])).toBe(true);
  });
  it('true: issues trigger + an agent action (reads the event by design)', () => {
    const job: JobSpec = { steps: [{ uses: 'anthropics/claude-code-action@v1' }] };
    expect(isInjectableAgentJob(job, ['issues'])).toBe(true);
  });
  it('false: a trusted trigger (push) even with a body reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.issue.body }}' }] };
    expect(isInjectableAgentJob(job, ['push'])).toBe(false);
  });
  it('false: untrusted trigger but no injectable surface', () => {
    const job: JobSpec = { steps: [{ run: 'npm test' }] };
    expect(isInjectableAgentJob(job, ['issue_comment'])).toBe(false);
  });
});
