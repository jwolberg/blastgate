import { describe, expect, it } from 'vitest';
import { analyzeGitlabCi } from './index';

/** A job triggerable by a merge request that references an AWS secret variable. */
const MR_SECRET = [
  'deploy:',
  '  script:',
  '    - echo "$AWS_SECRET_ACCESS_KEY" > /tmp/creds',
  '  rules:',
  '    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'',
].join('\n');

/** A push-only (trusted) job that references the same secret. */
const PUSH_SECRET = [
  'deploy:',
  '  script:',
  '    - echo "$AWS_SECRET_ACCESS_KEY"',
  '  only:',
  '    - main',
].join('\n');

describe('analyzeGitlabCi', () => {
  it('emits a gitlab ci-job, a secret sink, and a fork entry for an MR-triggerable secret job', () => {
    const r = analyzeGitlabCi({ content: MR_SECRET });
    const job = r.nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.provider).toBe('gitlab');
    expect(job && job.kind === 'ci-job' && job.forkTriggerable).toBe(true);
    expect(r.nodes.some((n) => n.kind === 'sink' && n.identity === 'AWS_SECRET_ACCESS_KEY')).toBe(
      true,
    );
    expect(r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'fork-pr')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'holds')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'triggers')).toBe(true);
  });

  it('emits no fork entry for a push-only job (not merge-request triggerable)', () => {
    const r = analyzeGitlabCi({ content: PUSH_SECRET });
    expect(r.nodes.some((n) => n.kind === 'ci-job')).toBe(true);
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(false);
  });

  it('does not read GitLab predefined CI_ variables as secrets', () => {
    const content = [
      'job:',
      '  script:',
      '    - echo "$CI_PIPELINE_SOURCE $CI_COMMIT_SHA"',
      '  rules:',
      '    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'',
    ].join('\n');
    const r = analyzeGitlabCi({ content });
    expect(r.nodes.some((n) => n.kind === 'sink')).toBe(false);
  });

  it('detects an install step for the cross-layer edge', () => {
    const content = ['test:', '  script:', '    - bundle install'].join('\n');
    const job = analyzeGitlabCi({ content }).nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.runsInstall).toBe(true);
  });
});
