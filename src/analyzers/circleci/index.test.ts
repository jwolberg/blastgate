import { describe, expect, it } from 'vitest';
import { analyzeCircleCi } from './index';

const SECRET_JOB = [
  'version: 2.1',
  'jobs:',
  '  deploy:',
  '    docker:',
  '      - image: cimg/base:2024',
  '    steps:',
  '      - run: aws s3 cp . s3://x --acl private',
  '      - run: echo "$AWS_SECRET_ACCESS_KEY"',
].join('\n');

describe('analyzeCircleCi (0035, out-of-repo gap)', () => {
  it('emits a circleci ci-job and secret sink, but NO fork entry (fork-triggerability is out-of-repo)', () => {
    const r = analyzeCircleCi({ content: SECRET_JOB });
    const job = r.nodes.find((n) => n.kind === 'ci-job');
    expect(job && job.kind === 'ci-job' && job.provider).toBe('circleci');
    expect(job && job.kind === 'ci-job' && job.forkTriggerable).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'sink' && n.identity === 'AWS_SECRET_ACCESS_KEY')).toBe(
      true,
    );
    // The gap: no entry is invented, so no false FAIL is produced from the config alone.
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(false);
  });

  it('surfaces the out-of-repo forked-PR-secret toggle as an advisory warning', () => {
    const r = analyzeCircleCi({ content: SECRET_JOB });
    expect(
      r.diagnostics.some(
        (d) => d.level === 'warn' && /forked pull requests|forked-PR builds/i.test(d.message),
      ),
    ).toBe(true);
  });

  it('does not read CircleCI predefined CIRCLE_ variables as secrets', () => {
    const content = [
      'version: 2.1',
      'jobs:',
      '  b:',
      '    steps:',
      '      - run: echo $CIRCLE_SHA1',
    ].join('\n');
    expect(analyzeCircleCi({ content }).nodes.some((n) => n.kind === 'sink')).toBe(false);
  });
});
