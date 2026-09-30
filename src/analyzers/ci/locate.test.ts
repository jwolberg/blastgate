import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { locateSource } from './locate';

/**
 * Evidence for a `fail` must cite the exact source line where attacker input lands
 * (plan R7 / KTD3). The locator maps a workflow key path to its 1-based line using
 * the YAML parser's own positions — never a text search, which would match the
 * wrong job when two jobs share a step.
 */
describe('locateSource — workflow key path → source line', () => {
  it('finds the run: of the artifact-injection fixture on line 12', () => {
    const yaml = readFileSync(
      join(
        dirname(fileURLToPath(import.meta.url)),
        '../../../test/fixtures/ci-artifact-injection/positive/.github/workflows/comment.yml',
      ),
      'utf8',
    );
    expect(locateSource(yaml).stepLine('comment', 1, 'run')).toBe(12);
  });

  it('distinguishes identical steps in two different jobs', () => {
    const yaml = [
      'on: issues', // 1
      'jobs:', // 2
      '  a:', // 3
      '    steps:', // 4
      '      - run: echo "${{ github.event.issue.title }}"', // 5
      '  b:', // 6
      '    steps:', // 7
      '      - uses: actions/checkout@v4', // 8
      '      - run: echo "${{ github.event.issue.title }}"', // 9
    ].join('\n');
    const loc = locateSource(yaml);
    expect(loc.stepLine('a', 0, 'run')).toBe(5);
    expect(loc.stepLine('b', 1, 'run')).toBe(9);
  });

  it('returns the key line for a block-scalar run:', () => {
    const yaml = [
      'jobs:', // 1
      '  build:', // 2
      '    steps:', // 3
      '      - name: greet', // 4
      '        run: |', // 5
      '          echo one', // 6
      '          echo "${{ github.event.issue.body }}"', // 7
    ].join('\n');
    expect(locateSource(yaml).stepLine('build', 0, 'run')).toBe(5);
  });

  it('returns the step start line when no field is given', () => {
    const yaml = [
      'jobs:', // 1
      '  build:', // 2
      '    steps:', // 3
      '      - uses: actions/checkout@v4', // 4
      '      - name: test', // 5
      '        run: npm test', // 6
    ].join('\n');
    expect(locateSource(yaml).stepLine('build', 1)).toBe(5);
  });

  it('finds a with.<key> input, including flow-style maps', () => {
    const yaml = [
      'jobs:', // 1
      '  bot:', // 2
      '    steps:', // 3
      '      - uses: actions/github-script@v7', // 4
      "        with: { script: 'core.info(`${{ github.event.comment.body }}`)' }", // 5
      '      - uses: x/notify@v1', // 6
      '        with:', // 7
      '          text: ${{ github.event.issue.title }}', // 8
    ].join('\n');
    const loc = locateSource(yaml);
    expect(loc.stepLine('bot', 0, 'with.script')).toBe(5);
    expect(loc.stepLine('bot', 1, 'with.text')).toBe(8);
  });

  it('returns undefined (never throws) for a missing job, step, or field', () => {
    const yaml = ['jobs:', '  build:', '    steps:', '      - run: npm test'].join('\n');
    const loc = locateSource(yaml);
    expect(loc.stepLine('nope', 0, 'run')).toBeUndefined();
    expect(loc.stepLine('build', 5, 'run')).toBeUndefined();
    expect(loc.stepLine('build', 0, 'uses')).toBeUndefined();
    expect(loc.line(['jobs', 'build', 'steps', 0, 'with', 'script'])).toBeUndefined();
  });

  it('looks up a top-level GitLab job key by generic path', () => {
    const yaml = [
      'stages: [test]', // 1
      '', // 2
      'unit:', // 3
      '  stage: test', // 4
      '  script: npm ci', // 5
      '', // 6
      'deploy:', // 7
      '  script: ./deploy.sh', // 8
    ].join('\n');
    const loc = locateSource(yaml);
    expect(loc.line(['unit'])).toBe(3);
    expect(loc.line(['deploy'])).toBe(7);
    expect(loc.line(['deploy', 'script'])).toBe(8);
  });

  it('returns undefined for invalid YAML rather than throwing', () => {
    expect(locateSource('jobs: [unclosed').line(['jobs'])).toBeUndefined();
  });
});
