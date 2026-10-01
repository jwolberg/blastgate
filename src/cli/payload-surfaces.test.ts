import { describe, expect, it } from 'vitest';
import { runAction, type ActionEnv } from '../action/index';
import { runEngine } from '../engine/gate';
import { checkChange } from '../mcp/tools';
import { toRunRecord } from '../report/run-record';
import type { RepoFs } from './collect';
import { runCli } from './index';
import { renderMarkdown, renderText } from './render';

/**
 * 0049 / plan R7, R10: every surface shows where a fail lands (file:line) and what it
 * reaches, but the illustrative payload appears ONLY in local text output and in JSON
 * when explicitly requested. The markdown report, the Action summary/annotations, the MCP
 * tool, and `--record` run records never carry it — a public PR surface must not publish a
 * working attack on a vulnerable repo.
 */

const WF = '.github/workflows/triage.yml';
const SHELL_INJECTION = [
  'on:',
  '  issues:',
  'jobs:',
  '  triage:',
  '    steps:',
  '      - run: echo "${{ github.event.issue.title }}"', // 6
  '      - run: ./deploy.sh',
  '        env:',
  '          K: ${{ secrets.DEPLOY_KEY }}',
].join('\n');
// Agent-in-CI U5 (0059): an AE1 agent fail is held to the same surface rules.
const AGENT_FAIL = [
  'on: issue_comment',
  'permissions:',
  '  issues: write',
  'jobs:',
  '  claude:',
  '    steps:',
  '      - uses: anthropics/claude-code-action@v1', // 7
  '        env:',
  '          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0',
  '        with:',
  '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
  '          github_token: ${{ secrets.GITHUB_TOKEN }}',
  "          allowed_non_write_users: '*'",
  "          claude_args: '--allowedTools Bash'",
].join('\n');
const PAYLOAD_MARKER = 'attacker.example';

describe.each([
  { name: 'shell injection', content: SHELL_INJECTION, line: 6, secret: 'DEPLOY_KEY' },
  { name: 'agent Rule-of-Two fail', content: AGENT_FAIL, line: 7, secret: 'ANTHROPIC_API_KEY' },
])('evidence + payload surfaces (0049): $name', ({ content, line, secret }) => {
  const fs: RepoFs = {
    read: (p) => (p === WF ? content : null),
    listWorkflows: () => [WF],
  };

  async function cli(args: string[]): Promise<string> {
    let out = '';
    await runCli(['.', ...args], {
      fs,
      stdin: () => Promise.resolve(''),
      stdout: (s) => {
        out += s;
      },
      stderr: () => {},
    });
    return out;
  }

  const result = runEngine({ ci: { workflows: [{ path: WF, content }] } });

  it('the engine finding carries the payload (precondition)', () => {
    const f = result.findings.find((x) => x.tier === 'fail');
    expect(f?.evidence?.payload).toContain(PAYLOAD_MARKER);
  });

  it('text output shows file:line, capability, and the payload', () => {
    const text = renderText(result);
    expect(text).toContain(`${WF}:${line}`);
    expect(text).toContain(secret);
    expect(text).toContain(PAYLOAD_MARKER);
  });

  it('markdown shows file:line and capability but never the payload', () => {
    const md = renderMarkdown(result);
    expect(md).toContain(`${WF}:${line}`);
    expect(md).toContain(secret);
    expect(md).not.toContain(PAYLOAD_MARKER);
  });

  it('JSON omits the payload by default and includes it with --include-payloads', async () => {
    const plain = await cli(['--json']);
    expect(plain).toContain(`"line": ${line}`);
    expect(plain).not.toContain(PAYLOAD_MARKER);
    expect(await cli(['--json', '--include-payloads'])).toContain(PAYLOAD_MARKER);
  });

  it('AE6: the Action summary and annotations name the line and secret, never the payload', () => {
    const annotations: string[] = [];
    const summaries: string[] = [];
    const env: ActionEnv = {
      fs,
      annotate: (_level, message) => annotations.push(message),
      summary: (md) => summaries.push(md),
    };
    runAction(env);
    const all = [...annotations, ...summaries].join('\n');
    expect(all).toContain(secret);
    expect(all).toContain(`${WF}:${line}`);
    expect(all).not.toContain(PAYLOAD_MARKER);
  });

  it('the MCP tool result carries no payload', () => {
    const out = checkChange(fs, {}, 'HEAD');
    expect(JSON.stringify(out)).toContain(secret);
    expect(JSON.stringify(out)).not.toContain(PAYLOAD_MARKER);
  });

  it('a --record run record keeps the evidence line but no payload', () => {
    const rec = JSON.stringify(toRunRecord(result, { timestamp: '2026-09-29T00:00:00Z' }));
    expect(rec).toContain(`"line":${line}`);
    expect(rec).not.toContain(PAYLOAD_MARKER);
  });
});
