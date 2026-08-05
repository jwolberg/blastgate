import { describe, expect, it } from 'vitest';
import type { RepoFs } from '../cli/collect';
import { runCli } from '../cli/index';
import { handleRequest, type McpContext } from './server';
import { CHECK_CHANGE_TOOL, checkChange } from './tools';

const HEAD_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/evil-pkg': { version: '1.0.0', hasInstallScript: true },
  },
});
const BASE_LOCK = JSON.stringify({ packages: { '': { name: 'app' } } });
const WORKFLOW = [
  'on:',
  '  pull_request:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');

function memFs(files: Record<string, string>, base?: Record<string, string>): RepoFs {
  return {
    read: (p) => (p in files ? files[p]! : null),
    listWorkflows: () =>
      Object.keys(files).filter((p) => /^\.github\/workflows\/.*\.ya?ml$/.test(p)),
    gitShow: base ? (_ref, p) => (p in base ? base[p]! : null) : undefined,
  };
}
function failingFs(): RepoFs {
  return memFs(
    { 'package-lock.json': HEAD_LOCK, '.github/workflows/ci.yml': WORKFLOW },
    { 'package-lock.json': BASE_LOCK },
  );
}
function cleanFs(): RepoFs {
  return memFs({ 'package.json': '{"name":"app"}' });
}
function ctx(fs: RepoFs): McpContext {
  return { fs, base: 'HEAD' };
}

// Minimal JSON-RPC request builder.
function req(id: number | string | null, method: string, params?: unknown): unknown {
  return { jsonrpc: '2.0', id, method, params };
}

describe('MCP protocol (handleRequest)', () => {
  it('initialize returns the blastgate server info and tool capability', () => {
    const res = handleRequest(
      req(1, 'initialize', { protocolVersion: '2025-06-18' }),
      ctx(cleanFs()),
    );
    expect(res).not.toBeNull();
    const r = res as { result: { serverInfo: { name: string }; capabilities: { tools: unknown } } };
    expect(r.result.serverInfo.name).toBe('blastgate');
    expect(r.result.capabilities.tools).toBeDefined();
  });

  it('tools/list advertises blastgate_check_change with an input schema', () => {
    const res = handleRequest(req(2, 'tools/list'), ctx(cleanFs())) as {
      result: { tools: Array<{ name: string; inputSchema: unknown }> };
    };
    const tool = res.result.tools.find((t) => t.name === 'blastgate_check_change');
    expect(tool).toBeDefined();
    expect(tool!.inputSchema).toBeDefined();
    expect(CHECK_CHANGE_TOOL.name).toBe('blastgate_check_change');
  });

  it('a notification (no id) yields no response', () => {
    expect(handleRequest(req(null, 'initialized'), ctx(cleanFs()))).toBeNull();
  });

  it('an unknown method yields a JSON-RPC method-not-found error', () => {
    const res = handleRequest(req(9, 'does/not/exist'), ctx(cleanFs())) as {
      error?: { code: number };
    };
    expect(res.error?.code).toBe(-32601);
  });
});

describe('blastgate_check_change (tools/call)', () => {
  function call(
    fs: RepoFs,
    args: unknown,
  ): { content: Array<{ text: string }>; isError?: boolean; structuredContent?: unknown } {
    const res = handleRequest(
      req(3, 'tools/call', { name: 'blastgate_check_change', arguments: args }),
      ctx(fs),
    ) as {
      result: { content: Array<{ text: string }>; isError?: boolean; structuredContent?: unknown };
    };
    return res.result;
  }

  it('reports a reachable-path verdict on a malicious-dependency change', () => {
    const out = call(failingFs(), { change_kind: 'dependency', file_path: 'package-lock.json' });
    expect(out.isError).toBe(false);
    expect(out.content[0]!.text).toContain('AWS_SECRET_ACCESS_KEY');
    const sc = out.structuredContent as { verdict: string; findings: unknown[] };
    expect(sc.verdict).toBe('fail');
    expect(sc.findings.length).toBeGreaterThan(0);
  });

  it('reports a clean verdict on a benign change and never signals a block', () => {
    const out = call(cleanFs(), { change_kind: 'other' });
    expect(out.isError).toBe(false);
    const sc = out.structuredContent as { verdict: string };
    expect(sc.verdict).toBe('pass');
    // advisory only — the result is never a block/deny
    expect(JSON.stringify(out)).not.toContain('"decision"');
    expect(JSON.stringify(out)).not.toContain('permissionDecision');
  });

  it('malformed arguments yield a structured tool error and the server stays up', () => {
    const bad = handleRequest(
      req(4, 'tools/call', { name: 'blastgate_check_change', arguments: 'not-an-object' }),
      ctx(failingFs()),
    ) as { result: { isError?: boolean } };
    expect(bad.result.isError).toBe(true);
    // the server still answers the next request
    const ping = handleRequest(req(5, 'ping'), ctx(failingFs())) as { result: unknown };
    expect(ping.result).toBeDefined();
  });

  it('an unknown tool name is a structured error, not a protocol error', () => {
    const res = handleRequest(
      req(6, 'tools/call', { name: 'nope', arguments: {} }),
      ctx(cleanFs()),
    ) as { result: { isError?: boolean }; error?: unknown };
    expect(res.error).toBeUndefined();
    expect(res.result.isError).toBe(true);
  });
});

describe('MCP / CLI parity (KTD10)', () => {
  it('the tool verdict + findings equal the CLI gate output for the same change', async () => {
    const toolOut = checkChange(failingFs(), {}, 'HEAD');

    let cliJson = '';
    await runCli(['.', '--base', 'HEAD', '--json'], {
      fs: failingFs(),
      stdin: () => Promise.resolve(''),
      stdout: (s) => {
        cliJson += s;
      },
      stderr: () => {},
    });

    expect(JSON.parse(JSON.stringify(toolOut.structured.findings))).toEqual(JSON.parse(cliJson));
  });
});
