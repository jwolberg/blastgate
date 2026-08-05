/**
 * Minimal stdio JSON-RPC 2.0 MCP server (U13) exposing `blastgate_check_change`.
 *
 * `handleRequest` is a pure request→response function (offline-testable); the
 * newline-delimited stdio transport is the only stateful part and lives in
 * `runStdioServer`. The server is scoped to the project dir (the injected
 * `RepoFs`) and is advisory — it computes verdicts, never blocks (KTD12).
 */

import type { RepoFs } from '../cli/collect';
import { VERSION } from '../index';
import { CHECK_CHANGE_TOOL, checkChange } from './tools';

const PROTOCOL_VERSION = '2025-06-18';

export interface McpContext {
  /** Project-dir-scoped filesystem the tool scans. */
  fs: RepoFs;
  /** Diff base for change signals (defaults to HEAD). */
  base?: string;
}

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

function ok(id: number | string, result: unknown): JsonRpcResponse {
  return { jsonrpc: '2.0', id, result };
}
function fail(id: number | string, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/** A tool error is a normal result with `isError: true` (the agent sees it), not a protocol error. */
function toolResult(text: string, isError: boolean, structured?: unknown): unknown {
  const result: Record<string, unknown> = { content: [{ type: 'text', text }], isError };
  if (structured !== undefined) {
    result.structuredContent = structured;
  }
  return result;
}

function callTool(id: number | string, params: unknown, ctx: McpContext): JsonRpcResponse {
  const p = (params ?? {}) as { name?: string; arguments?: unknown };
  if (p.name !== CHECK_CHANGE_TOOL.name) {
    return ok(id, toolResult(`Unknown tool: ${String(p.name)}`, true));
  }
  try {
    const out = checkChange(ctx.fs, p.arguments ?? {}, ctx.base ?? 'HEAD');
    return ok(id, toolResult(out.text, false, out.structured));
  } catch (err) {
    return ok(id, toolResult(`blastgate_check_change error: ${(err as Error).message}`, true));
  }
}

/** Handle one JSON-RPC request. Returns null for a notification (no id). */
export function handleRequest(request: unknown, ctx: McpContext): JsonRpcResponse | null {
  const req = (request ?? {}) as JsonRpcRequest;
  const { id, method, params } = req;
  if (id === undefined || id === null) {
    return null; // notification — no response
  }

  switch (method) {
    case 'initialize': {
      const requested = (params as { protocolVersion?: string } | undefined)?.protocolVersion;
      return ok(id, {
        protocolVersion: requested ?? PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: 'blastgate', version: VERSION },
      });
    }
    case 'tools/list':
      return ok(id, { tools: [CHECK_CHANGE_TOOL] });
    case 'tools/call':
      return callTool(id, params, ctx);
    case 'ping':
      return ok(id, {});
    default:
      return fail(id, -32601, `Method not found: ${String(method)}`);
  }
}

/**
 * Run the stdio transport: read newline-delimited JSON-RPC from stdin, dispatch
 * each request, write responses to stdout. Resolves when stdin closes. A malformed
 * line is skipped (the server stays up).
 */
export function runStdioServer(ctx: McpContext): Promise<void> {
  return new Promise((resolve) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const raw = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!raw) {
          continue;
        }
        let request: unknown;
        try {
          request = JSON.parse(raw);
        } catch {
          continue; // skip a malformed line; keep serving
        }
        const response = handleRequest(request, ctx);
        if (response) {
          process.stdout.write(`${JSON.stringify(response)}\n`);
        }
      }
    });
    process.stdin.on('end', () => resolve());
  });
}
