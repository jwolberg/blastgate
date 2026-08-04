import type { AnalyzerResult } from '../types';
import { emptyResult } from '../types';
import {
  classifyRule,
  classifyServer,
  type Grant,
  hasCommandHook,
  type McpServer,
} from './capability';

export interface AgentInputs {
  /** .mcp.json contents. */
  mcpJson?: string | null;
  /** .claude/settings.json contents. */
  claudeSettings?: string | null;
  /** .cursor/mcp.json contents. */
  cursorMcpJson?: string | null;
}

function parseServers(source: string, json: string, result: AnalyzerResult): Grant[] {
  try {
    const data = JSON.parse(json) as { mcpServers?: Record<string, McpServer> };
    const servers = data.mcpServers ?? {};
    return Object.entries(servers).flatMap(([name, server]) =>
      classifyServer(source, name, server),
    );
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse ${source}: ${(err as Error).message}`,
    });
    return [];
  }
}

function parseSettings(json: string, result: AnalyzerResult): Grant[] {
  try {
    const data = JSON.parse(json) as {
      permissions?: { allow?: string[]; ask?: string[] };
      hooks?: unknown;
    };
    const grants: Grant[] = [];
    const rules = [...(data.permissions?.allow ?? []), ...(data.permissions?.ask ?? [])];
    for (const rule of rules) {
      const grant = classifyRule('.claude/settings.json', rule);
      if (grant) {
        grants.push(grant);
      }
    }
    if (hasCommandHook(data.hooks)) {
      grants.push({
        source: '.claude/settings.json (hook)',
        capabilityClass: 'shell',
        scope: 'command hook',
        exceedsBaseline: true,
      });
    }
    return grants;
  } catch (err) {
    result.diagnostics.push({
      level: 'error',
      message: `failed to parse .claude/settings.json: ${(err as Error).message}`,
    });
    return [];
  }
}

function emitGrant(result: AnalyzerResult, grant: Grant, index: number): void {
  const grantId = `grant:${grant.source}:${grant.capabilityClass}:${index}`;
  result.nodes.push({
    id: grantId,
    kind: 'agent-grant',
    source: grant.source,
    capabilityClass: grant.capabilityClass,
    scope: grant.scope,
    exceedsBaseline: grant.exceedsBaseline,
  });
  if (!grant.exceedsBaseline) {
    return;
  }
  const entryId = `entry:agent:${grant.source}`;
  const sinkId = `sink:capability:${grant.capabilityClass}:${grant.scope}`;
  result.nodes.push({
    id: entryId,
    kind: 'entry',
    entryKind: 'injectable-agent-surface',
    exposure: 2,
    label: `injectable agent surface (${grant.source})`,
  });
  result.nodes.push({
    id: sinkId,
    kind: 'sink',
    sinkKind: 'privileged-capability',
    identity: `${grant.capabilityClass}:${grant.scope}`,
  });
  result.edges.push({ from: entryId, to: grantId, edge: { kind: 'injects' } });
  result.edges.push({ from: grantId, to: sinkId, edge: { kind: 'reaches' } });
  result.diagnostics.push({
    level: 'warn',
    message: `${grant.source}: ${grant.capabilityClass} grant "${grant.scope}" exceeds the least-privilege baseline (OWASP MCP02)`,
  });
}

/**
 * Agent/MCP layer analyzer (U6). Parses committed agent config — Claude Code
 * first (.mcp.json, .claude/settings.json permissions + hooks), then Cursor —
 * into fs/network/shell/tool capability grants, flags grants exceeding the
 * least-privilege baseline, and for each over-baseline grant emits an injectable
 * agent-surface entry and a privileged-capability sink (AE4). Cross-layer wiring
 * to CI secrets is the engine's job (U7).
 */
export function analyzeAgents(inputs: AgentInputs): AnalyzerResult {
  const result = emptyResult();
  const grants: Grant[] = [];
  if (inputs.mcpJson) {
    grants.push(...parseServers('.mcp.json', inputs.mcpJson, result));
  }
  if (inputs.cursorMcpJson) {
    grants.push(...parseServers('.cursor/mcp.json', inputs.cursorMcpJson, result));
  }
  if (inputs.claudeSettings) {
    grants.push(...parseSettings(inputs.claudeSettings, result));
  }
  grants.forEach((grant, index) => emitGrant(result, grant, index));
  return result;
}
