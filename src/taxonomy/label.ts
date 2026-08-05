import type { ReachPath } from '../graph/reachability';
import type { AgenticId, McpId } from './owasp';

/** Zero-or-one Agentic and zero-or-one MCP category per finding (KTD9). */
export interface OwaspLabels {
  agentic?: AgenticId;
  mcp?: McpId;
}

/**
 * Assign OWASP categories to a reachable path by archetype (KTD9):
 * - new dependency / install script → ASI04 (Agentic Supply Chain) + MCP04
 *   (Dependency Tampering)
 * - fork-triggerable CI reaching a secret → ASI03 (Identity & Privilege Abuse);
 *   no MCP category unless an agent grant is on the path (pure-CI findings have
 *   no MCP-server relevance — "no applicable MCP category")
 * - prompt-injectable agent surface → ASI01 (Agent Goal Hijack) + MCP10
 *   (Context Injection & Over-Sharing)
 * - committed command hook (deterministic, not injectable) → ASI03 (Identity &
 *   Privilege Abuse) + MCP02 (Privilege Escalation via Scope Creep). It is a standing
 *   over-privilege, so it carries no ASI01 goal-hijack claim (U18).
 * - any path through an over-baseline agent grant is scope creep → MCP02, which
 *   takes precedence over the entry-derived MCP category.
 */
export function labelPath(path: ReachPath): OwaspLabels {
  const hasOverBaselineGrant = path.nodes.some(
    (n) => n.kind === 'agent-grant' && n.exceedsBaseline,
  );

  let agentic: AgenticId | undefined;
  let mcp: McpId | undefined;

  switch (path.entry.entryKind) {
    case 'new-dependency':
      agentic = 'ASI04';
      mcp = 'MCP04';
      break;
    case 'fork-pr':
      agentic = 'ASI03';
      mcp = undefined;
      break;
    case 'injectable-agent-surface':
      agentic = 'ASI01';
      mcp = 'MCP10';
      break;
    case 'privileged-hook':
      agentic = 'ASI03';
      mcp = 'MCP02';
      break;
  }

  if (hasOverBaselineGrant) {
    mcp = 'MCP02';
    agentic ??= 'ASI03';
  }

  return { agentic, mcp };
}
