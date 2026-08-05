/**
 * OWASP taxonomy map — the single, versioned source for finding labels (KTD9).
 *
 * Agentic: OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10), the
 * canonical genai.owasp.org ranked list.
 * MCP: OWASP MCP Top 10 (MCP01–MCP10) — DRAFT (v0.1 beta, final ~Oct 2026); the
 * version is pinned here so a renumber is a one-file change and findings never
 * carry an unversioned category.
 */

export const OWASP_AGENTIC_VERSION = '2026';
export const OWASP_MCP_VERSION = '2025';

export type AgenticId =
  'ASI01' | 'ASI02' | 'ASI03' | 'ASI04' | 'ASI05' | 'ASI06' | 'ASI07' | 'ASI08' | 'ASI09' | 'ASI10';

export type McpId =
  'MCP01' | 'MCP02' | 'MCP03' | 'MCP04' | 'MCP05' | 'MCP06' | 'MCP07' | 'MCP08' | 'MCP09' | 'MCP10';

export const AGENTIC_TOP_10: Record<AgenticId, string> = {
  ASI01: 'Agent Goal Hijack',
  ASI02: 'Tool Misuse & Exploitation',
  ASI03: 'Identity & Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities',
  ASI05: 'Unexpected Code Execution (RCE)',
  ASI06: 'Memory & Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication',
  ASI08: 'Cascading Failures',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
};

export const MCP_TOP_10: Record<McpId, string> = {
  MCP01: 'Token Mismanagement & Secret Exposure',
  MCP02: 'Privilege Escalation via Scope Creep',
  MCP03: 'Tool Poisoning',
  MCP04: 'Software Supply Chain Attacks & Dependency Tampering',
  MCP05: 'Command Injection & Execution',
  MCP06: 'Intent Flow Subversion',
  MCP07: 'Insufficient Authentication & Authorization',
  MCP08: 'Lack of Audit and Telemetry',
  MCP09: 'Shadow MCP Servers',
  MCP10: 'Context Injection & Over-Sharing',
};

/** Versioned display label, e.g. `ASI04:2026`. */
export function agenticLabel(id: AgenticId): string {
  return `${id}:${OWASP_AGENTIC_VERSION}`;
}

/** Versioned display label, e.g. `MCP02:2025`. */
export function mcpLabel(id: McpId): string {
  return `${id}:${OWASP_MCP_VERSION}`;
}
