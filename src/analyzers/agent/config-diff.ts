/**
 * Agent-config diff analyzer (0023).
 *
 * A fork/untrusted PR that adds or edits an agent *instruction* file is a prompt
 * injection against any maintainer who reviews the change with a coding agent —
 * the same class as lockfile poisoning. The capability analyzer (`./index`) sees
 * `.mcp.json`/`.claude/settings.json` grants; this sees the free-text instruction
 * files it cannot (CLAUDE.md, AGENTS.md, .cursorrules), and only flags them when
 * the diff introduces them (a repo's own committed CLAUDE.md is not a finding).
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';

/** Free-text agent instruction files that steer a coding agent (not capability grants). */
export const AGENT_INSTRUCTION_PATHS = [
  'CLAUDE.md',
  'AGENTS.md',
  '.cursorrules',
  '.github/copilot-instructions.md',
];

export interface AgentConfigFile {
  path: string;
  /** Contents at head, or null if absent. */
  head: string | null;
  /** Contents at the diff base, or null if absent (or no base). */
  base: string | null;
}

export interface AgentDiffInputs {
  files: AgentConfigFile[];
}

export type ChangeKind = 'added' | 'changed';

/** Whether the diff introduces this instruction file. Removed/unchanged/absent → null. */
export function classifyConfigChange(f: AgentConfigFile): ChangeKind | null {
  if (f.head === null) {
    return null;
  }
  if (f.base === null) {
    return 'added';
  }
  return f.base === f.head ? null : 'changed';
}

export function analyzeAgentDiff(inputs: AgentDiffInputs): AnalyzerResult {
  const result = emptyResult();
  for (const f of inputs.files) {
    const change = classifyConfigChange(f);
    if (!change) {
      continue;
    }
    const entryId = `entry:agent-config-change:${f.path}`;
    const sinkId = `sink:agent-config:${f.path}`;
    const entry: AttackNode = {
      id: entryId,
      kind: 'entry',
      entryKind: 'agent-config-change',
      exposure: 3,
      label: `agent instruction file ${f.path} ${change} by this change`,
    };
    const sink: AttackNode = {
      id: sinkId,
      kind: 'sink',
      sinkKind: 'privileged-capability',
      identity: `agent instructions (${f.path})`,
    };
    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: 'injects' } });
  }
  return result;
}
