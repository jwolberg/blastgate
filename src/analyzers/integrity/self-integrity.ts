/**
 * Self-integrity analyzer (0024).
 *
 * Blastgate runs on every commit with repo access and ships via a marketplace, so
 * the obvious bypass is an agent disabling the gate before doing the thing the gate
 * blocks. When a change removes Blastgate's own enforcement from a gate-config file
 * — a hook that was wired at base is gone at head — that is itself a finding.
 *
 * Warn, not fail: removal can be a legitimate un-adoption, so it is surfaced loudly
 * for review rather than hard-blocking. It fires only when the gate WAS wired at
 * base (a repo that never used Blastgate is never flagged).
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';

/** Files that wire Blastgate's enforcement into a consuming repo. */
export const GATE_CONFIG_PATHS = ['plugin/hooks/hooks.json', '.mcp.json', '.claude/settings.json'];

const REFERENCES_GATE = /blastgate/i;

export interface GateConfigFile {
  path: string;
  head: string | null;
  base: string | null;
}

export interface SelfIntegrityInputs {
  files: GateConfigFile[];
}

/** True when Blastgate's enforcement was present at base but is gone at head (removed/deleted). */
export function gateEnforcementRemoved(f: GateConfigFile): boolean {
  const wasWired = f.base !== null && REFERENCES_GATE.test(f.base);
  const stillWired = f.head !== null && REFERENCES_GATE.test(f.head);
  return wasWired && !stillWired;
}

export function analyzeSelfIntegrity(inputs: SelfIntegrityInputs): AnalyzerResult {
  const result = emptyResult();
  for (const f of inputs.files) {
    if (!gateEnforcementRemoved(f)) {
      continue;
    }
    const entryId = `entry:gate-tamper:${f.path}`;
    const sinkId = `sink:gate-integrity:${f.path}`;
    const entry: AttackNode = {
      id: entryId,
      kind: 'entry',
      entryKind: 'gate-tamper',
      exposure: 3,
      label: `Blastgate enforcement removed from ${f.path}`,
    };
    const sink: AttackNode = {
      id: sinkId,
      kind: 'sink',
      sinkKind: 'privileged-capability',
      identity: `gate enforcement (${f.path})`,
    };
    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: 'injects' } });
  }
  return result;
}
