import type { AttackGraph } from '../graph/graph';
import type { AttackEdge, AttackNode } from '../graph/types';

export interface EmittedEdge {
  from: string;
  to: string;
  edge: AttackEdge;
}

export interface Diagnostic {
  level: 'error' | 'warn';
  message: string;
}

/**
 * What every layer analyzer returns: pure data (nodes, intra-layer edges,
 * diagnostics) the engine merges into one graph. Analyzers never mutate a shared
 * graph directly and never synthesize cross-layer edges — that is the engine's
 * job (U7).
 */
export interface AnalyzerResult {
  nodes: AttackNode[];
  edges: EmittedEdge[];
  diagnostics: Diagnostic[];
}

export function emptyResult(): AnalyzerResult {
  return { nodes: [], edges: [], diagnostics: [] };
}

/** Merge an analyzer result into a graph: nodes first, then intra-layer edges. */
export function applyResult(ag: AttackGraph, result: AnalyzerResult): void {
  for (const node of result.nodes) {
    ag.addNode(node);
  }
  for (const e of result.edges) {
    ag.addEdge(e.from, e.to, e.edge);
  }
}
