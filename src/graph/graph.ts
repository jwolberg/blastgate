import { DirectedGraph } from 'graphology';
import type { AttackEdge, AttackNode, EntryNode, SinkNode } from './types';

/**
 * A thin, typed wrapper over a graphology directed graph. Node ids are stable
 * strings so analyzers in different layers can reference the same node (e.g. a
 * secret sink emitted by both the CI and agent layers). See plan U2 / KTD2.
 */
export class AttackGraph {
  readonly graph: DirectedGraph<AttackNode, AttackEdge>;

  constructor() {
    this.graph = new DirectedGraph<AttackNode, AttackEdge>({ allowSelfLoops: false });
  }

  /** Idempotent: adding a node with an existing id is a no-op. */
  addNode(node: AttackNode): void {
    if (!this.graph.hasNode(node.id)) {
      this.graph.addNode(node.id, node);
    }
  }

  /** Idempotent on (from, to): merges rather than throwing on a repeat edge. */
  addEdge(from: string, to: string, edge: AttackEdge): void {
    this.graph.mergeDirectedEdge(from, to, edge);
  }

  node(id: string): AttackNode {
    return this.graph.getNodeAttributes(id);
  }

  entryNodes(): EntryNode[] {
    return this.nodesOfKind('entry') as EntryNode[];
  }

  sinkNodes(): SinkNode[] {
    return this.nodesOfKind('sink') as SinkNode[];
  }

  private nodesOfKind(kind: AttackNode['kind']): AttackNode[] {
    const out: AttackNode[] = [];
    this.graph.forEachNode((_id, attrs) => {
      if (attrs.kind === kind) {
        out.push(attrs);
      }
    });
    return out;
  }
}
