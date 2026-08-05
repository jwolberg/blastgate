/**
 * Engine — graph build + cross-layer edge synthesis (U7).
 *
 * Runs the three layer analyzers over already-collected repo inputs, merges their
 * nodes and intra-layer edges into one graph, then adds the cross-layer edges the
 * analyzers structurally could not: an install-script dependency `runs-in` a CI
 * job that runs an install step and is attacker-triggerable. This is where the
 * cross-layer attack path becomes real. Analyzers stay pure emitters; the engine
 * owns all cross-layer synthesis. Filesystem collection (a repo path → inputs) is
 * the CLI's job (U9); this module is pure and offline (KTD6).
 */

import { analyzeAgentDiff, type AgentDiffInputs } from '../analyzers/agent/config-diff';
import { analyzeAgents, type AgentInputs } from '../analyzers/agent/index';
import { analyzeCi, type CiInputs } from '../analyzers/ci/index';
import { analyzeDependencies, type DependencyInputs } from '../analyzers/deps/index';
import { analyzeExec, type ExecInputs } from '../analyzers/exec/index';
import { type AnalyzerResult, applyResult, type Diagnostic } from '../analyzers/types';
import { AttackGraph } from '../graph/graph';
import type { CiJobNode, DependencyNode } from '../graph/types';
import type { Acknowledgement } from './acknowledge';

/** Per-layer inputs; an omitted layer is simply not analyzed. */
export interface EngineInputs {
  deps?: DependencyInputs;
  ci?: CiInputs;
  agent?: AgentInputs;
  /** Repo-own install/build lifecycle scripts scanned for CI-divergent execution (0021). */
  exec?: ExecInputs;
  /** Agent instruction files added/changed by the diff — review-time injection (0023). */
  agentDiff?: AgentDiffInputs;
  /** Human-accepted findings (`.blastgate/acknowledged.json`); downgrades fail→warn (U14). */
  acknowledged?: Acknowledgement[];
  /**
   * Acks introduced by the diff (present at head, absent on base) that were NOT
   * honored (0019) — a PR cannot self-approve its own findings. Surfaced as a warn.
   */
  acknowledgedIgnored?: Acknowledgement[];
  /**
   * Pre-computed provenance-regression result (U8). The engine core is offline
   * (KTD6); the network-touching provenance analyzer runs in the CLI behind
   * `--provenance` and passes its result here to be merged like any other layer.
   */
  provenance?: AnalyzerResult;
}

export interface BuildResult {
  graph: AttackGraph;
  /** Merged analyzer diagnostics (parse errors, warn-level hygiene notes). */
  diagnostics: Diagnostic[];
}

/**
 * An install-script dependency's poisoned lifecycle code runs in any job that runs
 * an install step — but it is only an *attacker-reachable* sink path when that job
 * is triggerable by untrusted input (a fork PR carrying the malicious change). A
 * push-only install job runs the script only after a maintainer merges (trusted),
 * so it is not an external attack path — this keeps precision high (R14) and
 * matches the plan's non-fork integration negative.
 */
function synthesizeCrossLayerEdges(ag: AttackGraph): void {
  const deps: DependencyNode[] = [];
  const jobs: CiJobNode[] = [];
  ag.graph.forEachNode((_id, n) => {
    if (n.kind === 'dependency') {
      deps.push(n);
    } else if (n.kind === 'ci-job') {
      jobs.push(n);
    }
  });

  for (const dep of deps) {
    if (!dep.hasInstallScript) {
      continue;
    }
    for (const job of jobs) {
      if (job.runsInstall && job.forkTriggerable) {
        ag.addEdge(dep.id, job.id, { kind: 'runs-in' });
      }
    }
  }
}

/** Build the unified attack-surface graph from per-layer inputs (U7 step 1). */
export function buildGraph(inputs: EngineInputs): BuildResult {
  const ag = new AttackGraph();
  const diagnostics: Diagnostic[] = [];

  const results = [
    inputs.deps ? analyzeDependencies(inputs.deps) : undefined,
    inputs.ci ? analyzeCi(inputs.ci) : undefined,
    inputs.agent ? analyzeAgents(inputs.agent) : undefined,
    inputs.exec ? analyzeExec(inputs.exec) : undefined,
    inputs.agentDiff ? analyzeAgentDiff(inputs.agentDiff) : undefined,
    // Merged last: its entry→dep edge targets a dependency node the deps analyzer emits.
    inputs.provenance,
  ];
  for (const result of results) {
    if (!result) {
      continue;
    }
    applyResult(ag, result);
    diagnostics.push(...result.diagnostics);
  }

  synthesizeCrossLayerEdges(ag);
  return { graph: ag, diagnostics };
}
