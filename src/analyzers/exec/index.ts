/**
 * Execution layer analyzer (0021, offline). Flags CI-divergent execution in the
 * repo's OWN install/build lifecycle scripts — code engineered to behave
 * differently under observation (CI / a container / a TTY), the concealment used
 * by the AISI Mythos-5 dropper to stay dormant where it would be noticed.
 *
 * Emits a `ci-divergent` entry node reaching a `privileged-capability` sink
 * (install/build-time execution) → a warn-tier finding: a heuristic never hard-
 * fails a build (KTD4/R14). Escalation to a fail when the divergent script also
 * reaches a secret-bearing job is a follow-on. The detector is `./divergence`.
 */

import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import { detectDivergence, type DivergenceKind } from './divergence';

/** One install/build script (its command string, or a local file it invokes) to scan. */
export interface ExecScript {
  /** A label, e.g. `postinstall` or `postinstall → scripts/setup.js`. */
  name: string;
  /** The source to scan. */
  source: string;
}

export interface ExecInputs {
  scripts: ExecScript[];
}

const KIND_LABEL: Record<DivergenceKind, string> = {
  ci: 'CI',
  container: 'a container',
  tty: 'an interactive terminal',
};

export function analyzeExec(inputs: ExecInputs): AnalyzerResult {
  const result = emptyResult();

  for (const script of inputs.scripts) {
    const hits = detectDivergence(script.source);
    if (hits.length === 0) {
      continue;
    }
    const environs = [...new Set(hits.map((h) => KIND_LABEL[h.kind]))].join(' / ');
    const markers = [...new Set(hits.map((h) => h.marker))].join(', ');
    const entryId = `entry:ci-divergent:${script.name}`;
    const sinkId = `sink:exec:${script.name}`;

    const entry: AttackNode = {
      id: entryId,
      kind: 'entry',
      entryKind: 'ci-divergent',
      exposure: 2,
      label: `install/build script ${script.name} runs differently under ${environs} (${markers})`,
    };
    const sink: AttackNode = {
      id: sinkId,
      kind: 'sink',
      sinkKind: 'privileged-capability',
      identity: `install/build-time execution (${script.name})`,
    };

    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: 'reaches' } });
  }

  return result;
}
