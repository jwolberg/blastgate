/**
 * Engine — reachability → ranking → assembled findings (U7 step 2).
 *
 * Runs the graph reachability (per entry, sink), ranks + labels each path (U3),
 * and assembles the stable `Finding` shape: concrete path, sink, a reachability
 * reason, a remediation, and OWASP labels. Reason/remediation are derived from the
 * path's archetype (which layers it crosses), not free-form.
 */

import { rankFindings, type RankedFinding } from '../graph/ranking';
import { reachablePaths, type ReachPath } from '../graph/reachability';
import type {
  AgentGrantNode,
  AttackNode,
  CiJobNode,
  DependencyNode,
  SinkNode,
} from '../graph/types';
import { type Finding, tierForSink } from '../findings/finding';
import { agenticLabel, mcpLabel } from '../taxonomy/owasp';
import type { BuildResult } from './build';

/** A short human label for a node in a rendered path. */
function nodeLabel(n: AttackNode): string {
  switch (n.kind) {
    case 'entry':
      return n.label;
    case 'dependency':
      return `${n.pkg}@${n.version}`;
    case 'ci-job':
      return `${n.workflow}#${n.job}`;
    case 'agent-grant':
      return `${n.source} (${n.capabilityClass}:${n.scope})`;
    case 'sink':
      return n.identity;
  }
}

function find<T extends AttackNode>(path: ReachPath, kind: T['kind']): T | undefined {
  return path.nodes.find((n): n is T => n.kind === kind);
}

/** A fork-PR path whose triggering job is actor-gated to trusted roles (U17). */
function isGuardedForkPr(path: ReachPath): boolean {
  return path.entry.entryKind === 'fork-pr' && path.entry.guarded === true;
}

/** Derive the reachability reason + remediation from the path's cross-layer shape. */
function describe(path: ReachPath): { reason: string; remediation: string } {
  const dep = find<DependencyNode>(path, 'dependency');
  const job = find<CiJobNode>(path, 'ci-job');
  const grant = find<AgentGrantNode>(path, 'agent-grant');
  const sink: SinkNode = path.sink;
  const isSecret = sink.sinkKind === 'secret' || sink.sinkKind === 'credential';

  if (path.entry.entryKind === 'untrusted-text-injection') {
    const where = job ? `${job.workflow}#${job.job}` : 'the workflow';
    return {
      reason:
        `${path.entry.label} — attacker-authored text from an untrusted event is read by job ${where}, ` +
        `which holds ${sink.sinkKind} ${sink.identity}. A prompt/command injection in that text (e.g. an ` +
        `HTML comment invisible on the rendered page but read via the API) can drive the job to exfiltrate it.`,
      remediation:
        `Do not pass untrusted event text (issue/PR/comment body) into a privileged step; restrict the ` +
        `workflow to trusted actors (author_association / github.actor) and remove ${sink.identity} from the ` +
        `untrusted-triggered job.`,
    };
  }

  if (path.entry.entryKind === 'ci-divergent') {
    return {
      reason:
        `${path.entry.label} — an install/build script that changes behavior based on whether ` +
        `it runs in CI, a container, or an interactive terminal is the concealment technique used ` +
        `to keep a malicious lifecycle payload dormant exactly where it would be observed.`,
      remediation:
        `Remove the environment-conditional branch from the install/build script (or justify it in ` +
        `review); where lifecycle scripts are not required, install with \`npm ci --ignore-scripts\`.`,
    };
  }

  if (path.entry.entryKind === 'privileged-hook') {
    const location = path.entry.label.replace(/ \(committed hook\)$/, '');
    return {
      reason:
        `${path.entry.label} runs a shell command outside Claude Code's permission gate — a ` +
        `standing privileged capability (${sink.identity}). It fires deterministically, not via ` +
        `prompt injection, so it is not externally attacker-controllable; the risk is an ` +
        `over-scoped or untrusted hook command.`,
      remediation:
        `Review the hook command in ${location}, keep it minimal and repo-local, and remove the ` +
        `hook if it is not required.`,
    };
  }

  if (dep && job && isSecret) {
    const untrusted = job.forkTriggerable
      ? ', which is triggered by untrusted input (fork PRs)'
      : '';
    return {
      reason:
        `New or changed dependency ${dep.pkg}@${dep.version} declares an install script that ` +
        `executes in job ${job.workflow}#${job.job}${untrusted} and holds ${sink.sinkKind} ` +
        `${sink.identity}, which the script can exfiltrate.`,
      remediation:
        `Gate lifecycle scripts in that job (e.g. run \`npm ci --ignore-scripts\`) or remove ` +
        `${sink.identity} from ${job.workflow}#${job.job}.`,
    };
  }

  if (grant && isSecret) {
    return {
      reason:
        `Injectable agent surface ${grant.source} grants ${grant.capabilityClass} capability ` +
        `(${grant.scope}) that can read and exfiltrate ${sink.sinkKind} ${sink.identity}.`,
      remediation:
        `Scope the ${grant.capabilityClass} grant in ${grant.source} to the minimum required, ` +
        `or keep ${sink.identity} out of the agent's reach.`,
    };
  }

  if (grant) {
    return {
      reason:
        `Injectable agent surface ${grant.source} grants ${grant.capabilityClass} capability ` +
        `(${grant.scope}) that exceeds the least-privilege baseline and reaches ${sink.identity}.`,
      remediation:
        `Scope the ${grant.capabilityClass} grant in ${grant.source} down to the minimum ` +
        `required path/host, or remove it.`,
    };
  }

  if (job && isSecret) {
    if (isGuardedForkPr(path)) {
      return {
        reason:
          `Job ${job.workflow}#${job.job} triggers on untrusted events ` +
          `(${job.triggers.join(', ')}) and holds ${sink.sinkKind} ${sink.identity}, but its ` +
          `\`if:\` is actor-gated to trusted roles — so it is not externally triggerable, though ` +
          `the broad credential scope remains a least-privilege risk.`,
        remediation:
          `Scope ${sink.identity} down to least privilege for ${job.workflow}#${job.job}; the ` +
          `actor guard limits who can trigger the job but not its blast radius when it runs.`,
      };
    }
    return {
      reason:
        `Job ${job.workflow}#${job.job} is triggered by untrusted input ` +
        `(${job.triggers.join(', ')}) and holds ${sink.sinkKind} ${sink.identity}, which is ` +
        `exfiltratable from an untrusted run.`,
      remediation:
        `Remove ${sink.identity} from the untrusted-triggerable job ${job.workflow}#${job.job}, ` +
        `or restrict its triggers to trusted events.`,
    };
  }

  return {
    reason: `${path.entry.label} reaches ${sink.sinkKind} ${sink.identity} in ${path.hops} hop(s).`,
    remediation: `Break the path from ${path.entry.label} to ${sink.identity}.`,
  };
}

function toFinding(ranked: RankedFinding): Finding {
  const { path, labels, score } = ranked;
  const { reason, remediation } = describe(path);
  const labelStrings = [
    labels.agentic ? agenticLabel(labels.agentic) : undefined,
    labels.mcp ? mcpLabel(labels.mcp) : undefined,
  ].filter((s): s is string => s !== undefined);

  return {
    id: `${path.entry.id}=>${path.sink.id}`,
    // An actor-gated fork-PR path is not externally attacker-controllable → warn, not
    // fail (U17); still reported because the broad credential scope is a real risk.
    tier: isGuardedForkPr(path) ? 'warn' : tierForSink(path.sink.sinkKind),
    score,
    path: path.nodes.map(nodeLabel),
    pathNodeIds: path.nodes.map((n) => n.id),
    hops: path.hops,
    entry: { kind: path.entry.entryKind, label: path.entry.label },
    sink: { kind: path.sink.sinkKind, identity: path.sink.identity },
    reason,
    remediation,
    owasp: labels,
    labels: labelStrings,
  };
}

/** Most-severe first, with a fully deterministic tie-break for byte-identical output. */
function compareFindings(a: Finding, b: Finding): number {
  if (a.score !== b.score) {
    return b.score - a.score;
  }
  if (a.hops !== b.hops) {
    return a.hops - b.hops;
  }
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** Assemble ranked findings from a built graph (U7 step 2). */
export function assembleFindings(build: BuildResult): Finding[] {
  return rankFindings(reachablePaths(build.graph)).map(toFinding).sort(compareFindings);
}
