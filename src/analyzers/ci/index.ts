import type { AgentAssessment, AttackNode, RepoVisibility } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import { assessAgentStep } from './agents';
import {
  agentActionsUsed,
  artifactSpliceStep,
  agentIngestedSteps,
  classifyUntrustedText,
  relayedTextEvents,
  credentialReachableTextTriggers,
  injectableTextRefs,
  injectionNeutralized,
  workflowRunArtifactInjection,
} from './injection';
import { locateSource } from './locate';
import {
  checksOutUntrustedRef,
  credentialReachableTriggers,
  findSecretRefs,
  hasActorGuard,
  hasInstallStep,
  installStep,
  normalizeTriggers,
  parseWorkflow,
  resolvePermissions,
  secretRefPaths,
  unpinnedActions,
  untrustedExecutionStep,
} from './parse';

export interface WorkflowInput {
  path: string;
  content: string;
}

export interface CiInputs {
  workflows: WorkflowInput[];
  /** Repository visibility for the agent exfiltration leg (KTD5); absent = `unknown`. */
  visibility?: RepoVisibility;
}

const CREDENTIAL_HINT = /(AWS|TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i;

function sinkKindFor(name: string): 'secret' | 'credential' {
  return CREDENTIAL_HINT.test(name) ? 'credential' : 'secret';
}

/**
 * CI (GitHub Actions) layer analyzer (U5). Emits a CI job node per job annotated
 * with triggers, secrets, and fork-triggerability; a secret sink per held secret;
 * a GITHUB_TOKEN credential sink for over-broad permissions; and a fork-PR entry
 * for jobs reachable from untrusted input. Cross-layer edges (an install script
 * running inside a job) are the engine's job (U7).
 */
/** The agent assessment closest to a fail: most legs held, then a covered version; first wins ties. */
function strongestAgent(
  candidates: { stepIndex: number; assessment: AgentAssessment }[],
): { stepIndex: number; assessment: AgentAssessment } | undefined {
  const score = (a: AgentAssessment): number =>
    [a.direct, a.access, a.exfil].filter((l) => l === 'held').length * 2 + (a.covered ? 1 : 0);
  return candidates.reduce<(typeof candidates)[number] | undefined>(
    (best, c) => (!best || score(c.assessment) > score(best.assessment) ? c : best),
    undefined,
  );
}

export function analyzeCi(inputs: CiInputs): AnalyzerResult {
  const result = emptyResult();
  // 0067: attacker text handed to a workflow through `workflow_run`, resolved across files.
  const relayed = relayedTextEvents(
    inputs.workflows.flatMap((w) => {
      try {
        return [{ path: w.path, spec: parseWorkflow(w.content) }];
      } catch {
        return [];
      }
    }),
  );

  for (const wf of inputs.workflows) {
    let spec;
    try {
      spec = parseWorkflow(wf.content);
    } catch (err) {
      result.diagnostics.push({
        level: 'error',
        message: `failed to parse ${wf.path}: ${(err as Error).message}`,
      });
      continue;
    }

    const triggers = normalizeTriggers(spec.on);
    const locator = locateSource(wf.content);
    // A fork/external actor reaches a secret or writable GITHUB_TOKEN only through an
    // event that runs privileged (base-repo context). Plain fork `pull_request` gets a
    // read-only token and no secrets, so it is NOT credential-reachable — excluding it
    // is the difference between a reachable path and a declared permission (R14).
    const credentialReachable = credentialReachableTriggers(triggers);
    const jobs = spec.jobs ?? {};

    for (const [jobId, job] of Object.entries(jobs)) {
      const { names: secretNames, usesAllSecrets } = findSecretRefs(job);
      const perms = resolvePermissions(spec, job);
      const jobNodeId = `job:${wf.path}#${jobId}`;
      const stepEvidence = (i: number | undefined) => {
        const line = i === undefined ? undefined : locator.line(['jobs', jobId, 'steps', i]);
        return line === undefined ? undefined : { file: wf.path, line };
      };
      // 0096: cite the line that runs the code (`run:` / `uses:`), not the step's `name:`.
      const execStep = untrustedExecutionStep(job, spec);
      const execField =
        execStep !== undefined && typeof job.steps?.[execStep]?.run === 'string' ? 'run' : 'uses';
      const execLine =
        execStep === undefined ? undefined : locator.stepLine(jobId, execStep, execField);
      const evidenceAt = (path: (string | number)[]) => {
        const line = locator.line(path);
        return line === undefined ? undefined : { file: wf.path, line };
      };
      // 0096: where the job exposes each sink, so a report can cite it.
      const exposure: Record<string, { file: string; line: number }> = {};
      for (const [name, path] of secretRefPaths(job)) {
        const at = evidenceAt(['jobs', jobId, ...path]);
        if (at) {
          exposure[name] = at;
        }
      }
      const tokenIdentity = `GITHUB_TOKEN (${perms.raw})`;
      const tokenAt =
        job.permissions !== undefined
          ? evidenceAt(['jobs', jobId, 'permissions'])
          : evidenceAt(['permissions']);
      if (perms.overBroad && tokenAt) {
        exposure[tokenIdentity] = tokenAt;
      }

      // 0041: attacker-triggerable is not enough — the job is credential-reachable only
      // when the attacker's code can actually RUN in it (an untrusted PR-head checkout).
      // A privileged job with no such checkout (the standard label/triage bot acting on
      // event metadata) holds a token but exposes no way to use it → not a finding. This
      // gate also flows to the cross-layer install-script path (build.ts keys `runs-in`
      // off `forkTriggerable`), so a fork's dependency is only "reachable" when the job
      // checks out and installs the fork's code.
      const forkTriggerable = credentialReachable.length > 0 && checksOutUntrustedRef(job);

      const jobNode: AttackNode = {
        id: jobNodeId,
        kind: 'ci-job',
        provider: 'github',
        workflow: wf.path,
        job: jobId,
        triggers,
        secrets: secretNames,
        forkTriggerable,
        runsInstall: hasInstallStep(job),
        execEvidence: execLine === undefined ? undefined : { file: wf.path, line: execLine },
        exposure,
        installEvidence: stepEvidence(installStep(job)),
      };
      result.nodes.push(jobNode);

      for (const name of secretNames) {
        const sinkId = `sink:secret:${name}`;
        result.nodes.push({
          id: sinkId,
          kind: 'sink',
          sinkKind: sinkKindFor(name),
          identity: name,
        });
        result.edges.push({ from: jobNodeId, to: sinkId, edge: { kind: 'holds' } });
      }

      if (perms.overBroad) {
        const tokenSink = `sink:credential:GITHUB_TOKEN@${wf.path}#${jobId}`;
        // 0047: only a token that can change repo code or mint cloud credentials is a
        // credential sink; PR/issue/comment/label write is a privileged capability (warn).
        result.nodes.push({
          id: tokenSink,
          kind: 'sink',
          sinkKind:
            perms.codeWrite || perms.mintsCredentials ? 'credential' : 'privileged-capability',
          identity: tokenIdentity,
        });
        result.edges.push({ from: jobNodeId, to: tokenSink, edge: { kind: 'holds' } });
      }

      if (forkTriggerable) {
        const entryId = `entry:fork-pr:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: 'entry',
          entryKind: 'fork-pr',
          exposure: 3,
          label: `${credentialReachable.join('/')} reaches job ${jobId}`,
          guarded: hasActorGuard(job),
        });
        result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: 'triggers' } });
      }

      // 0022/0042: attacker-controlled input reaching a sink is a prompt/command-injection
      // surface. Two shapes: (a) untrusted event *text* interpolated into a step or fed to a
      // coding agent — only on a privileged event (a plain fork `pull_request` gets a
      // read-only token / no secrets, so it is not a credential path); (b) a `workflow_run`
      // job that splices a downloaded (untrusted) artifact's contents into a shell (0042).
      // An actor guard (U17/0017) restricts who triggers it, so exempt it.
      const injectableEvents = credentialReachableTextTriggers(triggers);
      // 0044: the text-injection path is neutralized by a recognized guard (actor/label
      // gate, in-step github-script permission-check-with-throw) or by safe handling
      // (untrusted text only boolean-matched) — cutting the co-presence false positives the
      // top-50 scan surfaced. Artifact injection (0042) keys on a real shell-splice sink and
      // keeps only the original narrow actor-guard exemption.
      // 0046: classify WHERE the text lands; only a sink that could inject becomes an entry
      // (env-passed / boolean-compared text never does). Tiering by class is the engine's.
      // 0067: a relayed issue/PR reaches the job as a number, not text, so only an agent that
      // fetches and reads it ingests the text; other sinks need the job's own text events.
      const relayEvents = triggers.includes('workflow_run') ? (relayed.get(wf.path) ?? []) : [];
      const directSink =
        injectableEvents.length > 0 && !injectionNeutralized(job)
          ? classifyUntrustedText(job)
          : undefined;
      const relaySink =
        !directSink && relayEvents.length > 0 && !injectionNeutralized(job)
          ? classifyUntrustedText(job)
          : undefined;
      const textSink =
        directSink ?? (relaySink?.sinkClass === 'agent-ingested' ? relaySink : undefined);
      const textEvents =
        directSink !== undefined
          ? injectableEvents.join('/')
          : `${relayEvents.join('/')} (relayed via workflow_run)`;
      const spliceStep =
        workflowRunArtifactInjection(job, triggers) && !hasActorGuard(job)
          ? artifactSpliceStep(job)
          : undefined;
      // The artifact splice is an execution sink; it wins over a weaker text sink.
      const artifactWins =
        spliceStep !== undefined && (!textSink || textSink.sinkClass !== 'execution');
      // 0059: judge every agent step against the Rule of Two and keep the strongest, so a
      // tool-less LLM step ahead of a fail-capable agent cannot mask it.
      const agent =
        !artifactWins && textSink?.sinkClass === 'agent-ingested'
          ? strongestAgent(
              agentIngestedSteps(job).map((stepIndex) => ({
                stepIndex,
                assessment: assessAgentStep({
                  workflow: spec,
                  job,
                  stepIndex,
                  visibility: inputs.visibility ?? 'unknown',
                  relayedEvents: relayEvents,
                }),
              })),
            )
          : undefined;
      const sinkPath = artifactWins
        ? ['steps', spliceStep, 'run']
        : agent
          ? ['steps', agent.stepIndex, 'uses']
          : textSink?.path;
      if (sinkPath) {
        const refs = injectableTextRefs(job);
        const via = refs.length > 0 ? refs.join(', ') : agentActionsUsed(job).join(', ');
        const label = artifactWins
          ? `untrusted workflow_run artifact reaches a shell in job ${jobId}`
          : `untrusted ${textEvents} text reaches job ${jobId} (${via})`;
        const line = locator.line(['jobs', jobId, ...sinkPath]);
        const entryId = `entry:injection:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: 'entry',
          entryKind: 'untrusted-text-injection',
          exposure: 3,
          label,
          guarded: false,
          sinkClass: artifactWins ? 'execution' : textSink?.sinkClass,
          evidence: line === undefined ? undefined : { file: wf.path, line },
          // 0059: judge the agent step against the Rule of Two; the engine fails it only
          // when all three legs hold.
          agent: agent?.assessment,
        });
        result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: 'injects' } });
      }

      for (const u of unpinnedActions(job)) {
        result.diagnostics.push({
          level: 'warn',
          message: `unpinned action \`${u}\` in ${wf.path}#${jobId} (pin to a full commit SHA)`,
        });
      }
      if (perms.overBroad) {
        result.diagnostics.push({
          level: 'warn',
          message: `over-broad GITHUB_TOKEN permissions (${perms.raw}) on ${wf.path}#${jobId}`,
        });
      }
      if (usesAllSecrets || job.secrets === 'inherit') {
        result.diagnostics.push({
          level: 'warn',
          message: `${wf.path}#${jobId} exposes the full secret set (toJSON(secrets) or secrets: inherit)`,
        });
      }
      if (hasInstallStep(job) && forkTriggerable && (secretNames.length > 0 || perms.overBroad)) {
        result.diagnostics.push({
          level: 'warn',
          message: `pwn-request shape: ${wf.path}#${jobId} runs install on an untrusted trigger while holding secrets`,
        });
      }
    }
  }

  return result;
}
