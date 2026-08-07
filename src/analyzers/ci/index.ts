import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import {
  agentActionsUsed,
  credentialReachableTextTriggers,
  injectableTextRefs,
  injectionNeutralized,
  isInjectableAgentJob,
  workflowRunArtifactInjection,
} from './injection';
import {
  checksOutUntrustedRef,
  credentialReachableTriggers,
  findSecretRefs,
  hasActorGuard,
  hasInstallStep,
  normalizeTriggers,
  parseWorkflow,
  resolvePermissions,
  unpinnedActions,
} from './parse';

export interface WorkflowInput {
  path: string;
  content: string;
}

export interface CiInputs {
  workflows: WorkflowInput[];
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
export function analyzeCi(inputs: CiInputs): AnalyzerResult {
  const result = emptyResult();

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
        result.nodes.push({
          id: tokenSink,
          kind: 'sink',
          sinkKind: 'credential',
          identity: `GITHUB_TOKEN (${perms.raw})`,
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
      const textInjection =
        injectableEvents.length > 0 &&
        isInjectableAgentJob(job, triggers) &&
        !injectionNeutralized(job);
      const artifactInjection = workflowRunArtifactInjection(job, triggers) && !hasActorGuard(job);
      if (textInjection || artifactInjection) {
        const refs = injectableTextRefs(job);
        const via = refs.length > 0 ? refs.join(', ') : agentActionsUsed(job).join(', ');
        const label =
          artifactInjection && !textInjection
            ? `untrusted workflow_run artifact reaches a shell in job ${jobId}`
            : `untrusted ${injectableEvents.join('/')} text reaches job ${jobId} (${via})`;
        const entryId = `entry:injection:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: 'entry',
          entryKind: 'untrusted-text-injection',
          exposure: 3,
          label,
          guarded: false,
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
