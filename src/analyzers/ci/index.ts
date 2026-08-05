import type { AttackNode } from '../../graph/types';
import { type AnalyzerResult, emptyResult } from '../types';
import {
  agentActionsUsed,
  injectableTextRefs,
  isInjectableAgentJob,
  untrustedTextTriggers,
} from './injection';
import {
  findSecretRefs,
  hasActorGuard,
  hasInstallStep,
  normalizeTriggers,
  parseWorkflow,
  resolvePermissions,
  unpinnedActions,
  untrustedTriggers,
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
    const untrusted = untrustedTriggers(triggers);
    const forkTriggerable = untrusted.length > 0;
    const jobs = spec.jobs ?? {};

    for (const [jobId, job] of Object.entries(jobs)) {
      const { names: secretNames, usesAllSecrets } = findSecretRefs(job);
      const perms = resolvePermissions(spec, job);
      const jobNodeId = `job:${wf.path}#${jobId}`;

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
          label: `${untrusted.join('/')} reaches job ${jobId}`,
          guarded: hasActorGuard(job),
        });
        result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: 'triggers' } });
      }

      // 0022: attacker-authored event text reaching an agent/step is a prompt-injection
      // surface. An actor guard (U17/0017) restricts who triggers it, so exempt it.
      if (isInjectableAgentJob(job, triggers) && !hasActorGuard(job)) {
        const refs = injectableTextRefs(job);
        const via = refs.length > 0 ? refs.join(', ') : agentActionsUsed(job).join(', ');
        const entryId = `entry:injection:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: 'entry',
          entryKind: 'untrusted-text-injection',
          exposure: 3,
          label: `untrusted ${untrustedTextTriggers(triggers).join('/')} text reaches job ${jobId} (${via})`,
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
