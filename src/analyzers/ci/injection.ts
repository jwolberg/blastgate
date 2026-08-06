/**
 * Untrusted-text → agent injection detection (0022).
 *
 * The AISI Mythos-5 injection lived in a GitHub issue read by an AI triage agent.
 * Blastgate scans committed workflows offline, so what it can see deterministically
 * is the *configuration* that opens the path: a job triggered by an event that
 * carries attacker-authored free text, which then either pipes that text into a
 * step or runs a coding-agent action that ingests the event by design. When that
 * job also holds a secret/token, the injection is a reachable exfiltration path.
 */

import { collectStrings, type JobSpec } from './parse';

/** Events that carry attacker-authored free text (issue/PR/discussion bodies, comments). */
export const UNTRUSTED_TEXT_EVENTS = new Set([
  'issues',
  'issue_comment',
  'pull_request_target',
  'pull_request',
  'pull_request_review',
  'pull_request_review_comment',
  'discussion',
  'discussion_comment',
]);

export function untrustedTextTriggers(triggers: string[]): string[] {
  return triggers.filter((t) => UNTRUSTED_TEXT_EVENTS.has(t));
}

/**
 * Untrusted-text events that ALSO run privileged (base-repo context), so an injection
 * into them can actually reach the job's secrets / writable token. Plain `pull_request`
 * is excluded: a fork PR runs with a READ-ONLY token and no secrets, so an injection
 * there is a code-execution risk on the runner — not a credential exfiltration path (the
 * sink Blastgate models). Mirrors parse.ts's `credentialReachableTriggers` for the
 * fork-PR entry, so both entry kinds honor GitHub's fork-token rule identically.
 */
export function credentialReachableTextTriggers(triggers: string[]): string[] {
  return untrustedTextTriggers(triggers).filter((t) => t !== 'pull_request');
}

// Attacker-authored fields of the event payload: `.body` / `.title` on issue,
// comment, pull_request, review, discussion. Numbers/ids/logins are not free text.
const UNTRUSTED_TEXT_REF = /github\.event\.[\w.]*(?:body|title)\b/g;

// Coding-agent actions that read the event context by design (so the body reaches
// the agent even without an explicit `${{ … }}` interpolation).
const AGENT_ACTION_RE = /(?:anthropics\/claude|claude-code|opencode|aider|sweep-ai|gpt-engineer)/i;

/** The attacker-authored event-text expressions a job interpolates into its steps. */
export function injectableTextRefs(job: JobSpec): string[] {
  const strings: string[] = [];
  collectStrings(job, strings);
  const refs = new Set<string>();
  for (const s of strings) {
    for (const m of s.matchAll(UNTRUSTED_TEXT_REF)) {
      refs.add(m[0]);
    }
  }
  return [...refs];
}

/** Known coding-agent actions a job runs. */
export function agentActionsUsed(job: JobSpec): string[] {
  return (job.steps ?? [])
    .map((s) => s.uses)
    .filter((u): u is string => typeof u === 'string')
    .filter((u) => AGENT_ACTION_RE.test(u));
}

/**
 * A job is a prompt-injection surface when an untrusted-text event triggers it AND
 * it either interpolates attacker-authored event text or runs an agent that ingests
 * the event. (Actor-guard exemption is applied by the analyzer, mirroring U17/0017.)
 */
export function isInjectableAgentJob(job: JobSpec, triggers: string[]): boolean {
  if (untrustedTextTriggers(triggers).length === 0) {
    return false;
  }
  return injectableTextRefs(job).length > 0 || agentActionsUsed(job).length > 0;
}

/** A step that downloads a CI artifact (the artifact may originate from an untrusted run). */
export function downloadsArtifact(job: JobSpec): boolean {
  return (job.steps ?? []).some((s) => {
    if (typeof s.uses === 'string' && /actions\/download-artifact/.test(s.uses)) {
      return true;
    }
    const script = typeof s.with?.script === 'string' ? s.with.script : '';
    return (
      (typeof s.run === 'string' && /gh\s+run\s+download|downloadArtifact\s*\(/.test(s.run)) ||
      /downloadArtifact\s*\(/.test(script)
    );
  });
}

/** Reading a file's contents into a shell command line (`$(<file)` / `$(cat file)`) — unsafe if the file is attacker-controlled. */
const FILE_INTO_SHELL_RE = /\$\(\s*<|\$\(\s*cat\s/;

/** A `run:` step that splices file contents into the command line via command substitution. */
export function readsFileIntoShell(job: JobSpec): boolean {
  return (job.steps ?? []).some((s) => typeof s.run === 'string' && FILE_INTO_SHELL_RE.test(s.run));
}

/**
 * workflow_run artifact injection (0042): a privileged `workflow_run` job downloads an
 * artifact built by the (untrusted) `pull_request` run and then splices its contents into
 * a shell via command substitution (`gh pr comment $(<PRurl)`). The downloaded content is
 * attacker-controlled, so this is command/argument injection in a privileged context —
 * the one genuine finding the top-25 assessment surfaced (and the shape single-layer tools
 * miss). Passing the artifact as a *quoted argument to a trusted committed script* is NOT
 * this — only a shell-substitution sink counts.
 */
export function workflowRunArtifactInjection(job: JobSpec, triggers: string[]): boolean {
  return triggers.includes('workflow_run') && downloadsArtifact(job) && readsFileIntoShell(job);
}
