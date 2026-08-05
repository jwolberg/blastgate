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
