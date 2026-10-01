import { describe, expect, it } from 'vitest';
import {
  agentActionsUsed,
  classifyUntrustedText,
  injectableTextRefs,
  isInjectableAgentJob,
  splicesFileIntoCommand,
  textOnlyBooleanMatched,
} from './injection';
import type { JobSpec, StepSpec } from './parse';

/**
 * The AISI Mythos-5 injection was planted in a GitHub issue and read by an AI
 * triage agent. The deterministic, offline signal Blastgate can see is the
 * *workflow configuration* that creates the path: a job on an untrusted-text
 * event that pipes attacker-authored body/title text into a step, or runs a
 * coding-agent action that ingests the event by design (0022).
 */
describe('injectableTextRefs — attacker-authored event text piped into a step', () => {
  it('finds an issue body reference in a run step', () => {
    const job: JobSpec = { steps: [{ run: 'echo "${{ github.event.issue.body }}"' }] };
    expect(injectableTextRefs(job)).toContain('github.event.issue.body');
  });
  it('finds a comment body reference in a with: input', () => {
    const job: JobSpec = {
      steps: [{ uses: 'x/y@v1', with: { prompt: '${{ github.event.comment.body }}' } }],
    };
    expect(injectableTextRefs(job)).toContain('github.event.comment.body');
  });
  it('finds a PR title reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.pull_request.title }}' }] };
    expect(injectableTextRefs(job).length).toBeGreaterThan(0);
  });
  it('does not match a non-text event field (e.g. number)', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.issue.number }}' }] };
    expect(injectableTextRefs(job)).toHaveLength(0);
  });
});

describe('agentActionsUsed — a coding agent that ingests the event context', () => {
  it('detects anthropics/claude-code-action', () => {
    const job: JobSpec = { steps: [{ uses: 'anthropics/claude-code-action@v1' }] };
    expect(agentActionsUsed(job)).toHaveLength(1);
  });
  it('ignores an ordinary action', () => {
    const job: JobSpec = { steps: [{ uses: 'actions/checkout@v4' }] };
    expect(agentActionsUsed(job)).toHaveLength(0);
  });
});

describe('isInjectableAgentJob — untrusted-text trigger + an injectable surface', () => {
  it('true: issue_comment trigger + a body reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.comment.body }}' }] };
    expect(isInjectableAgentJob(job, ['issue_comment'])).toBe(true);
  });
  it('true: issues trigger + an agent action (reads the event by design)', () => {
    const job: JobSpec = { steps: [{ uses: 'anthropics/claude-code-action@v1' }] };
    expect(isInjectableAgentJob(job, ['issues'])).toBe(true);
  });
  it('false: a trusted trigger (push) even with a body reference', () => {
    const job: JobSpec = { steps: [{ run: 'echo ${{ github.event.issue.body }}' }] };
    expect(isInjectableAgentJob(job, ['push'])).toBe(false);
  });
  it('false: untrusted trigger but no injectable surface', () => {
    const job: JobSpec = { steps: [{ run: 'npm test' }] };
    expect(isInjectableAgentJob(job, ['issue_comment'])).toBe(false);
  });
});

describe('textOnlyBooleanMatched — untrusted text is only compared, never injected (0044)', () => {
  it('true: the only body/title refs are arguments to contains()', () => {
    const job: JobSpec = {
      if: "contains(github.event.comment.body, 'fable') || contains(github.event.issue.body, 'x')",
      steps: [{ run: 'echo hi' }],
    };
    expect(textOnlyBooleanMatched(job)).toBe(true);
  });
  it('false: a bare body interpolation in a run step (a real injection sink)', () => {
    const job: JobSpec = {
      if: "contains(github.event.issue.body, 'x')",
      steps: [{ run: 'echo ${{ github.event.issue.body }}' }],
    };
    expect(textOnlyBooleanMatched(job)).toBe(false);
  });
  it('false: a coding-agent action is present (ingests the event by design)', () => {
    const job: JobSpec = {
      if: "contains(github.event.comment.body, '@claude')",
      steps: [{ uses: 'anthropics/claude-code-action@v1' }],
    };
    expect(textOnlyBooleanMatched(job)).toBe(false);
  });
  it('false: no untrusted-text ref at all — nothing to neutralize', () => {
    const job: JobSpec = { steps: [{ run: 'npm test' }] };
    expect(textOnlyBooleanMatched(job)).toBe(false);
  });
});

/**
 * 0046 / plan R4, KTD1–KTD2: classify WHERE untrusted event text lands, instead of
 * flagging its mere co-presence with a secret. Only an execution sink can later fail.
 */
describe('classifyUntrustedText — sink classes (0046)', () => {
  const TITLE = '${{ github.event.issue.title }}';
  const BODY = '${{ github.event.comment.body }}';

  it('run: interpolation → execution at that step', () => {
    const job: JobSpec = { steps: [{ uses: 'actions/checkout@v4' }, { run: `echo "${TITLE}"` }] };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'execution',
      path: ['steps', 1, 'run'],
    });
  });

  it('github-script script: interpolation → execution', () => {
    const job: JobSpec = {
      steps: [{ uses: 'actions/github-script@v7', with: { script: `core.info(\`${BODY}\`)` } }],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'execution',
      path: ['steps', 0, 'with', 'script'],
    });
  });

  it('text passed via env: and read as "$VAR" → no sink', () => {
    const job: JobSpec = { steps: [{ run: 'echo "$TITLE"', env: { TITLE } }] };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it('job-level env: → no sink', () => {
    const job: JobSpec = { env: { TITLE }, steps: [{ run: 'echo "$TITLE"' }] };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it('text only compared in if: → no sink', () => {
    const job: JobSpec = {
      if: "contains(github.event.comment.body, '/deploy')",
      steps: [{ if: "github.event.issue.title == 'x'", run: 'npm test' }],
    };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it('boolean contains() inside a run: expression → no sink', () => {
    const job: JobSpec = {
      steps: [{ run: "echo ${{ contains(github.event.comment.body, 'fable') }}" }],
    };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it('a coding-agent action → agent-ingested, even without an explicit interpolation', () => {
    const job: JobSpec = {
      steps: [{ uses: 'anthropics/claude-code-action@v1', with: { prompt: 'triage this' } }],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'agent-ingested',
      path: ['steps', 0, 'uses'],
    });
  });

  it('title in a third-party action with: input → action-input', () => {
    const job: JobSpec = { steps: [{ uses: 'x/notify@v1', with: { text: TITLE } }] };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'action-input',
      path: ['steps', 0, 'with', 'text'],
    });
  });

  it('the strongest sink wins: agent step + run: interpolation → execution', () => {
    const job: JobSpec = {
      steps: [
        { uses: 'anthropics/claude-code-action@v1', with: { prompt: BODY } },
        { uses: 'x/notify@v1', with: { text: TITLE } },
        { run: `echo "${TITLE}"` },
      ],
    };
    expect(classifyUntrustedText(job)?.sinkClass).toBe('execution');
    expect(classifyUntrustedText(job)?.path).toEqual(['steps', 2, 'run']);
  });

  it('text in an unclassified step field → unrecognized', () => {
    const job: JobSpec = {
      steps: [{ run: 'make', 'working-directory': TITLE } as StepSpec],
    };
    expect(classifyUntrustedText(job)?.sinkClass).toBe('unrecognized');
  });

  it('job-level reusable-workflow with: input → unrecognized (fail-closed, never dropped)', () => {
    const job = { uses: './.github/workflows/notify.yml', with: { title: TITLE } } as JobSpec;
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'unrecognized',
      path: ['with', 'title'],
    });
  });

  it('a job with no untrusted text → undefined', () => {
    expect(classifyUntrustedText({ steps: [{ run: 'npm test' }] })).toBeUndefined();
  });
});

/**
 * 0054 / plan KTD9: an artifact splice is a sink only when an unquoted command
 * substitution reads a file in command-word/argument position. The 2026-09-29 re-scan's
 * four false fails (pytorch ×3, grafana) were all assignments of validated numbers.
 */
describe('splicesFileIntoCommand — quote- and assignment-aware (0054)', () => {
  it.each([
    ['gh pr comment $(<PRurl) -b "linter output"'],
    ['if [ -s error.log ]\nthen\n  gh pr edit $(<PRurl) --add-label x\nfi'],
    ['make && gh api $(cat target.txt)'],
    ['do_thing; curl $(cat url.txt)'],
  ])('flags an unquoted splice in argument position: %s', (run) => {
    expect(splicesFileIntoCommand(run)).toBe(true);
  });

  it.each([
    [
      'PR_NUMBER=$(cat /tmp/pr-number/pr-number.txt)\nif ! [[ "$PR_NUMBER" =~ ^[0-9]+$ ]]; then exit 1; fi',
    ],
    ['ISSUE_NUM=$(cat issue_number.txt)'],
    ['export X=$(<file)'],
    ['local X=$(cat file)'],
    ['echo "body $(cat error.log)"'],
    ['gh pr comment 1 -b "Linter failed:\n```\n$(cat error.log)\n```"'],
    ['HASH=$(cat .github/workflows/a.yml \\\n  .github/workflows/b.yml | sha256sum)'],
    ["echo '$(cat f)'"],
  ])('does not flag an assignment or quoted substitution: %s', (run) => {
    expect(splicesFileIntoCommand(run)).toBe(false);
  });

  // PR #36 review: a stray quote in a comment or heredoc must not hide a later splice.
  it.each([
    ["# don't\ngh pr comment $(cat pr.txt)"],
    ["cat <<EOF\nit's\nEOF\ngh pr comment $(cat f)"],
    ['# say "hi\ngh pr comment $(cat pr.txt)'],
    ["cat <<-'END'\n\tdon't\n\tEND\ngh pr edit $(<PRurl)"],
    // Unbalanced quotes at end of script: fail closed to the plain match.
    ['echo "oops\ngh pr comment $(cat f)'],
    // PR #36 re-review: here-strings and arithmetic shifts are not heredocs.
    ['cat <<< "x"\ngh c $(cat f)'],
    ['read v <<< foo\ngh c $(cat f)'],
    ['x=$((1<<n))\ngh c $(cat f)'],
    // A file read inside arithmetic is evaluated as an expression; an unclosed `$((` must not swallow the script.
    ['echo $(( $(cat f) + 1 ))'],
    ['echo $((1+\ngh c $(cat f)'],
  ])('is not blinded by comments, heredocs, or unbalanced quotes: %s', (run) => {
    expect(splicesFileIntoCommand(run)).toBe(true);
  });

  it.each([['# gh pr comment $(cat f)'], ['cat <<EOF > body.md\n$(cat error.log)\nEOF']])(
    'does not flag a substitution inside a comment or heredoc body: %s',
    (run) => {
      expect(splicesFileIntoCommand(run)).toBe(false);
    },
  );

  it('still flags the splice when a quoted substitution precedes it on another line', () => {
    const run = 'echo "note $(cat a)"\ngh pr comment $(<PRurl)';
    expect(splicesFileIntoCommand(run)).toBe(true);
  });
});

/**
 * Agent-in-CI U2 (0056; R1, R8; KTD7): every profiled agent action ingests the event by
 * design, and a tool-less LLM step (actions/ai-inference, or github-script calling
 * GitHub Models) ingests untrusted text that reaches it through `env:`, `with:`, its
 * script, or an earlier step's output. `env:` protects a shell, not a model.
 */
describe('classifyUntrustedText — agent and tool-less LLM steps (0056)', () => {
  const TITLE = '${{ github.event.issue.title }}';
  const BODY = '${{ github.event.issue.body }}';
  const MODELS_SCRIPT = [
    'const res = await fetch("https://models.github.ai/inference/chat/completions", {',
    '  method: "POST",',
    '  body: JSON.stringify({ messages: [{ role: "user", content: process.env.ISSUE_BODY }] }),',
    '});',
  ].join('\n');

  it('AE4: issue title/body via env: into github-script that calls GitHub Models → agent-ingested', () => {
    const job: JobSpec = {
      permissions: { issues: 'write', models: 'read' },
      steps: [
        {
          uses: 'actions/github-script@v7',
          env: { ISSUE_TITLE: TITLE, ISSUE_BODY: BODY },
          with: { script: MODELS_SCRIPT },
        },
      ],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'agent-ingested',
      path: ['steps', 0, 'uses'],
    });
  });

  it('github-script reading the body from a job-level env: and calling Models → agent-ingested', () => {
    const job: JobSpec = {
      env: { ISSUE_BODY: BODY },
      steps: [{ uses: 'actions/github-script@v7', with: { script: MODELS_SCRIPT } }],
    };
    expect(classifyUntrustedText(job)?.sinkClass).toBe('agent-ingested');
  });

  it('github-script reading env but calling no model → no sink (env-passed rule)', () => {
    const job: JobSpec = {
      steps: [
        {
          uses: 'actions/github-script@v7',
          env: { ISSUE_BODY: BODY },
          with: { script: 'core.info(process.env.ISSUE_BODY.length)' },
        },
      ],
    };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it('actions/ai-inference with the issue body in prompt: → agent-ingested, not action-input', () => {
    const job: JobSpec = {
      steps: [{ uses: 'actions/ai-inference@v2', with: { prompt: `Classify: ${BODY}` } }],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'agent-ingested',
      path: ['steps', 0, 'uses'],
    });
  });

  it('actions/ai-inference fed the body through an earlier step output (home-assistant HEAD) → agent-ingested', () => {
    const job: JobSpec = {
      steps: [
        {
          id: 'detect_language',
          uses: 'actions/github-script@v7',
          env: { ISSUE_TITLE: TITLE, ISSUE_BODY: BODY },
          with: { script: "core.setOutput('issue_text', process.env.ISSUE_BODY)" },
        } as StepSpec,
        {
          uses: 'actions/ai-inference@v2',
          with: { prompt: 'Is this English?\n${{ steps.detect_language.outputs.issue_text }}' },
        },
      ],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'agent-ingested',
      path: ['steps', 1, 'uses'],
    });
  });

  it('actions/ai-inference fed via ${{ env.X }} holding the body → agent-ingested', () => {
    const job: JobSpec = {
      env: { ISSUE_BODY: BODY },
      steps: [{ uses: 'actions/ai-inference@v2', with: { prompt: '${{ env.ISSUE_BODY }}' } }],
    };
    expect(classifyUntrustedText(job)?.sinkClass).toBe('agent-ingested');
  });

  it('actions/ai-inference with no untrusted text reaching it → no sink', () => {
    const job: JobSpec = {
      steps: [
        { id: 'clean', run: 'echo "n=1" >> "$GITHUB_OUTPUT"' } as StepSpec,
        {
          uses: 'actions/ai-inference@v2',
          with: { prompt: 'Summarize ${{ steps.clean.outputs.n }}' },
        },
      ],
    };
    expect(classifyUntrustedText(job)).toBeUndefined();
  });

  it.each([
    ['google-github-actions/run-gemini-cli@v0'],
    ['openai/codex-action@v1'],
    ['anthropics/claude-code-action@v1'],
  ])('%s → agent-ingested by design, with no interpolation', (uses) => {
    const job: JobSpec = { steps: [{ uses: 'actions/checkout@v4' }, { uses }] };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'agent-ingested',
      path: ['steps', 1, 'uses'],
    });
  });

  it('an unprofiled agent on the legacy name list (aider) stays agent-ingested', () => {
    const job: JobSpec = { steps: [{ uses: 'paul-gauthier/aider-action@v1' }] };
    expect(classifyUntrustedText(job)?.sinkClass).toBe('agent-ingested');
  });

  it('an execution sink plus an agent in one job → execution still wins', () => {
    const job: JobSpec = {
      steps: [
        { uses: 'google-github-actions/run-gemini-cli@v0' },
        { run: `echo "${TITLE}"` },
        { uses: 'actions/ai-inference@v2', with: { prompt: BODY } },
      ],
    };
    expect(classifyUntrustedText(job)).toEqual({
      sinkClass: 'execution',
      path: ['steps', 1, 'run'],
    });
  });

  it('agentActionsUsed lists gemini, codex, and ai-inference steps', () => {
    const job: JobSpec = {
      steps: [
        { uses: 'google-github-actions/run-gemini-cli@v0' },
        { uses: 'openai/codex-action@v1' },
        { uses: 'actions/ai-inference@v2' },
        { uses: 'actions/checkout@v4' },
      ],
    };
    expect(agentActionsUsed(job)).toHaveLength(3);
  });
});
