import { describe, expect, it } from 'vitest';
import type { RepoVisibility } from '../../engine/build';
import {
  AGENT_PROFILES,
  agentProfileFor,
  assessAgentStep,
  geminiYoloIgnoresAllowlist,
} from './agents';
import { parseWorkflow } from './parse';

/**
 * Agent-in-CI U1 (0055): each recognized agent action resolves to a cited,
 * versioned profile of its trigger gate and tool defaults (R2, R9; KTD1). A ref
 * the profile does not cover is `unknown` (it warns, never fails); an action no
 * profile names is not an agent at all.
 */
describe('agentProfileFor — action + ref → profile', () => {
  it('resolves anthropics/claude-code-action@v1 to the claude profile', () => {
    const r = agentProfileFor('anthropics/claude-code-action@v1');
    expect(r?.profile.id).toBe('claude');
    expect(r?.covered).toBe(true);
  });

  it('resolves a full claude release tag inside the v1 line', () => {
    expect(agentProfileFor('anthropics/claude-code-action@v1.0.238')?.covered).toBe(true);
  });

  it('resolves openai/codex-action@v1 to the codex profile', () => {
    const r = agentProfileFor('openai/codex-action@v1');
    expect(r?.profile.id).toBe('codex');
    expect(r?.covered).toBe(true);
  });

  it('resolves run-gemini-cli@v0.1.21 to the gemini profile, gate absent', () => {
    const r = agentProfileFor('google-github-actions/run-gemini-cli@v0.1.21');
    expect(r?.profile.id).toBe('gemini');
    expect(r?.covered).toBe(true);
    expect(r?.profile.gate).toBe('none');
  });

  it('resolves actions/ai-inference to the tool-less LLM profile', () => {
    const r = agentProfileFor('actions/ai-inference@v2');
    expect(r?.profile.id).toBe('llm-inference');
    expect(r?.profile.toolLess).toBe(true);
  });

  it('matches the action name case-insensitively', () => {
    expect(agentProfileFor('Anthropics/Claude-Code-Action@v1')?.profile.id).toBe('claude');
  });

  it('marks a version outside every range unknown, naming the ref (AE5)', () => {
    const r = agentProfileFor('anthropics/claude-code-action@v0.0.17');
    expect(r?.profile.id).toBe('claude');
    expect(r?.covered).toBe(false);
    expect(r?.unknown).toMatch(/v0\.0\.17/);
  });

  it('marks a branch ref unknown: a moving branch has no version to check', () => {
    expect(agentProfileFor('anthropics/claude-code-action@main')?.covered).toBe(false);
    expect(agentProfileFor('anthropics/claude-code-action@beta')?.covered).toBe(false);
  });

  it('marks an unrecorded SHA pin unknown (R9)', () => {
    const r = agentProfileFor('openai/codex-action@0123456789abcdef0123456789abcdef01234567');
    expect(r?.covered).toBe(false);
    expect(r?.unknown).toMatch(/SHA/);
  });

  it('marks a missing ref unknown', () => {
    expect(agentProfileFor('openai/codex-action')?.covered).toBe(false);
  });

  it('returns undefined for an unrecognized action (not an agent)', () => {
    expect(agentProfileFor('actions/checkout@v4')).toBeUndefined();
    expect(agentProfileFor('actions/github-script@v7')).toBeUndefined();
    expect(agentProfileFor('./local-action')).toBeUndefined();
  });

  it('does not match a look-alike owner or repo', () => {
    expect(agentProfileFor('evil/claude-code-action@v1')).toBeUndefined();
    expect(agentProfileFor('anthropics/claude-code-action-fork@v1')).toBeUndefined();
  });
});

describe('AGENT_PROFILES — every profile is cited and gated as its docs say', () => {
  it('every profile has at least one non-empty https citation', () => {
    for (const p of AGENT_PROFILES) {
      expect(p.citations.length, p.id).toBeGreaterThan(0);
      for (const c of p.citations) {
        expect(c, p.id).toMatch(/^https:\/\/\S+$/);
      }
    }
  });

  it('claude and codex gate on write access, opened to all by a wildcard input', () => {
    const claude = AGENT_PROFILES.find((p) => p.id === 'claude');
    const codex = AGENT_PROFILES.find((p) => p.id === 'codex');
    expect(claude?.gate).toBe('write-access');
    expect(claude?.outsiderInputs).toEqual(['allowed_non_write_users', 'allowed_bots']);
    expect(codex?.gate).toBe('write-access');
    // allow-users: '*' admits every user (checkActorPermissions.ts); allow-bot-users rejects '*'.
    expect(codex?.outsiderInputs).toEqual(['allow-users']);
  });
});

/**
 * The --yolo allowlist bypass is a Gemini CLI property (fixed in 0.39.1 and
 * 0.40.0-preview.3, GHSA-wpqr-6v78-jr5g), set by the step's `gemini_cli_version`
 * input — not by the run-gemini-cli action version, which installs `latest`.
 */
describe('geminiYoloIgnoresAllowlist — gemini_cli_version → bypass', () => {
  it('is false when unset or a moving channel (installs a patched CLI)', () => {
    expect(geminiYoloIgnoresAllowlist(undefined)).toBe(false);
    expect(geminiYoloIgnoresAllowlist('')).toBe(false);
    expect(geminiYoloIgnoresAllowlist('latest')).toBe(false);
    expect(geminiYoloIgnoresAllowlist('preview')).toBe(false);
    expect(geminiYoloIgnoresAllowlist('nightly')).toBe(false);
  });

  it('is true for a pin below 0.39.1', () => {
    expect(geminiYoloIgnoresAllowlist('0.39.0')).toBe(true);
    expect(geminiYoloIgnoresAllowlist('v0.12.3')).toBe(true);
  });

  it('is false for a pin at or above the fix', () => {
    expect(geminiYoloIgnoresAllowlist('0.39.1')).toBe(false);
    expect(geminiYoloIgnoresAllowlist('0.41.0')).toBe(false);
  });

  it('treats 0.40.0 previews before preview.3 as vulnerable', () => {
    expect(geminiYoloIgnoresAllowlist('0.40.0-preview.2')).toBe(true);
    expect(geminiYoloIgnoresAllowlist('0.40.0-preview.3')).toBe(false);
  });

  it('is unknown for an expression, branch, or commit', () => {
    expect(geminiYoloIgnoresAllowlist('${{ vars.GEMINI_VERSION }}')).toBe('unknown');
    expect(geminiYoloIgnoresAllowlist('my-branch')).toBe('unknown');
    expect(geminiYoloIgnoresAllowlist(42)).toBe('unknown');
  });
});

/**
 * Agent-in-CI U3 (0057; R3–R5, R9, R10): each agent step is judged against the Agents
 * Rule of Two. Direct = an outsider can trigger the agent itself; access = the agent
 * has a tool that can read a credential the job holds; exfil = it has a way out. Each
 * leg is held, missing, or unknown — only all three held may later fail (U5).
 */
describe('assessAgentStep — Rule of Two legs (0057)', () => {
  function assess(yaml: string, visibility: RepoVisibility = 'unknown') {
    const wf = parseWorkflow(yaml);
    const [jobId, job] = Object.entries(wf.jobs ?? {})[0]!;
    const idx = (job.steps ?? []).findIndex(
      (s) => typeof s.uses === 'string' && agentProfileFor(s.uses) !== undefined,
    );
    expect(idx, jobId).toBeGreaterThanOrEqual(0);
    return assessAgentStep({ workflow: wf, job, stepIndex: idx, visibility });
  }

  // AE1 (Comment and Control shape): bypass to all users, unrestricted Bash, scrub off.
  const AE1 = `
on: issue_comment
permissions: { issues: write }
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`;

  it('AE1: claude bypass *, Bash, scrub disabled, API key → all three legs hold', () => {
    const a = assess(AE1);
    expect([a.direct, a.access, a.exfil]).toEqual(['held', 'held', 'held']);
    expect(a.covered).toBe(true);
  });

  it('claude bypass with the scrub default and a checkout-persisted contents:write token → access via .git/config', () => {
    const a = assess(`
on: issue_comment
permissions: { contents: write }
jobs:
  claude:
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`);
    expect(a.access).toBe('held');
    expect(a.reasons.access).toMatch(/\.git\/config/);
  });

  it('claude bypass with the scrub default, no persisted token, no credential files → access missing', () => {
    const a = assess(`
on: issue_comment
permissions: { contents: write }
jobs:
  claude:
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`);
    expect(a.access).toBe('missing');
    expect(a.reasons.access).toMatch(/scrub/i);
  });

  it('under the scrub, a WIF credentials file is unusable (its exchange needs the scrubbed OIDC token) → access missing', () => {
    const a = assess(`
on: issue_comment
permissions: { id-token: write }
jobs:
  claude:
    steps:
      - uses: google-github-actions/auth@v2
        with: { workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/g }
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`);
    expect(a.access).toBe('missing');
    expect(a.readable.token).toBe(false);
  });

  it('under the scrub, a key file google-github-actions/auth wrote from a secret proves that secret', () => {
    const a = assess(`
on: issue_comment
jobs:
  claude:
    steps:
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: \${{ secrets.GCP_SA_KEY }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`);
    expect(a.access).toBe('held');
    expect(a.readable.secrets).toEqual(['GCP_SA_KEY']);
    expect(a.readable.token).toBe(false);
  });

  it('AE2: claude without the bypass → direct missing (indirect injection)', () => {
    const a = assess(AE1.replace("allowed_non_write_users: '*'", ''));
    expect(a.direct).toBe('missing');
    expect(a.reasons.direct).toMatch(/write access/);
  });

  it('allowed_non_write_users without github_token does not open the gate (App auth)', () => {
    const a = assess(AE1.replace('github_token: ${{ secrets.GITHUB_TOKEN }}', ''));
    expect(a.direct).toBe('missing');
  });

  it('AE3: tools restricted to Bash(gh issue view:*) → access missing', () => {
    const a = assess(
      AE1.replace("'--allowedTools Bash'", `'--allowedTools "Bash(gh issue view:*)"'`),
    );
    expect(a.access).toBe('missing');
    expect(a.direct).toBe('held');
  });

  it("allowed_bots: '*' on an issue_comment job → direct holds only on a public repo", () => {
    const bots = AE1.replace("allowed_non_write_users: '*'", "allowed_bots: '*'");
    expect(assess(bots, 'public').direct).toBe('held');
    // Only a public repo lets an arbitrary GitHub App open issues or comment (security doc).
    expect(assess(bots, 'unknown').direct).toBe('unknown');
    expect(assess(bots, 'private').direct).toBe('missing');
  });

  it('a recognized job actor guard → direct missing', () => {
    const a = assess(
      AE1.replace(
        '    runs-on: ubuntu-latest',
        "    runs-on: ubuntu-latest\n    if: github.event.comment.author_association == 'OWNER'",
      ),
    );
    expect(a.direct).toBe('missing');
  });

  it('a push-only trigger → direct missing', () => {
    expect(assess(AE1.replace('on: issue_comment', 'on: push')).direct).toBe('missing');
  });

  it('codex with allow-users: someone → direct missing (KTD3)', () => {
    const a = assess(`
on: issue_comment
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: someone
`);
    expect(a.direct).toBe('missing');
  });

  it("codex with allow-users: '*' → direct holds (KTD3 revised)", () => {
    const a = assess(`
on: issue_comment
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: '*'
`);
    expect(a.direct).toBe('held');
  });

  it('codex: its own OpenAI key is proxied and sudo dropped, so it is not readable by default', () => {
    const yaml = `
on: issue_comment
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: '*'
`;
    expect(assess(yaml).access).toBe('missing');
    const unsafe = yaml.replace(
      "allow-users: '*'",
      "allow-users: '*'\n          safety-strategy: unsafe",
    );
    expect(assess(unsafe).access).toBe('held');
    const jobSecret = yaml.replace(
      '      - uses: openai/codex-action@v1',
      '      - uses: openai/codex-action@v1\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}',
    );
    expect(assess(jobSecret).access).toBe('held');
  });

  const GEMINI = `
on:
  issues:
    types: [opened]
permissions: { id-token: write, issues: write }
jobs:
  triage:
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          gcp_workload_identity_provider: \${{ vars.GCP_WIF_PROVIDER }}
          prompt: Triage this issue.
`;

  it('gemini on issues with OIDC and no guard → direct and access hold (KTD4)', () => {
    const a = assess(GEMINI);
    expect(a.direct).toBe('held');
    expect(a.access).toBe('held');
  });

  it('gemini with an author_association guard → direct missing', () => {
    const a = assess(
      GEMINI.replace(
        '  triage:\n',
        '  triage:\n    if: contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.issue.author_association)\n',
      ),
    );
    expect(a.direct).toBe('missing');
  });

  it('gemini settings restricting shell to one command → no shell; a CLI pin below 0.39.1 makes it unknown', () => {
    const restricted = GEMINI.replace(
      '          prompt: Triage this issue.',
      `          prompt: Triage this issue.
          settings: '{"tools":{"core":["run_shell_command(gh issue edit)"]}}'`,
    );
    expect(assess(restricted).access).toBe('missing');
    const pinned = restricted.replace(
      '          prompt: Triage',
      "          gemini_cli_version: '0.38.0'\n          prompt: Triage",
    );
    // An old CLI ignores the allowlist and auto-trusts the repo's .gemini/settings.json.
    expect(assess(pinned).access).toBe('unknown');
  });

  it('claude_args built from a non-literal expression → unknown recorded', () => {
    const a = assess(AE1.replace("'--allowedTools Bash'", '${{ vars.CLAUDE_ARGS }}'));
    expect(a.access).toBe('unknown');
    expect(a.unknown.join(' ')).toMatch(/claude_args/);
  });

  const READ_ONLY_SECRET = `
on: issue_comment
jobs:
  claude:
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Read'
`;

  it('public visibility, a readable secret, but no shell or network tool → exfil holds via logs', () => {
    const a = assess(READ_ONLY_SECRET, 'public');
    expect(a.exfil).toBe('held');
    expect(a.reasons.exfil).toMatch(/log/i);
  });

  it('unknown visibility and no shell, network, or public write → exfil missing', () => {
    const a = assess(READ_ONLY_SECRET, 'unknown');
    expect(a.exfil).toBe('missing');
  });

  it('a token that can write issues is a public-surface exfil channel', () => {
    const a = assess(
      READ_ONLY_SECRET.replace(
        'on: issue_comment',
        'on: issue_comment\npermissions: { issues: write }',
      ),
    );
    expect(a.exfil).toBe('held');
  });

  it('a tool-less LLM step never holds access (R8)', () => {
    const a = assess(`
on: issues
permissions: { issues: write, models: read }
jobs:
  label:
    steps:
      - uses: actions/ai-inference@v2
        with:
          prompt: \${{ github.event.issue.body }}
`);
    expect(a.access).toBe('missing');
  });

  it('an uncovered version is recorded as unknown, naming it (R9)', () => {
    const a = assess(AE1.replace('claude-code-action@v1', 'claude-code-action@v0.0.17'));
    expect(a.covered).toBe(false);
    expect(a.unknown.join(' ')).toMatch(/v0\.0\.17/);
  });

  it('every leg carries a reason (R10)', () => {
    const a = assess(AE1);
    expect(a.reasons.direct && a.reasons.access && a.reasons.exfil).toBeTruthy();
  });
});

/** PR #38 review (plan KTD2, U3 step 5): bypass preconditions, scrub scope, and tool legs. */
describe('assessAgentStep — claude bypass and scrub details (0057)', () => {
  function assess(yaml: string, visibility: RepoVisibility = 'unknown') {
    const wf = parseWorkflow(yaml);
    const job = Object.values(wf.jobs ?? {})[0]!;
    const idx = (job.steps ?? []).findIndex((s) => /claude-code-action/.test(String(s.uses)));
    return assessAgentStep({ workflow: wf, job, stepIndex: idx, visibility });
  }
  const claude = (opts: { top?: string; jobEnv?: string; withLines: string[]; pre?: string }) => `
on: issue_comment
${opts.top ?? ''}
jobs:
  claude:
${opts.jobEnv ?? ''}
    steps:
${opts.pre ?? ''}
      - uses: anthropics/claude-code-action@v1
        with:
${opts.withLines.map((l) => `          ${l}`).join('\n')}
`;
  const KEY = 'anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}';
  const TOKEN = 'github_token: ${{ secrets.GITHUB_TOKEN }}';

  it("allowed_bots: '*' alone does not scrub, so environment secrets count", () => {
    const a = assess(
      claude({ withLines: [KEY, "allowed_bots: '*'", "claude_args: '--allowedTools Bash'"] }),
      'public',
    );
    expect(a.direct).toBe('held');
    expect(a.access).toBe('held');
    expect(a.readable.secrets).toContain('ANTHROPIC_API_KEY');
  });

  it.each([
    ['job', { jobEnv: '    env:\n      CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0' }],
    ['workflow', { top: 'env:\n  CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0' }],
  ])('the scrub opt-out at %s env: is honored', (_scope, where) => {
    const lines = [
      KEY,
      TOKEN,
      "allowed_non_write_users: '*'",
      "claude_args: '--allowedTools Bash'",
    ];
    expect(assess(claude({ withLines: lines })).access).toBe('missing');
    expect(assess(claude({ withLines: lines, ...where })).access).toBe('held');
  });

  it('Read only, a checkout-persisted contents:write token, public repo → access via file read, exfil via logs', () => {
    const yaml = claude({
      top: 'permissions:\n  contents: write',
      pre: '      - uses: actions/checkout@v4',
      withLines: [KEY, TOKEN, "allowed_non_write_users: '*'", "claude_args: '--allowedTools Read'"],
    });
    const a = assess(yaml, 'public');
    expect([a.direct, a.access, a.exfil]).toEqual(['held', 'held', 'held']);
    expect(a.readable.token).toBe(true);
    expect(a.readable.secrets).toEqual([]);
    expect(assess(yaml, 'unknown').exfil).toBe('missing');
  });
});

/** PR #39 review fixes: secret scope, step/needs guards, gemini settings, unknown workspace config. */
describe('assessAgentStep — PR #39 review fixes', () => {
  function assess(yaml: string, jobId?: string, visibility: RepoVisibility = 'unknown') {
    const wf = parseWorkflow(yaml);
    const job = jobId ? wf.jobs![jobId]! : Object.values(wf.jobs ?? {})[0]!;
    const idx = (job.steps ?? []).findIndex(
      (s) => typeof s.uses === 'string' && agentProfileFor(s.uses) !== undefined,
    );
    return assessAgentStep({ workflow: wf, job, stepIndex: idx, visibility });
  }

  it("a secret only in another step's env is not readable by the agent", () => {
    const a = assess(`
on: issue_comment
jobs:
  claude:
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
      - run: ./deploy.sh
        env:
          DEPLOY: \${{ secrets.DEPLOY_KEY }}
`);
    expect(a.readable.secrets).toEqual(['ANTHROPIC_API_KEY']);
  });

  it("workflow- and job-level env secrets are in the agent step's scope", () => {
    const a = assess(`
on: issue_comment
env:
  WF_SECRET: \${{ secrets.WF_SECRET }}
jobs:
  codex:
    env:
      JOB_SECRET: \${{ secrets.JOB_SECRET }}
    steps:
      - run: echo hi
        env:
          OTHER: \${{ secrets.OTHER }}
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: '*'
`);
    expect(a.readable.secrets.sort()).toEqual(['JOB_SECRET', 'WF_SECRET']);
  });

  it('codex with only another step holding a secret → access missing', () => {
    const a = assess(`
on: issue_comment
jobs:
  codex:
    steps:
      - run: echo hi
        env:
          X: \${{ secrets.OTHER }}
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: '*'
`);
    expect(a.access).toBe('missing');
  });

  const GUARDABLE = (jobIf: string, stepIf: string, needs: string) => `
on: issue_comment
jobs:
  gate:
    if: github.event.comment.author_association == 'MEMBER'
    steps:
      - run: echo ok
  claude:
${needs}${jobIf}    steps:
      - uses: anthropics/claude-code-action@v1
${stepIf}        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: '*'
          claude_args: '--allowedTools Bash'
`;

  it('a step-level author_association guard on the agent step → direct missing', () => {
    expect(assess(GUARDABLE('', '', ''), 'claude').direct).toBe('held');
    const a = assess(
      GUARDABLE('', "        if: github.event.comment.author_association == 'OWNER'\n", ''),
      'claude',
    );
    expect(a.direct).toBe('missing');
  });

  it('a needs: gate job carrying an actor guard → direct missing', () => {
    expect(assess(GUARDABLE('', '', '    needs: [gate]\n'), 'claude').direct).toBe('missing');
  });

  it.each([['always()'], ['${{ !cancelled() }}'], ['failure()']])(
    'a needs: gate does not guard a job that runs anyway (if: %s)',
    (cond) => {
      const yaml = GUARDABLE(`    if: ${cond}\n`, '', '    needs: [gate]\n');
      expect(assess(yaml, 'claude').direct).toBe('held');
    },
  );

  const GEMINI = (extra: string, env = '') => `
on: issues
jobs:
  triage:
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
${env}        with:
          gemini_api_key: \${{ secrets.GEMINI_API_KEY }}
${extra}          prompt: Triage this issue.
`;

  it('gemini settings tools.exclude removing the shell → access missing', () => {
    expect(assess(GEMINI('')).access).toBe('held');
    const a = assess(
      GEMINI(`          settings: '{"tools":{"exclude":["run_shell_command","web_fetch"]}}'\n`),
    );
    expect(a.access).toBe('missing');
  });

  it('GEMINI_TRUST_WORKSPACE loads the repo .gemini/settings.json, which Blastgate does not read → unknown', () => {
    const a = assess(GEMINI('', "        env:\n          GEMINI_TRUST_WORKSPACE: 'true'\n"));
    expect(a.access).toBe('unknown');
    expect(a.unknown.join(' ')).toMatch(/\.gemini\/settings\.json/);
  });

  it('a Gemini CLI pinned below 0.39.1 auto-trusts the workspace → tool grants unknown', () => {
    const a = assess(GEMINI("          gemini_cli_version: '0.38.0'\n"));
    expect(a.access).toBe('unknown');
  });

  it("allowed_bots: '*' reason says any GitHub App can trigger it (claude security doc)", () => {
    const a = assess(
      `
on: issue_comment
jobs:
  claude:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: '*'
`,
      undefined,
      'public',
    );
    expect(a.direct).toBe('held');
    expect(a.reasons.direct).toMatch(/GitHub App/);
  });
});
