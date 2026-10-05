/**
 * Review packets for held fails (0093). Nothing goes out on a fail until Jay approves it (0092),
 * and an approval is only as good as the reading behind it. A packet puts everything needed to
 * judge one (repo, archetype) fail on one page: the finding, the workflow source at the exact
 * commit with the cited lines marked, the report that would be sent, a refutation checklist for
 * its archetype, and the `approved` entries to paste once it is confirmed.
 *
 * Packets name third-party repos with unfixed vulnerabilities, so they are written outside this
 * public repo (the private ops repo is the intended home) and clones are deleted afterwards.
 */

import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding } from '../findings/finding';
import { composeReport } from './disclose';
import { parseLedger } from './ledger';
import { archetypeOf, childEnv, scanRepos as defaultScanRepos } from './scan';
import { buildRequestBody } from './submit';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export interface PacketInput {
  repo: string;
  /** Full sha of the commit that was scanned; the approval pins to it. */
  sha: string;
  /** Engine that produced these findings (this local rescan). */
  engineVersion: string;
  /** Engine the crawler last scanned this repo with, from the ledger. */
  ledgerEngineVersion?: string;
  archetype: string;
  findings: Finding[];
  /** A repo file's text at `sha`, or null when the clone does not have it. */
  readSource: (file: string) => string | null;
  /** Every workflow file in the clone, repo-relative. */
  workflows: string[];
}

// ---------------------------------------------------------------- checklists

const CHECKS: Record<string, string[]> = {
  'fork-pr': [
    'An outsider can trigger it: `pull_request_target`; or `workflow_run` of a workflow that runs on fork `pull_request`s (open that workflow and check its `on:`); or an issue/comment trigger.',
    "It runs the outsider's code: a checkout of the PR head (`ref:` a head sha/ref **with** `repository:` set to the fork, `gh pr checkout`, or `git fetch … refs/pull/…`), **followed by** a step that executes it (install, build, test, a repo script). A branch name with no `repository:` checks out base-repo code.",
    'The named secret is present in that same job, at or after that step.',
  ],
  'untrusted-text-injection': [
    'The text is outsider-written: an issue or PR title or body, a comment, a branch name, a commit message, or a downloaded artifact.',
    'It is spliced in with `${{ }}` directly into `run:` or a `github-script` `script:`. Passing it through an environment variable and using `"$VAR"` is safe.',
    'An outsider can trigger the job: check `on:` and any `if:` on the author or their association.',
    'The job holds the named secret or a write token.',
  ],
  'injectable-agent-surface': [
    "An outsider can trigger the agent step: check the action's own gates for the pinned version (allowed users and bots, the write-permission check).",
    'The agent reads outsider text: an issue, comment, PR body, or diff.',
    'Its tools can read the credential: a shell, or reading files such as `.git/config` or the environment.',
    'It has a way to get data out: a comment, a push, or the network.',
  ],
  'new-dependency': [
    'The dependency is new or changed, and declares an install script.',
    'The job installs it without `--ignore-scripts`.',
    'An outsider can trigger that job, and it holds the named secret.',
  ],
};

const DEFAULT_CHECKS = [
  'An outsider can reach the entry named at the start of the path.',
  'Every hop in the path holds when you read the source.',
];

const COMMON_CHECKS = [
  'No guard the engine may have missed: a job or step `if:` on the actor, author association, a label, or same-repo; an `environment:` with required reviewers; an early `exit` before the risky step.',
  'The workflow is live: under `.github/workflows/`, and not disabled by `if: false`.',
  'The report is accurate as written: every file:line and claim in the body below is true. A real risk described wrongly counts as **refuted**.',
];

function checklist(archetype: string): string[] {
  const entry = archetype.split('->')[0] ?? '';
  return [...(CHECKS[entry] ?? DEFAULT_CHECKS), ...COMMON_CHECKS];
}

// ---------------------------------------------------------------- rendering

/** A code fence longer than any backtick run inside `body`, so quoted text can never close it. */
function fenced(body: string, lang = ''): string {
  const longest = Math.max(0, ...(body.match(/`+/g) ?? []).map((r) => r.length));
  const f = '`'.repeat(Math.max(3, longest + 1));
  return `${f}${lang}\n${body}\n${f}`;
}

/** `file:line` references in engine text, in order of appearance. */
function citedLines(f: Finding): Array<{ file: string; line: number }> {
  const out: Array<{ file: string; line: number }> = [];
  if (f.evidence) out.push({ file: f.evidence.file, line: f.evidence.line });
  for (const m of f.reason.matchAll(/([\w./-]+\.(?:ya?ml|json|toml|py|lock)):(\d+)/g)) {
    out.push({ file: m[1] as string, line: Number(m[2]) });
  }
  return out;
}

function numbered(text: string, marked: ReadonlySet<number>): string {
  const lines = text.replace(/\n$/, '').split('\n');
  const width = String(lines.length).length;
  return lines
    .map((l, i) => `${marked.has(i + 1) ? '>>' : '  '}${String(i + 1).padStart(width + 2)} | ${l}`)
    .join('\n');
}

const blob = (repo: string, sha: string, file: string, line?: number): string =>
  `https://github.com/${repo}/blob/${sha}/${file}${line ? `#L${line}` : ''}`;

export function renderPacket(input: PacketInput): string {
  const { repo, sha, archetype, findings } = input;
  const out: string[] = [
    '---',
    `repo: ${repo}`,
    `sha: ${sha}`,
    `archetype: ${archetype}`,
    `findings: ${findings.length}`,
    `engine: ${input.engineVersion}`,
    'verdict: pending',
    'skeptic: pending',
    '---',
    '',
    `# ${repo}: ${archetype}`,
    '',
    `Commit [\`${sha}\`](https://github.com/${repo}/tree/${sha}). Generated by \`crawl review\`.`,
    '',
  ];
  if (input.ledgerEngineVersion && input.ledgerEngineVersion !== input.engineVersion) {
    out.push(
      `**Engine differs:** the crawler last scanned with \`${input.ledgerEngineVersion}\`, this packet used \`${input.engineVersion}\`. Rebuild at the ops repo's \`BLASTGATE_SHA\` before approving, or the finding ids may not match what the crawler would send.`,
      '',
    );
  }
  out.push(
    '## Verdict',
    '',
    'Set `verdict:` above to `confirmed` or `refuted` after working the checklist against the source. Approve only a confirmed packet, and only by pasting the entries at the bottom into the ops `config.json` `approved` list.',
    '',
    '## Skeptic',
    '',
    'Not run yet.',
    '',
    '## Findings',
    '',
  );
  findings.forEach((f, i) => {
    out.push(`### ${i + 1}. \`${f.id}\``, '');
    out.push(`- **path:** ${f.path.join(' → ')}`);
    if (f.evidence) {
      out.push(
        `- **at:** [${f.evidence.file}:${f.evidence.line}](${blob(repo, sha, f.evidence.file, f.evidence.line)}), reaching \`${f.evidence.capability}\``,
      );
    }
    out.push(`- **why:** ${f.reason}`, `- **fix:** ${f.remediation}`);
    if (f.labels.length > 0) out.push(`- **labels:** ${f.labels.join(', ')}`);
    out.push('');
  });

  out.push('## Checklist', '', ...checklist(archetype).map((c) => `- [ ] ${c}`), '');

  out.push('## Source at this commit', '');
  const cited = new Map<string, Set<number>>();
  for (const f of findings) {
    for (const { file, line } of citedLines(f)) {
      cited.set(file, (cited.get(file) ?? new Set()).add(line));
    }
  }
  for (const [file, lines] of cited) {
    out.push(`### [${file}](${blob(repo, sha, file)})`, '');
    const text = input.readSource(file);
    out.push(
      text === null
        ? '_Not found in the clone. Open it on GitHub at the link above._'
        : fenced(numbered(text, lines)),
      '',
    );
  }
  const others = input.workflows.filter((w) => !cited.has(w));
  if (others.length > 0) {
    out.push(
      '### Other workflows in this repo',
      '',
      'A `workflow_run` trigger or a reusable workflow lives in one of these.',
      '',
      ...others.map((w) => `- [${w}](${blob(repo, sha, w)})`),
      '',
    );
  }

  const body = buildRequestBody(
    composeReport({ repo, sha, findings, blastgateVersion: input.engineVersion }),
  );
  out.push(
    '## Report that would be sent',
    '',
    fenced(JSON.stringify(body, null, 2), 'json'),
    '',
    '## Approve',
    '',
    'Only if `verdict: confirmed`. Paste these into `approved` in the ops `config.json`:',
    '',
    fenced(
      JSON.stringify(
        findings.map((f) => ({ repo, sha, findingId: f.id })),
        null,
        2,
      ),
      'json',
    ),
    '',
  );
  return out.join('\n');
}

// ---------------------------------------------------------------- runReview

export interface ReviewArgs {
  ledger: string;
  out: string;
  /** Review only this repo. */
  repo?: string;
}

export interface ReviewDeps {
  /** Extra env for the scan script (tests: EVAL_REMOTE_BASE, BLASTGATE_CLI). */
  env?: NodeJS.ProcessEnv;
  scanRepos?: typeof defaultScanRepos;
  log: (line: string) => void;
  /** Observes the temporary clone root (tests check it is removed). */
  onWorkdir?: (dir: string) => void;
}

export interface ReviewSummary {
  packets: number;
  /** Repos with a held fail that no longer fail at HEAD. */
  resolved: string[];
  /** Repos that could not be cloned or scanned. */
  unscannable: string[];
}

const UNSENT = new Set(['held', 'queued']);

const packetName = (repo: string, archetype: string): string =>
  `${repo.replace('/', '__')}__${archetype.replace('->', '--').replace(/[^A-Za-z0-9._-]/g, '_')}.md`;

/** Read a repo file only if it is a regular file that really lives inside the clone. */
export function cloneReader(clone: string): (file: string) => string | null {
  let base: string;
  try {
    base = realpathSync(clone);
  } catch {
    return () => null;
  }
  return (file) => {
    const full = resolve(clone, file);
    try {
      if (!lstatSync(full).isFile()) return null;
      const real = realpathSync(full);
      if (!real.startsWith(base + sep)) return null;
      return readFileSync(real, 'utf8');
    } catch {
      return null;
    }
  };
}

function listWorkflows(clone: string): string[] {
  const dir = join(clone, '.github', 'workflows');
  try {
    return readdirSync(dir)
      .filter((f) => /\.ya?ml$/.test(f))
      .sort()
      .map((f) => `.github/workflows/${f}`);
  } catch {
    return [];
  }
}

/**
 * Skeptic verdicts (0094), most urgent first: what it disproved or doubted needs Jay's eyes
 * before anything it could not refute. Anything unrecognized sorts with `pending`.
 */
export const SKEPTIC_VERDICTS = ['refuted', 'doubtful', 'pending', 'could-not-refute'] as const;

function skepticRank(v: string): number {
  const i = (SKEPTIC_VERDICTS as readonly string[]).indexOf(v);
  return i === -1 ? SKEPTIC_VERDICTS.indexOf('pending') : i;
}

function frontField(md: string, key: string): string | undefined {
  return new RegExp(`^${key}: (.*)$`, 'm').exec(md.split('\n---\n')[0] ?? '')?.[1];
}

export async function runReview(args: ReviewArgs, deps: ReviewDeps): Promise<ReviewSummary> {
  const out = resolve(args.out);
  if (out === ROOT || out.startsWith(ROOT + sep)) {
    throw new Error(
      `refusing to write review packets inside the public blastgate repo (${out}); they name unfixed vulnerabilities. Use the private ops repo.`,
    );
  }
  const ledger = parseLedger(readFileSync(args.ledger, 'utf8'));
  const repos = [
    ...new Set(ledger.disclosures.filter((d) => UNSENT.has(d.state)).map((d) => d.repo)),
  ]
    .filter((r) => args.repo === undefined || r === args.repo)
    .sort();

  const work = mkdtempSync(join(tmpdir(), 'blastgate-review-'));
  deps.onWorkdir?.(work);
  const summary: ReviewSummary = { packets: 0, resolved: [], unscannable: [] };
  const rows: Array<{ skeptic: string; line: string }> = [];
  try {
    const scans = await (deps.scanRepos ?? defaultScanRepos)(repos, {
      workdir: join(work, 'clones'),
      outdir: join(work, 'eval'),
      env: childEnv(deps.env ?? {}),
    });
    mkdirSync(out, { recursive: true });
    for (const repo of repos) {
      const scan = scans[repo];
      if (!scan || scan.verdict === 'clone-failed' || scan.verdict === 'unknown') {
        summary.unscannable.push(repo);
        continue;
      }
      if (scan.verdict !== 'fail') {
        summary.resolved.push(repo);
        continue;
      }
      const name = repo.replace('/', '__');
      const all = JSON.parse(readFileSync(join(work, 'eval', `${name}.json`), 'utf8')) as Finding[];
      const groups = new Map<string, Finding[]>();
      for (const f of all.filter((x) => x.tier === 'fail')) {
        const a = archetypeOf(f);
        groups.set(a, [...(groups.get(a) ?? []), f]);
      }
      const clone = join(work, 'clones', name);
      const readSource = cloneReader(clone);
      const workflows = listWorkflows(clone);
      for (const [archetype, findings] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
        const file = join(out, packetName(repo, archetype));
        // Never clobber a reviewed packet for the same commit; a new commit needs a new review.
        let md: string;
        const prior = existsSync(file) ? readFileSync(file, 'utf8') : undefined;
        if (prior !== undefined && frontField(prior, 'sha') === scan.fullSha) {
          md = prior;
          deps.log(`review: kept ${packetName(repo, archetype)} (same commit)`);
        } else {
          md = renderPacket({
            repo,
            sha: scan.fullSha,
            engineVersion: scan.engineVersion,
            ...(ledger.repos[repo]?.engineVersion
              ? { ledgerEngineVersion: ledger.repos[repo].engineVersion }
              : {}),
            archetype,
            findings,
            readSource,
            workflows,
          });
          writeFileSync(file, md);
        }
        summary.packets++;
        const skeptic = frontField(md, 'skeptic') ?? '?';
        rows.push({
          skeptic,
          line: `| ${repo} | ${archetype} | \`${scan.fullSha.slice(0, 7)}\` | ${findings.length} | ${skeptic} | ${frontField(md, 'verdict') ?? '?'} | [packet](${packetName(repo, archetype)}) |`,
        });
      }
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  const index = [
    '# Held fails: review packets',
    '',
    "Each packet is one (repo, archetype) fail rescanned at the repo's current HEAD. Work the",
    'checklist against the quoted source, set `verdict:`, and approve only confirmed packets.',
    "Sorted by the skeptic's verdict, refuted and doubtful first. The skeptic is advisory: only",
    'your `verdict:` and an `approved` entry can release a report.',
    '',
    '| Repo | Archetype | Commit | Findings | Skeptic | Verdict | Packet |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...rows
      .map((r, i) => ({ ...r, i }))
      .sort((a, b) => skepticRank(a.skeptic) - skepticRank(b.skeptic) || a.i - b.i)
      .map((r) => r.line),
    '',
  ];
  if (summary.resolved.length > 0) {
    index.push(
      '## No longer failing',
      '',
      ...summary.resolved.map(
        (r) => `- ${r}: no longer fails at HEAD; the next crawl resolves its held disclosure.`,
      ),
      '',
    );
  }
  if (summary.unscannable.length > 0) {
    index.push(
      '## Could not scan',
      '',
      ...summary.unscannable.map((r) => `- ${r}: clone or scan failed; nothing can be judged.`),
      '',
    );
  }
  writeFileSync(join(out, 'README.md'), index.join('\n'));
  deps.log(
    `review: ${summary.packets} packet(s), ${summary.resolved.length} resolved, ${summary.unscannable.length} unscannable -> ${out}`,
  );
  return summary;
}
