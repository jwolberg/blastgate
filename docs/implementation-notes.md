# Implementation Notes

Running log of decisions, deviations, and tradeoffs for human review.

## 2026-09-29 — Precision Core (0045–0053)

Plan: `docs/plans/2026-09-29-001-feat-precision-core-plan.md`.

- **0045 — invalid YAML yields no positions.** `locateSource` returns `undefined` for every lookup when the document has parse errors, rather than best-effort positions from a partial tree. The analyzer already reports the parse error, and evidence that might point at the wrong line is worse than none (R8 demotes it).
- **0047 — deviation: `id-token: write` stays a credential sink.** The plan's KTD4 said only code-write (`contents: write` / `write-all`) is a credential sink. `id-token: write` lets the job mint cloud credentials via OIDC (e.g. assume an AWS role), which is secret-equivalent under R1, and it already failed before this change. Demoting it would have turned a real exploit path into a warn. Added `mintsCredentials` alongside `codeWrite`.
- **0047 — follow-up to revisit: `packages: write`.** It can publish a poisoned package/image, a supply-chain compromise outside the repo. Under R3's literal "changing code in a repo" it is a warn. Worth a product decision.
- **0048 — approximation: "code runs after the untrusted checkout".** A fork-PR path is fail-eligible only when a `run:` step or a local `./` action comes after the untrusted checkout. Any such `run:` is treated as able to run attacker-controlled repo code (scripts, Makefiles, configs), even `echo`. Fail-leaning on purpose: it only removes the clear no-execution case (checkout as the last step).
- **0048 — sequencing deviation: e2e flip landed here, not in 0050.** The existing `untrusted-text-injection` fixture (claude-code-action reading a comment) becomes `warn` under the contract. Its expectation flips in this commit so every commit stays green. 0050 still adds the new shell-injection fixture pair.
- **0048 — evidence on warns.** Agent-ingested, action-input, and unrecognized findings still carry `file:line` + capability (useful for triage) but never a payload. Payload presence is what separates a fail's proof from a warn's pointer.
- **0054 — added mid-session after the first re-scan.** All 4 remaining fails (pytorch ×3, grafana) were false positives: validated `X=$(cat f)` assignments that the 0042 regex treated as shell splices. The detector is now quote- and assignment-aware. Accepted false negative: a quoted `"$(<f)"` used as a whole argument can still inject a leading `--flag`. The plan's R12 premise that the four August artifact findings stay fail was wrong and was amended (user-approved).
- **0051 — result and caveats.** Re-scan: 0 fails, 15 warns, 0 UNKNOWN (`docs/evaluations/2026-09-29-precision-core-rescan.md`). A zero-fail sample makes fail precision untestable, so fail recall needs Track 3's labeled benchmark. Two repo owners (`fastapi`, `laravel`) were reconstructed from short names.
- **0051 — gap found for Track 2.** Issue text passed via `env:` into an LLM call (home-assistant's GitHub Models triage) is prompt injection, but it produces no finding. `env:` protects the shell, not a model. Agent detection keys on known coding-agent actions only.
- **0052 — descoped (user-directed).** Live sandbox reproductions on throwaway repos were dropped in favor of the committed fixture pairs, whose fails the e2e suite already requires to carry complete evidence (plan KTD7).

## 2026-08-06 — 0044: injection precision (in-step guards + safe handling)

- **Problem.** The top-50 scan showed the `untrusted-text-injection → secret` finding fires on
  *co-presence* of (untrusted event text) + (a secret in the job), missing two things that
  separate a real exploit from safe automation: in-step/in-script actor guards the `if:`-only
  detector (0017) can't see, and whether the text is actually *injected* vs merely *compared*.
- **Three new, conservative detectors** (fail-closed: an unrecognized guard leaves the finding
  standing, like 0041):
  - `isLabelGated` (parse.ts): `if: github.event.label.name …` — applying a label needs
    triage/write, so an outside contributor can't self-trigger (node's flaky-test / review-wanted).
  - `hasScriptPermissionGuard` (parse.ts): an `actions/github-script` step that checks
    collaborator/actor permission AND `throw`s — halting the job before any secret step (vite /
    svelte `ecosystem-ci-trigger`). A check that only sets an output is deliberately NOT a guard,
    so ant-design's un-gated DingTalk step stays a finding.
  - `textOnlyBooleanMatched` (injection.ts): every `body/title` ref appears only inside a boolean
    guard (`contains`/`startsWith`/`endsWith`) and no coding-agent action is present — the text is
    compared, never injected (pytorch's `claude-code.yml`, react-native's `/rebase`).
- **Scope: text path only.** `injectionNeutralized` gates only the TEXT-injection finding.
  `workflow_run` artifact injection (0042) keeps its original narrow `!hasActorGuard` and is never
  softened — it keys on a real shell-splice sink and was high-confidence in the review.
- **Deviation from the ticket's "downgrade to warn" wording → chose SUPPRESSION.** The injection
  finding was already suppressed-on-guard (unlike fork-pr, which warns via the `guarded` field), so
  extending *which* guards suppress keeps one consistent rule and a minimal, low-risk change; the
  regression bar is "NOT fail," which suppression satisfies. A future refinement could downgrade a
  solidly-guarded injection job to warn for fork-pr parity.
- **Empirical result (re-scan of the 18 prior-FAIL repos).** 18 FAIL → 13 FAIL / 5 PASS; fail-tier
  findings 46 → 27 (19 FPs removed). All 5 cleared repos hand-verified as genuine FPs (vite/svelte
  github-script guard; node label-gated; react-native `/rebase` boolean-matched; elasticsearch
  label-gated + `jq`-safe). All 4 artifact-injection findings and the un-gated credentialed jobs
  (ant-design, electron, transformers, …) preserved — no false negatives observed.
- **Known limitation (documented, not fixed).** A bare `actions-cool/check-user-permission` action
  whose result gates a *later step's* `if:` (not a job-wide halt) is not recognized as a guard —
  fail-closed, so ant-design correctly still fails. Per-step dataflow gating is future work.

## 2026-08-06 — 0040: yarn.lock + pnpm-lock.yaml dependency analysis

- **Decision: a new `jsdeps` analyzer, mirroring RubyGems** — not an extension of the
  npm `deps` analyzer. yarn/pnpm are the npm *ecosystem* but their lockfiles omit npm's
  `hasInstallScript` flag, so they need RubyGems' "diff-gated, assume install-capable"
  semantics, which differ from the npm path's "parse the whole lockfile with real flags."
  A separate analyzer keeps the critical npm path untouched and matches the reviewed
  RubyGems shape (`ecosystem: 'npm'`, `hasInstallScript: true`, `entry:new-dep:<pkg>` →
  `dep:<pkg>@<ver>` → engine `runs-in` synthesis unchanged).
- **Collection precedence (collect.ts): npm wins, else yarn, else pnpm.** A repo uses one
  JS package manager; gating yarn/pnpm on `package-lock.json` being absent avoids double
  analysis and ID collisions (both use the npm `dep:`/`entry:new-dep:` ids on purpose, so
  findings/labels/`describe()` are identical to npm's — ASI04/MCP04).
- **Parsers scoped to the common cases (per the ticket's design note).** `parseYarnLock`
  handles v1 "classic" and common Berry v2+ with one unindented-header + indented-`version`
  shape; exotic Berry protocols (`@patch:`/`@workspace:`/git) that don't yield a clean
  version are skipped. `parsePnpmLock` reads the `packages:` map and `pkgFromKey`
  normalizes v5 (`/name/ver`), v6 (`/name@ver(peer)`), and v9 (`name@ver`) key forms.
- **Diff keyed by package name → version (RubyGems parity).** Same known limitation: a
  package resolved at two versions simultaneously collapses to one entry. Acceptable —
  the gate verdict (any added/bumped dep in a fork-installed secret job → fail) is
  unaffected; worst case is a slightly imprecise change label.
- **Fail-closed:** an unparseable lockfile → error diagnostic → UNKNOWN (0020), same as npm.
- **Known gap (follow-up):** `.npmrc` change analysis is still gated on the npm path, so a
  yarn/pnpm repo's `.npmrc` registry-redirect signal is not yet surfaced; `.yarnrc.yml`
  likewise. Lockfile coverage was the ticket's scope; filed as a follow-up.
- **Fixtures:** `yarn-install-secret` + `pnpm-install-secret` (positive = added dep +
  fork-triggerable install job → fail; negative = same added dep but a `push`-only job →
  pass), wired into the `engine.e2e` coverage check. Full suite green.

## 2026-08-06 — 0039: graph-cap UNKNOWN on large repos (algorithm, not threshold)

- **Dimension that blew the cap.** The 0018 guard bounded `|entries| × |sinks|`, a
  proxy for the number of per-pair `bidirectional()` searches `reachablePaths` ran.
  On a big monorepo (40+ workflow files) hundreds of fork-triggerable jobs (entries)
  multiply hundreds of distinct secret + per-job `GITHUB_TOKEN` sinks past the 200k
  ceiling, so 4/12 in-scope repos in the 2026-08-05 run came back UNKNOWN with 0
  findings — the worst outcome (no signal *and* blocks the gate).
- **Decision: compute reachability incrementally so size scales** (the ticket's third
  option), not raise the threshold or prune. `reachablePaths`/`shortestPathsToSinks`
  now run **one single-source BFS per entry** (`singleSource` from
  `graphology-shortest-path/unweighted`) instead of a `bidirectional` search per
  (entry, sink). One BFS finds the shortest path to *all* reachable sinks at once, so
  real cost drops from `O(entries × sinks × (V+E))` to `O(entries × (V+E))` — linear
  in graph size. The genuine reachable paths on those repos were always few and short;
  the old cost model just refused to look.
- **Guard recalibrated to the real cost.** `reachabilityCost` is now
  `|entries| × (|nodes| + |edges|)` (the BFS-per-entry work), ceiling raised to
  `MAX_REACHABILITY_COST = 5e7` (`EngineOptions.maxPairs` → `maxCost`). Fail-closed
  (0020) is preserved: a fabricated tens-of-thousands-of-entries graph still exceeds
  the cap and returns UNKNOWN rather than hanging. The new algorithm also largely
  defangs the original 0018 DoS (5000×5000 pairs was ~25M `bidirectional` calls;
  it is now ~5000 BFS traversals).
- **Reproduction (acceptance #3/#4).** `caps.test.ts` builds a synthetic 60-workflow ×
  8-job monorepo (480 entries × 480 secrets = 230k entry×sink pairs, over the old cap)
  and asserts it now evaluates to a real `fail` verdict with findings and no error
  diagnostic — instead of a 0-finding UNKNOWN.
- **Parity note.** Output ordering is preserved (entries in id order, each entry's
  sinks in id order). Where a graph has multiple equal-length shortest paths for a
  pair, BFS may pick a different (still-shortest) intermediate path than the old
  bidirectional search; finding identity (`entry=>sink`), tier, and verdict are
  unchanged — only a displayed intermediate node could differ, and only when
  genuinely ambiguous. Real fixtures are linear chains, so no observed change.

## 2026-08-04 — Naming: Foothold → Blastgate

- **Decision:** Rename the product from **Foothold** to **Blastgate**.
- **Why:** "Foothold" names the *attacker's* move and says nothing about the
  differentiator. "Blastgate" encodes the model directly — *blast radius* = what a
  compromise can reach (the reachable-path thesis), *gate* = the enforcement surface
  (CI/PR gate, plugin hook). It reads as defender's language, not attacker jargon.
- **Alternatives considered:** Throughline (best on concept but npm + GitHub org both
  taken), Barbican (npm free but collides with OpenStack Barbican, a secrets manager),
  Portcullis / Cordon / Firebreak / Chokepoint / Interdict (npm + org taken), Reachpath
  (free but reads as a description, not a brand), Lastgate (taken + faint LastPass echo).
- **Availability (verified):** `blastgate` npm ✅ free, GitHub org ✅ free. Domains:
  `.dev` and `.com` taken; **`.io` and `.sh` available** — lean `blastgate.io` or
  `blastgate.sh` (the `.sh` matches the CLI framing and peer tools).
- **Follow-up:** ~~Repo directory is still `foothold/`~~ — done 2026-09-29: GitHub
  repo is `jwolberg/blastgate` and the local directory was renamed to `blastgate/`.

## 2026-08-04 — License: recommend Apache-2.0 (pending confirmation)

- **Decision (proposed):** Apache-2.0, not MIT. Manifest set to `Apache-2.0`; the
  `LICENSE` file is NOT yet added — awaiting user confirmation.
- **Why:** The peer group Blastgate aligns to (Trivy, Syft, Grype, OpenSSF Scorecard,
  Sigstore, OWASP ZAP) defaults to Apache-2.0, primarily for its explicit patent grant
  — which matters more for a novel security-analysis technique and enterprise adoption
  than for a typical npm library. MIT's only edge is simplicity / npm convention.
- **Reversibility:** Free to change now (zero external contributors); becomes costly
  only once others contribute under it.

## 2026-08-04 — Claude Code plugin scaffold

- **Decision:** Ship the plugin as a `plugin/` subdirectory of the product repo
  (non-destructive), self-hosting as its own marketplace (`source: "./"`).
- **Design — Pre vs Post asymmetry:** `PreToolUse` can block; `PostToolUse` cannot.
  So the plugin blocks at `git commit`/`git push` and manifest/workflow/MCP-config
  edits, and only *reacts* to `npm install` (contents exist only post-install),
  asking the agent to revert. The commit gate is the deterministic backstop.
- **Design — hook is load-bearing:** the deterministic hook is the real gate; the
  bundled MCP tool (`blastgate_check_change`) is ergonomics + the "agent checks
  itself" narrative and must never be the sole enforcement (a prompt-injected agent
  won't call it).
- **`bin/blastgate` is a stub:** default PASS everywhere so it never blocks real work
  while unimplemented; `BLASTGATE_DEMO_DENY=1` exercises the deny path. The stub also
  implements a minimal newline-delimited JSON-RPC MCP server so the plugin is
  connectable today. Real engine (cross-layer reachability) is the actual work and is
  the *same* engine the CI gate needs — the plugin adds no product scope.
- **Validation:** `claude plugin validate ./plugin --strict` passes. Added
  `metadata.description` to the marketplace manifest to satisfy strict mode.

## 2026-08-04 — Engine (U1): npm, not bun (deviation from repo convention)

- **Decision:** The engine package uses **npm** (package.json + package-lock.json,
  `npm run` scripts), overriding CLAUDE.md [11]'s bun default and the bun-based
  `.github/workflows/ci.yml` template.
- **Why:** Blastgate is npm-first and **dogfoods its own dependency layer** — U4's
  analyzer reads `package-lock.json`, and the plan's Definition of Done requires a
  self-scan. A bun project produces `bun.lockb`, not `package-lock.json`, so it
  could not scan itself. The product's own lockfile format dictates the toolchain.
- **Toolchain:** TypeScript (typecheck-only via `tsc --noEmit`, `moduleResolution:
  Bundler` so source imports stay extensionless), **tsup** for the `dist` build
  (avoids NodeNext `.js`-extension friction across tsc/vitest), **vitest** for
  tests, **eslint** (flat config) + **prettier** (scoped to `src`/`test`).
- **CI:** rewrote `.github/workflows/ci.yml` (was the bun template) to an npm
  `quality` job: `npm ci` → format:check → typecheck → lint → build → test.
- **License:** Apache-2.0 (confirmed by the user, resolving the pending call above);
  `package.json` `license` set accordingly.

## 2026-08-04 — Engine branch stacked on the plugin branch

- **Decision:** The engine work lands on `feat/blastgate-engine`, branched off the
  current `scaffold-blastgate-plugin` HEAD rather than `origin/main`.
- **Why:** `origin/main` holds only `LICENSE` — the plan, `.gitignore`, and the
  `plugin/` scaffold live only on `scaffold-blastgate-plugin`. Branching off bare
  main would drop the plan and `.gitignore` from the working tree. Stacking keeps
  the base coherent; engine commits stay isolated on their own branch (no collision
  with the plugin agent). Rebase onto `main` once the plugin branch merges.

## 2026-08-04 — Engine (U7): cross-layer engine + fail-threshold gate

- **Reachability refinement (R3 → per-(entry,sink)):** The engine reports the
  shortest path **per (entry, sink) pair**, not the single shortest path per sink
  that R3's literal wording (and `shortestPathsToSinks`) gives. Why: distinct
  attacker entry points reaching the same sink are distinct findings with distinct
  fixes — and a shorter *single-layer* path (fork-PR → job → secret) would
  otherwise **hide** the longer *cross-layer* path (install-script → dep → job →
  secret) that is the whole product thesis. Added `reachablePaths()` alongside the
  untouched `shortestPathsToSinks()`; entries/sinks are visited in id order for
  byte-identical output (determinism AC).
- **The one synthesized cross-layer edge — `runs-in`, gated on fork-triggerability:**
  `build.ts` adds `dep → job (runs-in)` only when `dep.hasInstallScript &&
  job.runsInstall && job.forkTriggerable`. An install script physically runs in
  *any* install job, but it is only *attacker-reachable* when the job is triggerable
  by untrusted input (a fork PR carrying the malicious change). A push-only install
  job runs the script only after a maintainer merges (trusted) — not an external
  attack path. This is exactly what makes the plan's non-fork integration case a
  **pass** (R14 precision) while AE1 fails.
- **Added `runsInstall: boolean` to `CiJobNode`** (set from the existing
  `hasInstallStep`), so the engine can wire `runs-in` without re-parsing workflows.
  Kept the field required (total type); updated the two U2/U3 test helpers that
  construct `CiJobNode` literals. Analyzers stay pure emitters — this is intra-layer
  job data, not a cross-layer edge.
- **Deliberately did NOT synthesize agent-grant → CI-secret edges.** The ticket AC
  lists "agent grant reaches sink"; that `reaches` edge (grant → privileged-
  capability sink) is already emitted by the U6 agent analyzer and is preserved
  through the merge — the engine's reachability turns it into the AE4 warn finding.
  A speculative agent → *CI secret* edge was rejected: per KD6/KTD6 the agent's
  blast radius is repo-declared grants, and CI secrets live in GitHub, not where a
  prompt-injected local agent runs. No fixture backed it; adding it would be
  aggressive and off-model.
- **3-state verdict vs binary gate:** `Verdict` is `fail | warn | pass` (informative);
  `gateFails()` is non-zero **only** on `fail` (KTD4). Warn-tier capability paths are
  reported without failing — so the plan's "gate verdict = pass (warn, not fail)"
  reads as verdict `warn`, gate does not fail (CLI will exit 0).
- **One `Finding` shape (`src/findings/finding.ts`), one entrypoint (`runEngine`).**
  Every surface (CLI/Action/plugin/MCP, U9–U14) rides `runEngine`; reason and
  remediation are derived from the path's cross-layer archetype, not free-form.

## 2026-08-04 — CLI (U9): blastgate command + plugin `--gate` hook mode

- **`runCli(argv, env)` is pure over an injected `CliEnv`** (a `RepoFs` port +
  stdin + stdout/stderr sinks). The whole CLI surface — scan, `--json`, and the
  hook gate — is offline-testable with an in-memory fs; the Node adapters
  (`readFileSync`, `readdirSync`, `git show` for `--base`) and real process I/O
  live only in the bin at the bottom of `index.ts`. 13 tests, no filesystem.
- **`import.meta.url === process.argv[1]` guard** around the bin invocation so
  importing the module for `runCli` in tests does **not** trigger `main()` /
  `process.exit`. The old U1 stub ran `process.exit(main())` at top level; that
  can't coexist with an importable `runCli`.
- **`--base` diff signals via `git show <ref>:<path>`** (KTD5), behind the
  `RepoFs.gitShow` port. A null base file ⇒ the path is new at head ⇒ every dep is
  "added" (correct for a brand-new lockfile). Gate mode defaults `--base HEAD` — a
  hook fires on an in-flight change, so diffing the working tree against HEAD lights
  up the new-dependency entry (verified in the smoke run: the cross-layer
  `postinstall → dep → fork job → AWS_SECRET_ACCESS_KEY` path appears only with a
  base).
- **Hook payloads match the plugin stub contract (KTD12):** PreToolUse phases
  (`pre-commit`, `pre-push`, `manifest-edit`, `workflow-edit`, `mcp-config-edit`)
  emit `{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",
  permissionDecisionReason:<ranked path → sink → fix>}}` and exit 0; the
  `dependency-install` PostToolUse phase emits `{decision:"block",reason:…}`
  (react-only). A non-fail verdict emits nothing (allow). The asymmetry (deny vs
  block) is the design — PostToolUse can't prevent, only signal a revert.
- **Exit codes:** scan mode exits non-zero **only** on a fail verdict (pass/warn →
  0), matching KTD4; gate mode exits 0 and communicates via the JSON payload (the
  plugin reads the decision, not the code).
- **`--provenance` is accepted but no-ops with a stderr note** (U8 not built yet);
  **`mcp` prints a "not wired yet (U13)" note.** Neither blocks U9. Non-existent
  path arg → clear stderr error + exit 2, no stack trace.

## 2026-08-04 — GitHub Action (U10): thin wrapper, structural parity

- **Parity is structural, not coincidental.** `runActionCore(fs, opts)` is literally
  `runEngine(collectInputs(fs, opts))` — the same call the CLI scan makes — so the
  Action and CLI cannot drift. The parity test asserts the two produce byte-identical
  findings JSON on the AE1 fixture; the Action file adds only PR surfacing.
- **Shared Node fs/git adapter.** Extracted `nodeRepoFs` into `src/cli/node-fs.ts`
  so the CLI and Action bins read a repo through the exact same adapter (the only
  code touching `node:fs`/`git`); collect/render/gate stay pure ports.
- **Surfacing:** `::error`/`::warning title=Blastgate::` workflow annotations (one
  per finding, message-escaped) + a job-summary markdown table appended to
  `$GITHUB_STEP_SUMMARY`; table cells escape `|`/newlines. No file/line positions in
  v1 (findings don't carry them) — annotations render fine without, which is the
  plan's "missing position info" edge case as the default path.
- **`base` defaults to `GITHUB_BASE_REF`** so a PR run gets diff signals for free
  (KTD5). `provenance` input accepted but no-ops with a warning (U8 pending).
- **Packaging caveat (filed as ticket 0015):** `action.yml` `main:` →
  `dist/action/index.js`, but `dist/` is gitignored. A consumed action runs that
  file directly with no build step, so the built JS must be committed at release
  refs. U10 proves the logic (parity + a real `node dist/action/index.js` smoke run
  over both fixtures); making the action third-party-consumable is a release-workflow
  follow-up — deliberately NOT committing `dist/` on every commit.

## 2026-08-05 — MCP self-check server (U13): blastgate mcp

- **Advisory, never enforcement (KTD12).** `blastgate_check_change` wraps the U7
  engine and returns the same `Finding` verdict the CLI gate produces, but its
  result is a plain MCP tool result (verdict + ranked paths + an "advisory only"
  note) — never a `decision:block` / `permissionDecision:deny`. A test asserts the
  tool output contains neither. The pre-commit hook stays the load-bearing gate; a
  prompt-injected agent won't voluntarily self-check.
- **Parity by construction (KTD10).** `checkChange` = `runEngine(collectInputs(...))`
  — the same call the CLI/Action make. A parity test asserts the tool's
  `structuredContent.findings` equal the CLI `--json` findings on the AE1 fixture.
- **`handleRequest` is pure (request → response).** JSON-RPC dispatch is offline-
  testable with an in-memory `RepoFs`; the newline-delimited stdio transport
  (`runStdioServer`) is the only stateful part and lives in the bin. Notifications
  (no `id`) yield no response; unknown methods → JSON-RPC `-32601`; a malformed
  tool argument or unknown tool name → a structured `isError:true` result (the
  agent sees it) and the server stays up — protocol errors and tool errors are kept
  distinct.
- **Scoped to the project dir.** The bin roots the server's `RepoFs` at
  `BLASTGATE_PROJECT_DIR ?? CLAUDE_PROJECT_DIR ?? '.'` (what `plugin/.mcp.json`
  passes), with diff base defaulting to HEAD. Smoke-verified over real stdio:
  initialize / tools/list / tools/call all respond correctly on the AE1 git fixture
  (verdict fail, 2 findings incl. the cross-layer ASI04/MCP04 path).
- **`mcp` handled in the bin, not `runCli`.** The stdio loop needs the real process
  streams, so `main()` intercepts `mcp` before the pure `runCli` dispatch; `runCli`
  keeps a harmless fallback note for a direct `mcp` call. Unblocks U14 (the plugin's
  MCP surface).

## 2026-08-05 — Claude Code plugin (U14): wired to the real engine + override

- **`plugin/bin/blastgate` is now a real shim, not a stub.** It resolves the engine
  CLI (the co-located `../../dist/cli/index.js` when developing in this repo, else
  `npx -y blastgate`) and forwards argv/stdin/stdout/stderr/exit-code straight
  through — re-implementing nothing (KTD10). Dropped the fake `BLASTGATE_DEMO_DENY`
  path and the stub MCP server (the real U13 server replaces it). Smoke-verified end
  to end via the actual bin over a git fixture: PreToolUse `deny` (AE5), PostToolUse
  `block` (npm install), clean → allow, and `/blastgate` (`check --since HEAD`).
- **CommonJS island:** the repo root is `"type":"module"`, which made Node parse the
  extensionless CJS bin as ESM (`require is not defined`). Added `plugin/package.json`
  `{"type":"commonjs"}` so the plugin subtree is CJS both in-repo and when installed
  standalone (Node resolves the nearest package.json). `claude plugin validate ./plugin
  --strict` still passes.
- **Acknowledged-finding override (engine, honored by all surfaces).** A committed
  `.blastgate/acknowledged.json` (`{acknowledged:[{id,reason}]}`) downgrades a matching
  **fail → warn** (recording the reason on the `Finding`), so the gate stops failing
  but the finding is still reported — never silently dropped. Implemented in the engine
  gate (`applyAcknowledgements` in `runEngine`) and read by `collectInputs`, so the CLI,
  Action, MCP tool, and plugin hook all honor it identically. Finding `id`
  (`<entry.id>=><sink.id>`) is the stable key. **No env kill switch** — the only way
  past a fail is to add its id to a file that shows in the diff/git history (the plan's
  "auditable override, not an all-or-nothing switch" lean). Expiry/`by` fields are a
  future enhancement.
- **`--since` alias:** the `/blastgate` SKILL calls `check --since <ref>`; wired
  `--since` as an alias for `--base`.
- **Self-scan clean:** a test runs the engine over Blastgate's own committed
  `plugin/.mcp.json` (a `${CLAUDE_PROJECT_DIR}`-scoped `blastgate mcp` tool server) and
  asserts no finding — the plugin never flags itself on install (U6 baseline).

## 2026-08-05 — Provenance-regression check (U8): opt-in, network-gated

- **The one network-touching check, off by default (KTD6).** `--provenance` is the
  only path that hits `registry.npmjs.org`; the whole scan/gate is otherwise offline
  and deterministic. The fetcher is constructed *inside* the `--provenance` CLI
  branch only, so the core literally cannot make a request without the flag (the
  entire offline test suite passing over the network-free sandbox is the proof).
- **`dist.attestations` presence is the sole primitive.** A package whose version
  changed and that *had* attestations at the base version but *lost* them at the head
  version is a regression (the CVE-2025-54313 shape). Absence at both versions is not
  a regression; a newly added package has no baseline; a fetch failure is a soft
  `null` (never a gate fail). The network is behind a `PackumentSource` port so tests
  run against recorded packuments — no live network in CI.
- **Emitted as a supply-chain `EntryNode`, not a bolt-on finding.** A regression
  produces `entry:provenance:<pkg>` + a `controls` edge to the head dep node + a
  diagnostic. It feeds the U7 graph exactly like a new-dependency entry, so it only
  becomes a *finding* when the regressed package reaches a sink — and then it ranks
  and labels through the normal pipeline (integration test: a regressed install-script
  dep in a fork-triggerable secret job → a fail finding). This keeps R14 precision:
  a provenance regression on an unreachable package is a diagnostic, not a gate fail.
- **Caching per package.** `cachedFetcher` dedupes by package name, so a base+head
  check of the same `pkg` is one request (asserted by a call counter). Merged last in
  `buildGraph` so its `entry→dep` edge targets the dependency node the deps analyzer
  already emitted.
- **Wired into both scan and check modes** behind the flag; `--provenance` needs a
  `--base` for a version baseline (a stderr note + skip otherwise). Provenance stays
  off in the plugin hooks by default (they must be fast/offline) unless a phase is
  explicitly invoked with the flag.

## 2026-08-05 — Fixture-repo test suite (U11): the engine's regression harness

- **On-disk minimal repos, exercised through the real filesystem collector.** Each
  `test/fixtures/<check>/{positive,negative}/` is a tiny repo (package.json, lockfile,
  workflow, and/or agent config); `engine.e2e.test.ts` builds a `RepoFs` over it and
  runs the *full* engine — the same `collectInputs → runEngine` path the CLI uses.
  This is the credibility deliverable (KD4): real reasoning proven by fixtures, not a
  staged demo.
- **Git-free diff signals.** Diff-based checks need a base lockfile; rather than make
  each fixture a git repo, `fixtureFs.gitShow` serves the base from a committed
  `package-lock.base.json` sidecar. Provenance fixtures ship a `packuments.json` that
  a recorded fetcher reads — the e2e stays fully offline.
- **Positive verdict is per-check, not always "fail."** The agent-overprivilege check
  is warn-tier (a capability sink), so its true-positive verdict is `warn`; the
  secret-path checks are `fail`. Each `CheckSpec` declares its expected positive
  verdict + a path/label assertion; every negative asserts `pass` + zero findings
  (R14).
- **Coverage guard enforces the R13 bar mechanically.** One test asserts the on-disk
  fixture dirs are *exactly* the declared check list and each has both a `positive/`
  and `negative/` — so adding a check without a fixture pair (or an orphan fixture)
  fails the suite. Verified it bites by hiding a negative dir (suite red) and restoring
  (green).
- Four shipped checks covered: install-script→secret (AE1/AE2), fork-PR→secret,
  agent-overprivilege (AE4), provenance-regression (AE3). 9 e2e tests; 98 total.

## 2026-08-05 — Threat-model POV doc (U12): the KD5 success measure

- **`docs/threat-model.md` is written for the "distinguishability" reader** (Success
  Criteria): the threat (repo-as-execution-surface, Shai-Hulud, slopsquatting,
  unsigned agent marketplaces), the cross-layer reachable-path model (nodes/edges/gate
  + a mermaid AE1 diagram), a tool-by-tool positioning table (inventory vs
  dependency/CI/MCP single-layer vs Blastgate's connective layer), the OWASP
  archetype→category mapping (every category it emits is defined there, with the
  MCP-draft `:2025` caveat), OWASP-as-asset framing, and the plugin-as-dogfood angle.
- **OWASP labels verified against `src/taxonomy/owasp.ts`** so the doc's category
  names match what the engine actually emits (ASI01/ASI03/ASI04, MCP02/MCP04/MCP10).
- README gained a short Positioning section linking the doc. No code changed — the
  98-test gate is unaffected (documentation deliverable, `Test expectation: none`).

## 2026-08-05 — Scan scope is gitignore-aware (ticket 0016, dogfood fix)

- **Found by dogfooding on Blastgate's own repo:** `blastgate .` warned on a
  `type: command` hook in `.claude/settings.json`, but that file is gitignored (local
  harness config, never committed). Blastgate reasons about the repo's *shipped*
  surface (KD6), so a gitignored path must not produce a finding.
- **Fix:** `nodeRepoFs` is now gitignore-aware — `read()` and `listWorkflows()` drop
  any path `git check-ignore` matches (memoized per path). An untracked-but-**not**-
  ignored file (an in-flight change a hook fires on) is still scanned; a non-git target
  falls back to reading the working tree unfiltered. The filter lives in the Node
  adapter only, so the pure collector and in-memory tests are untouched.
- **Verified:** a temp-git-repo test asserts a gitignored `.claude/settings.json`
  command hook scans clean (pass) while a tracked one still warns, plus the non-git
  fallback. Re-ran the self-scan → clean **PASS**. This closes the first
  false-positive class found in real use (R14 precision on real repos).

## 2026-08-05 — Model if: actor/trigger guards (ticket 0017, dogfood-driven)

- **Motivated by the volscan finding:** Blastgate failed the Claude Action job, which
  is correct — but it couldn't see whether an `if:` actor guard mitigated the untrusted
  trigger. 0017 teaches it to recognize one.
- **`hasActorGuard(job)` (parse.ts) is conservative and fail-closed.** Only two patterns
  count as a guard: an `author_association` compared against a trusted role
  (OWNER/MEMBER/COLLABORATOR), or a `github.actor`/`github.triggering_actor`
  comparison/allowlist. Anything else — including volscan's `contains(body, '@claude')`
  cost filter — is *not* a guard, so an unrecognized `if:` never downgrades a finding.
  Re-scanned volscan after the change: still FAILs (exit 1), as it should.
- **Guard lives on the fork-PR `EntryNode` (`guarded?`), not `CiJobNode`.** Deviation
  from the ticket's suggestion, on purpose: the gate downgrade keys off the path's
  entry, and a guarded entry ("triggerable, but only by trusted actors") is the natural
  carrier. Set by the CI analyzer from `hasActorGuard(job)`.
- **Downgrade, don't suppress (KTD4 refinement).** `checks.ts` downgrades a guarded
  fork-PR → secret path from **fail → warn** with a reason that says the trigger is
  actor-gated but the broad credential scope is still a least-privilege risk. The gate
  stops failing on a properly-gated job while still reporting it; an ungated one still
  fails. Covered by unit tests (`hasActorGuard`), analyzer tests (entry.guarded), and
  engine tests (gated=warn / ungated=fail).
- **Follow-up polish (not blocking):** ranking could sort fails above warns of equal
  score; a dedicated U11 fixture pair could be added — the behavior is already covered
  by inline-workflow engine tests.

## 2026-08-04 — Reframe committed command hooks: capability advisory, not injectable path (U18)

- **Dogfood finding.** Scanning `../TerMinal` surfaced a WARN that read as a manufactured
  attack path: `injectable agent surface (.claude/settings.json (hook)) → .claude/settings.json
  (hook) (shell:command hook) → shell:command hook`, labelled `ASI01:2026`. A committed
  `type: command` hook fires **deterministically** on an event — it is never selected by a
  prompt-injected model — so tagging it an "injectable agent surface" / ASI01 Agent Goal
  Hijack is a category error. It is a real *privileged capability* worth reviewing, but not
  an attacker-injectable entry. Blastgate's own settings.json (block-main-merge / stop-notify /
  remote-check hooks) trips the same rule, so the noise was self-inflicted.
- **Decision (chosen by user): reframe, keep firing.** Still WARN on a tracked command hook,
  but drop the injection framing. New `EntryKind: 'privileged-hook'` (types.ts); the hook grant
  is tagged `injectable: false` (capability.ts) and `emitGrant` wires `entry --reaches--> sink`
  **directly** (no injected-grant middleman), so the rendered path is the clean two-node
  `.claude/settings.json (committed hook) → shell:command hook` instead of a triple-restated
  chain. Only the command hook is affected — permission-rule shell grants (`Bash(*)`) and
  over-baseline MCP servers stay `injectable-agent-surface` / ASI01, since the agent *does*
  invoke those and an injected prompt can steer them.
- **Taxonomy:** `privileged-hook → ASI03` (Identity & Privilege Abuse) + `MCP02` (Privilege
  Escalation via Scope Creep); **no ASI01**. Ranks below a genuine injectable capability
  (entry exposure 1 vs 2). Reason/remediation reworded as a scope-review advisory.
- **Verified:** typecheck + eslint clean, 110/110 tests pass (updated agent/label/scan-scope
  tests assert the new entry kind, labels, and 2-node path; the injectable-MCP e2e + AE4 tests
  are untouched and still green). Re-ran the original CLI command → reframed WARN, exit 0.

## 2026-08-05 — Human-readable markdown report + workflow-fit guidance (--format md)

- **Why.** The tool was functional across all surfaces but the only output was
  terminal text + a JSON array, and nothing in the output told a user *where
  Blastgate belongs in their workflow*. Both gaps were UX, not engine.
- **Decision: one canonical markdown renderer, reused by every surface.** New
  `renderMarkdown()` in `src/cli/render.ts` is the single human-readable report —
  verdict headline, a shared `WORKFLOW_GUIDANCE` "where this runs" banner
  (local hook → CI PR gate → pre-merge) + gate policy, one section per finding
  (attacker→sink path, why, fix, sink, OWASP labels), and verdict-tailored next
  steps. `renderText()` gained the same one-line workflow footer.
- **Parity over a second format.** Rather than add a CLI-only report and leave the
  Action's bespoke `summaryTable()`, the Action's job summary now calls
  `renderMarkdown()` too — deleting `summaryTable`/`cell`. So the PR job summary and
  `blastgate --format md` are literally the same report (KTD10/R7); they cannot
  drift. The parity test's old `toContain('|')` (table) assertion was updated to the
  report shape (header + banner + sink + label).
- **CLI surface.** `--format text|json|md` with `--md`/`--json` shorthands
  (`outputFormat()` picks the renderer; json wins over md if both given). Chose `md`
  over `html` per the user — markdown renders natively in PR comments/job summaries
  and reads fine in a pager, no asset-embedding needed.
- **Docs pass.** README "Usage" gained a "Where it fits in your workflow" section and
  the `--format md` example; the adopt-blastgate runbook frames the local→PR→merge
  order and the report. (README also carried a pre-existing, unrelated intro rewrite
  in the working tree at the time of this change.)
- **Verified.** typecheck + eslint + prettier clean; full suite **197 passing**
  (was 189; +8 renderer/CLI tests). Ran the built CLI on the fork-pr-secret (FAIL,
  exit 1), agent-overprivilege (WARN, exit 0), and self (PASS, exit 0) — report and
  exit codes correct.

## 2026-08-05 — release.yml also ships the Marketplace Action (0027)

- **Why.** `release.yml` published only the npm package. The GitHub Action
  (`action.yml` → `main: dist/action/index.js`) was unpublishable: `dist/` is
  gitignored, so no tag's tree contains the file GitHub executes for a
  `uses: jwolberg/blastgate@vN` reference, and no floating `v0` tag existed.
- **Decision: build-in-release, not commit-dist-to-main.** Added a second
  `release-action` job that, on a `v*` tag, builds `dist/`, force-commits it onto
  the tagged commit, force-moves the exact version tag **and** the floating major
  tag (`v0`) to that commit, then `gh release create`s a Release. Kept the npm
  job unchanged; the two run in parallel with separate least-privilege scopes
  (npm: `id-token: write`; action: `contents: write`).
- **Tradeoff (accepted, revisit).** This makes the semver tag *mutable* — the
  workflow rewrites `v0.1.0` to a commit with an extra `build:` commit the local
  tag didn't have. The GitHub-recommended alternative is to **commit `dist/` to
  `main`** (un-ignore it + a `check-dist` CI guard that fails on a stale build);
  that keeps version tags immutable and drops the tag-force-move. Chose
  build-in-release because the ask was to change `release.yml` only and it keeps
  `main` free of build artifacts. If mutable tags bite, switch to committed-dist.
- **Loop-safe.** Tag pushes use the built-in `GITHUB_TOKEN`, which does not
  re-trigger workflows, so force-moving `v*` tags cannot recurse. Prerelease tags
  (`-rc.N`) do not advance `v0` and are marked `--prerelease`.
- **No new third-party actions.** Used the runner's built-in `gh` CLI for the
  Release instead of a marketplace action — fewer supply-chain deps in a
  `contents: write` job, consistent with the tool's own posture. `checkout` /
  `setup-node` stay SHA-pinned as before.
- **Verified.** YAML parses (`yaml.safe_load`, jobs `publish-npm` +
  `release-action`, trigger `push.tags [v*]`); tag/major/prerelease shell math
  checked against `v0.1.0` → `v0 --latest`, `v1.4.2` → `v1 --latest`,
  `v0.2.0-rc.1` → `v0 --prerelease`. Not exercised on a real tag push (would
  publish); recommend a dry run on a throwaway `v0.0.0-test` tag first.
- **Companion self-gate + `scan` script (same PR).** Added
  `.github/workflows/blastgate.yml` — a `pull_request` job that `npm ci && npm run
  build`s then runs `node dist/cli/index.js . --base <pr-base> --format md` into the
  job summary, failing the check on a reachable path. It uses the built CLI, not
  the (unpublished) Action, so the repo dogfoods **before** the first release;
  swap to `uses: jwolberg/blastgate@v0` post-publish for inline annotations. Also
  added `npm run scan` (`build` + whole-repo CLI) for the local loop. `checkout` /
  `setup-node` SHA-pinned to match release.yml.

## 2026-08-05 — Push-button first release: safe dry run + runbook (0029)

- **Why.** `release-action` had never run on a real tag, and the first tag would
  otherwise be a live experiment that also publishes to npm. Made the first
  release turnkey and de-risked.
- **Safe dry-run lane via a `-test` tag suffix.** Added an `if:
  ${{ !endsWith(github.ref_name, '-test') }}` guard to `publish-npm`, so a
  `v0.0.0-test` tag exercises `release-action` **only** — npm is never touched
  (npm publishes package.json's version, not the tag, so an unguarded throwaway
  tag would publish the real version). `-test` is also a prerelease, so `v0` is
  not advanced. `scripts/release-dry-run.sh` (`npm run release:dry`) pushes the
  tag, watches the run, asserts (Release created · `dist/action/index.js` in the
  tag tree · `v0` untouched · `publish-npm` skipped), then deletes the tag +
  release via an EXIT trap.
- **Runbook.** `docs/runbooks/release.md` documents prereqs (the `NPM_TOKEN`
  secret — the one missing gate; npm name is free), the dry run, the real
  `npm version` + `git push --follow-tags`, the one-time Marketplace publish, and
  post-release verification + rollback.
- **Verified.** `bash -n` clean on the script; `release.yml` + `package.json`
  still parse; guard expression checked (`v0.0.0-test`/`v0.1.0-rc.1` → skip only
  on `-test`). The dry run itself is **not** executed here — it pushes tags to the
  live repo, which is the human's call.

## 2026-08-05 — Queue: required-check enforcement + multi-repo rollout (0030)

- **Why.** The self-gate reports but doesn't block, and adopting Blastgate in
  other repos was undocumented. Prepared both as runnable tooling (not applied —
  they change live GitHub settings / other repos, and the rollout needs the Action
  published first).
- **Required check.** `scripts/require-checks.sh` sets `main` branch protection to
  require `quality` + `self-scan` (JSON body via `gh api --input`, `enforce_admins
  false`, `REVIEWS` env for solo maintainers), matching the branch-protection
  runbook — which was updated to list `self-scan` alongside `quality`.
- **Rollout.** `.github/workflows/blastgate-reusable.yml` (a `workflow_call` recipe
  wrapping `uses: jwolberg/blastgate@v0`) lets other repos adopt with a one-line
  caller; `scripts/rollout-blastgate.sh` opens that PR across repos (idempotent,
  never merges). `docs/runbooks/rollout.md` covers the personal-account path, the
  org-ruleset path (one ruleset, zero per-repo files), required-check, and the
  global plugin layer.
- **Blocked on release.** The reusable workflow and rollout reference
  `jwolberg/blastgate@v0`, so they only work after the first published release.
- **Verified.** `bash -n` clean on both scripts; both workflow YAMLs parse.
  Neither script is executed here (live GitHub side effects).

## 2026-08-05 — Ecosystem/CI/policy expansion (0029-0038): decisions

- **0033 — Python dependency-diff lockfile target: `requirements.txt` (v1).** Python has
  no single universal lockfile; `requirements.txt` is the most widely present and the
  simplest to diff (`pkg==version`), so it is the v1 target for the "newly added Python
  dependency" signal (poetry.lock / uv.lock / Pipfile.lock are format-specific follow-ups).
  An added/bumped pip package is treated as **install-capable** (a pip sdist runs
  `setup.py` at install), so it reaches a secret held by a fork-triggerable `pip install`
  job — the same model as npm's `hasInstallScript` and RubyGems (0032). Precision is
  diff-gated: an existing requirements.txt is trusted; only added/bumped packages become
  findings. Lives in the existing `pydeps` analyzer alongside the setup.py handling.
- **0032 — RubyGems install-capability is assumed, not detected.** Bundler's Gemfile.lock
  does not record whether a gem runs install-time code (native extension / Rakefile), and
  we cannot inspect gem internals offline, so an added gem is treated as install-capable.
  Same reasoning as the Python requirements case. Precision comes from cross-layer
  reachability (fork-triggerable `bundle install` job holding a secret), not per-gem
  script detection.
- **0031 — `provider` field on CiJobNode** (absent = github) mirrors `DependencyNode.ecosystem`.
- **0030 — policy.json** generalizes acknowledged.json; the three integrity invariants
  (committed & diffable / specific / self-approval-guarded) are enforced in code + tests.

## 2026-08-05 — CI fork-PR token model: plain `pull_request` is not credential-reachable

- **Finding (empirical).** Ran Blastgate against a random 15 of the top-100 most-starred
  GitHub repos. It *did* fire on real repos — correctly surfacing the
  `pull_request_target`-holds-a-secret pwn-request shape (ohmyzsh's App private key,
  nodejs/node ×14, TypeScript's `manage-prs`) — but ~55% of FAIL findings were **false
  positives**: plain `pull_request` jobs flagged as reaching a writable `GITHUB_TOKEN` /
  secret. Smoking gun: TypeScript's `coverage` job, which references **no secret** and
  only declares `id-token: write`, was reported as a fork→credential exfiltration path.
- **Root cause.** `ci/index.ts` set `forkTriggerable = untrustedTriggers().length > 0`,
  and `UNTRUSTED_EVENTS` included `pull_request`. GitHub runs fork PRs on `pull_request`
  with a **read-only** `GITHUB_TOKEN` and **withholds repo secrets**, so a write
  permission / `secrets.X` in a `pull_request`-only job is a declared permission a fork
  can never obtain — not a reachable path. This let a *pattern match on the permissions
  block* masquerade as reachability — exactly what the precision-over-recall rule (R14)
  forbids, and the core claim of the tool.
- **Fix.** New `credentialReachableTriggers()` — the privileged base-context events
  (`pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review[_comment]`)
  — now gates `forkTriggerable`. Plain `pull_request` no longer mints a fork-pr entry or a
  credential path.
- **Deviation — the bug was encoded in the tests/fixtures too.** The canonical AE1
  example, the four supply-chain positive fixtures (install-script / python-install /
  pypi-dep / rubygems), the provenance-regression fixture, and ~10 inline test scaffolds
  all used plain `pull_request` to mean "attacker-triggerable secret job." All corrected
  to `pull_request_target` (the realistic secret-reaching event). TDD: a RED regression
  test (`does not treat a plain fork pull_request job as credential-reachable`) drove the
  change; full suite green (278).
- **Simplification (accepted).** `pull_request_target` is still treated as running the
  fork's code even though GitHub checks out the *base* ref by default (the real danger
  needs an explicit PR-head checkout). Conservative on purpose; inspecting the checkout
  ref is a follow-up refinement.
- **Follow-ups.** (1) `untrusted-text-injection` on a plain `pull_request` (read-only
  token) is still reported reaching a credential sink — same class of over-claim, smaller
  blast radius; gate it the same way. (2) The README's headline Shai-Hulud example implies
  a fork `pull_request` install job reaches AWS creds — reword to `pull_request_target`
  (or note GitHub's default protection) so the flagship example is technically accurate.

## 2026-08-05 — CI exploitability gate + injection sinks (0041 / 0042)

- **Finding (empirical).** The top-25 threat assessment showed the fork-token fix left a
  *second, larger* false-positive class: 14 of 16 flagged items were the safe standard
  pattern — a `pull_request_target` / `workflow_run` label/triage bot that holds a writable
  token but **never runs untrusted code** (`actions/github-script` / `labeler` on event
  metadata, no PR-head checkout). The tool flagged "privileged event + token" without
  checking exploitability. Real false-positive rate ≈94%, not 0%.
- **0041 — execution gate.** `forkTriggerable` now requires `checksOutUntrustedRef(job)`
  (an `actions/checkout` with a PR/`workflow_run` head `ref:`, or `gh pr checkout` / a manual
  PR-ref fetch) in addition to a secret-bearing event. A privileged job with no untrusted
  checkout is no longer a finding. Because `build.ts` keys the cross-layer `runs-in` edge off
  `forkTriggerable`, the install-script path inherits the same gate (a fork's dependency is
  only "reachable" when the job checks out and installs the fork's code).
- **0042 — injection sinks.** Added `workflowRunArtifactInjection`: a `workflow_run` job that
  downloads an artifact (built by the untrusted `pull_request` run) and splices its contents
  into a shell via command substitution (`$(<file)` / `$(cat file)`) → an
  `untrusted-text-injection` finding with an artifact-specific reason. Passing the artifact as
  a quoted argument to a trusted committed script is NOT flagged. This catches the one genuine
  finding (`EbookFoundation/free-programming-books` `comment-pr.yml`) **on purpose** — before,
  the tool flagged it only by coincidence (as a generic `workflow_run` + token job).
- **Validation.** Re-scan of the 5 previously-flagged repos: freeCodeCamp / yt-dlp → PASS
  (11 FPs gone); hermes-agent → the workflow_run FP gone (only a separate ci-divergent WARN
  remains, correctly — it checks out `main`, not the PR, and passes the artifact to a trusted
  script); langflow → the 2 label FPs gone, leaving the genuine event-text injection; free-
  programming-books → FAIL via the new artifact-injection reason.
- **Deviation — fixtures/scaffolds encoded the pre-gate assumption.** AE1, the six supply-
  chain / fork-pr positive fixtures, and ~11 inline test scaffolds modeled a "dangerous fork
  job" with no PR-head checkout (which under the corrected model is safe). All were given an
  untrusted checkout (`gh pr checkout` / `ref: …head.sha`) so they represent the genuinely
  exploitable case. New `ci-artifact-injection` fixture pair + two unit tests added; full suite
  green (283).
- **Scope / simplification.** `checksOutUntrustedRef` recognizes the common untrusted-ref
  patterns; an unrecognized checkout keeps the current assume-reachable behavior (fail-closed),
  so this only removes clear FPs. `workflowRunArtifactInjection` v1 keys on the
  command-substitution file-read sink (`$(<`/`$(cat`); other artifact-exec shapes and a sharper
  event-text→`run:` taint model are future work. The artifact-injection finding reuses the
  `untrusted-text-injection` entry kind (ASI01/MCP10) to avoid taxonomy surgery.

## 2026-10-01 — Agent-in-CI U1 (0055): vendor re-verification changed two defaults

- **Deviation — codex-action `allow-users: '*'` opens the gate (KTD3 revised, user-approved).**
  The plan said codex's bypass inputs take explicit names only. The action's source
  (`src/checkActorPermissions.ts`, every tag v1.0–v1.12) admits all users when
  `allow-users` is `'*'`; only `allow-bot-users` rejects `'*'`. The codex profile now lists
  `allow-users` as an outsider input, so a wildcard can make the direct leg hold. Named users
  stay indirect warns.
- **Deviation — the gemini `--yolo` allowlist bypass keys on `gemini_cli_version`, not the
  action version (KTD4 revised, user-approved).** GHSA-wpqr-6v78-jr5g fixes it in Gemini CLI
  0.39.1 / 0.40.0-preview.3. run-gemini-cli 0.1.21 and 0.1.22 both default
  `gemini_cli_version: latest` and differ in nothing security-relevant (diffed action.yml).
  `geminiYoloIgnoresAllowlist` flags only a literal pin below the fix; unset/`latest`/
  `preview`/`nightly` are patched; an expression or branch is `unknown`.
- **Decision — ranges are major lines; branch and SHA refs are unknown.** claude v1, codex v1,
  run-gemini-cli 0.x, ai-inference v1–v3. A partial tag (`v1`) is covered only when its whole
  line lies in range. `@main`/`@beta` and every SHA pin resolve to `unknown` (warn, never fail)
  since no SHAs are recorded yet. Tradeoff: SHA-pinned agents — the hardened ones — cannot
  fail until we record release SHAs. Follow-up candidate: resolve SHAs from a recorded table.
- **Decision — `actions/ai-inference` stays tool-less even though it has tool inputs.** Its
  `enable-github-mcp` (GitHub MCP tools, needs a PAT) and `provider: copilot` (Copilot CLI) are
  off by default. They are recorded as `toolInputs` but the step still only warns (R8), which
  errs toward warn. Follow-up candidate: model them as tool grants.

## 2026-10-01 — Agent-in-CI U2 (0056): agent and tool-less LLM recognition

- **Deviation — home-assistant changed shape; U2 follows a one-step relay.** At HEAD,
  `detect-non-english-issues.yml` no longer calls GitHub Models from github-script. A
  github-script step reads the title/body from `env:` and `core.setOutput`s them, and
  `actions/ai-inference` reads `${{ steps.detect_language.outputs.issue_text }}`. A step's
  outputs now count as tainted when untrusted text reaches that step (any key, including
  `env:`), and a tool-less LLM step reading a tainted output or `${{ env.X }}` ingests. This
  taint is consulted only for LLM steps, so the 0046 rule (env-passed text never reaches a
  shell) is unchanged. Verified: the real workflow went from PASS to an agent-ingested WARN at
  the ai-inference step (line 65).
- **Decision — "calls GitHub Models" means the script names `models.github.ai` or
  `models.inference.ai.azure.com`.** A github-script step that calls a model through some
  other client or endpoint is not recognized (false negative, warn-only class).
- **Decision — the legacy name regex stays for unprofiled agents** (aider, opencode,
  sweep-ai, gpt-engineer, claude-code-base-action). They are still agent-ingested; profiled
  actions resolve through `agentProfileFor` first.

## 2026-10-01 — Agent-in-CI U4 (0058): repository visibility input

- **Decision — visibility is plumbed but not yet read.** `EngineInputs.visibility`
  (`public | private | unknown`) is always set by `collectInputs` (default `unknown`); U3/U5
  consume it. Tests assert the plumbing through `actionCollectOptions` / `scanCollectOptions`
  since no output changes until U5.
- **Decision — the Action reads only `repository.private` from `GITHUB_EVENT_PATH`.**
  `true` → private, `false` → public, missing/unreadable/non-boolean → unknown. Internal
  repos report `private: true`, so their logs are not counted as public. The MCP surface
  passes no visibility (unknown).

## 2026-10-01 — Agent-in-CI U3 (0057): Rule-of-Two assessment

- **Decision — only explicitly granted tools count.** For claude-code-action, tools come
  from `claude_args --allowedTools` / `settings.permissions.allow` only; the action's own
  default tool set is treated as no shell and no file read. An unrestricted `Bash` (or
  `Bash(*)`, or a permission-bypass flag) grants shell + file read + network; a scoped
  `Bash(cmd:*)` grants nothing; `Read` grants file read; `WebFetch` grants network.
  Tradeoff: a default-tools agent can never fail, so we may miss some real fails. In
  exchange, no fail rests on a default we did not read.
- **Decision — codex always has a shell** (`codex exec` runs commands in its sandbox) and
  has network only under `sandbox: danger-full-access`. Per the plan's R5, a shell tool alone
  satisfies the exfil leg.
- **Deviation — codex's own OpenAI key is not counted as readable.** The action serves
  `openai-api-key` through a proxy and drops sudo by default, and its security doc says this
  keeps the key secret. Counting it would have made every `allow-users: '*'` codex job a
  false fail. Only `safety-strategy: unsafe` exposes it. Other job secrets still count.
  (Found in self-review before commit; test added.)
- **Decision — gemini tools follow `settings` `tools.core` (or legacy `coreTools`).** No
  list means `--yolo` with every tool. A scoped `run_shell_command(cmd)` is not a shell unless
  the pinned Gemini CLI ignores allowlists (U1's `geminiYoloIgnoresAllowlist`).
- **Decision — on-disk credentials** are the `actions/checkout`-persisted token (only when it
  is `contents: write`), a `google-github-actions/auth` credentials file, and gemini's own
  `gcp_workload_identity_provider` credentials file. These stay readable under claude's
  env scrub (KTD2).
- **Decision — the public-surface exfil leg reads `issues` / `pull-requests` / `discussions:
  write` (or `write-all`)** from the token permissions. Inherited/unknown permissions do not
  count.

## 2026-10-01 — Agent-in-CI U5 (0059): agent verdict, evidence, and reasons

- **Decision — an agent fail is per sink.** Besides the three held legs and a covered
  version, the path's sink must be a credential the agent's tools can read
  (`AgentAssessment.readable`: secret names, every secret, or the GITHUB_TOKEN). Without
  this, claude's scrubbed `ANTHROPIC_API_KEY` would fail alongside the readable
  `.git/config` token. Now the key path warns and the token path fails. `tierFor` is
  unchanged (KTD6): the agent payload is simply withheld unless the path is proven.
- **Decision — the payload is a fixed comment** asking the agent to print `env | base64` or
  curl it to `attacker.example`. The 0049 surface tests now run over both the shell-injection
  fixture and an AE1 agent fail, so markdown, default JSON, the Action, MCP, and run records
  are all checked for the agent payload too.
- **Decision — `AgentAssessment`, `Leg`, and `RepoVisibility` moved to `src/graph/types.ts`**
  so the entry node can carry the assessment without the graph depending on an analyzer.
  `agents.ts` and `engine/build.ts` re-export them.
- **Decision — warn reasons list all three legs with their whys, then one cause:** a missing
  leg first, then an uncovered version, then a privileged-capability sink (e.g.
  `issues:write`), then a credential the tools cannot read. A sweep test checks that every
  agent fail across 36 claude variants names all three legs held and carries a payload.

## 2026-10-01 — Agent-in-CI U6 (0060): incident fixture pairs

- **Decision — the PromptPwnd fixture is a gemini issue-triage job**, matching Aikido's
  flagship example. It has the issue body interpolated into `prompt:`, a `gh`-only
  `run_shell_command` allowlist, and `gemini_cli_version: '0.38.0'`. That CLI ignores the
  allowlist under `--yolo` (GHSA-wpqr-6v78-jr5g), so it fails on `GEMINI_API_KEY`. The
  hardened engine test pins `latest` and warns.
- **Verified the fixtures are meaningful:** the three positives fail against the pre-U5 commit
  (6cb258b, all agents warn) and pass at U5. The negatives are the same workflows on `push`
  (KTD8) and produce zero findings.
- Hardened variants as engine tests: claude gate intact (AE2), tools restricted (AE3), and
  scrub default (U5); gemini with an `author_association` guard and PromptPwnd with a patched
  CLI (U6).

## 2026-10-01 — Agent-in-CI U7 (0061) re-scan findings fed back into U2 (0056)

- **Deviation — U2 also taints outputs of github-script steps that read text in-script.**
  The re-scan found home-assistant `detect-duplicate-issues.yml` had no finding. Its
  `extract` step reads the issue through `context.payload` / `github.rest.issues.get`
  and `setOutput`s the title and body, which `actions/ai-inference` then reads. A
  github-script step whose script names `context.payload` or `github.rest.issues|pulls` and
  reads `.body`/`.title` now taints its outputs. This affects only LLM-step classification
  (warn-only).
- **Eval hygiene — six clones were silently empty.** Network timeouts left sparse checkouts
  with no `.github/`, and they scanned as clean 0/0 (free-programming-books dropped from
  1 warn to 0 at the same SHA). They were re-cloned. `eval-scan.sh` gained `SCAN_FLAGS` (used
  with `--public`). Follow-up candidate: have the script fail a repo whose checkout lacks the
  sparse paths instead of scanning it.

## 2026-10-01 — 0062: gh-aw runtime steps are not PR-code execution (user-directed fix)

- **Why it's in this branch:** the 0061 re-scan produced 2 fails on home-assistant's
  `quality-scale-reviewer.lock.yml` that hand review refuted. Every `run:` after the PR-head
  checkout runs gh-aw's own runtime (`${RUNNER_TEMP}/gh-aw/actions/*.sh`, the MCP gateway,
  the Copilot launch). None runs PR code. Per the plan's stop condition I asked; you chose to
  fix 0048 here rather than ticket it.
- **Deviation from the option as worded:** exempting only `${RUNNER_TEMP}`-script steps would
  not clear it, because gh-aw also emits long inline runtime steps. The rule instead: in a job
  that uses `github/gh-aw-actions/setup`, a `run:` step referencing gh-aw runtime paths
  (`${RUNNER_TEMP}/gh-aw/`, `/tmp/gh-aw/`) is not execution evidence. A custom step in the
  same job (`npm ci`) and gh-aw-path steps without gh-aw setup still count (tests).
- **Result:** both home-assistant fails become warns. Follow-up candidates: the fork-PR warn
  reason still says "exfiltratable from an untrusted run" when there is no execution
  evidence (pre-existing wording), and gh-aw's Copilot engine is not yet a profiled agent.

## 2026-10-01 — Agent-in-CI U7 (0061): re-scan and documentation

- Final re-scan (`SCAN_FLAGS=--public`, all 50 clones verified populated): **0 fails, 20 warns**.
  The 2 agent findings are both home-assistant tool-less LLM warns. The 2 first-pass fails
  were gh-aw false fails, fixed in 0062. Results:
  `docs/evaluations/2026-10-01-agent-model-rescan.md`.
- Threat model §3.4 gains the agent verdict table (three legs with what breaks each), and
  the README states the Rule-of-Two fail rule and the `--public` flag.
- Known gaps recorded there: `workflow_run` relays into an agent (pytorch ×3) are the
  deferred multi-hop scope. Agent-fail precision is untestable on this sample (no proven
  agent exploit in it); the U6 fixtures are the positive evidence.

## 2026-10-01 — PR #39 review fixes (0057, 0059, 0060, 0062)

- **Fixed (high) — access counted secrets the agent cannot read.** Secrets now come only from
  the agent step's own environment (workflow `env:`, job `env:`, the step's `env:`/`with:`).
  A secret in another step's `env:` no longer makes the agent path fail. On-disk credentials
  are typed by the sink they prove. A checkout-persisted `contents: write` token proves the
  GITHUB_TOKEN sink. A key file `google-github-actions/auth` wrote from `credentials_json`
  proves that secret. A workload-identity file needs the job's OIDC request token, so it
  counts only when the environment is not scrubbed and the job has `id-token: write`.
- **Fixed — direct leg ignored step-level and `needs:` guards.** An actor or label guard on
  the agent step, or on any job it `needs` (transitively), now breaks the direct leg.
- **Fixed — gemini `tools.exclude` / `excludeTools` were ignored.** A workspace-trusted run
  (`GEMINI_TRUST_WORKSPACE: true`, or a CLI pinned below 0.39.1 that trusts it automatically)
  may load the repo's `.gemini/settings.json`, which Blastgate does not read, so its tools are
  unknown (R9). Consequence: the PromptPwnd fixture moved from "old CLI ignores a gh-only
  allowlist" to "patched CLI granted `run_shell_command`", and the old-CLI variant now warns.
- **Kept — `allowed_bots: '*'` opens the direct leg.** claude-code-action's security doc says
  that on a public repo, GitHub Apps "created by anyone" can trigger it with a prompt they
  control. The reason now says so and cites it.
- **Fixed — 0062 exempted user steps that only mentioned a gh-aw path.** Comments are
  stripped, and a step that also invokes workspace code (a relative path, make, npm/pnpm/bun
  run|test|install, npx, yarn, pip, python script, bash script, …) is never exempt. Checked
  against the real home-assistant lock file: `npm root -g` (a read-only query) does not count.
- **Fixed (suggestion) — the first agent step masked later ones.** Every agent-ingested step
  in a job is assessed, and the one closest to a fail (most legs held, then a covered version)
  becomes the entry, with its evidence line.
- Re-scan after the fixes: 50 repos, 0 fails, 20 warns (unchanged).
- **Open question for you:** PromptPwnd's leak used a *scoped* shell command
  (`gh issue edit --body "$GEMINI_API_KEY"`): shell expansion reads env even when only
  `gh issue edit` is allowed. The plan (AE3, user-approved) treats a scoped shell as no shell.
  That is precise against intent but misses this vector.

## 2026-10-01 — PR #39 re-review fixes (0059, 0062)

- **Fixed — 0062 used a denylist of workspace commands.** `node build.js`, `docker build .`,
  `$GITHUB_WORKSPACE/x.sh`, `eval`, `bash -c`, … slipped through. `isGhAwRuntimeStep` is now an
  allowlist. A gh-aw job's step is runtime only if every simple command, after stripping comments
  and heredoc bodies, masking quotes, and following `$(…)`, is a gh-aw runtime script, a
  `$GH_AW_*` invocation, or inert plumbing. Any unrecognized command counts as running PR code.
  `find -exec`, `git … core.hooksPath`, and `awk/sed/jq -f` are rejected. Calibrated on the real
  home-assistant lock file: every runtime step is still exempt, so 0 fails.
- **Fixed — `allowed_bots: '*'` failed regardless of visibility.** The doc scopes the any-App
  risk to public repos, so the direct leg is now held when public, unknown when unknown, and
  missing when private. The CLI default is unknown, so without `--public` a bots-only agent
  warns.
- **Taken (suggestion) — a guarded `needs:` job is not a gate when the dependent job runs
  `always()`, `!cancelled()`, or `failure()`.**
- Plan R4 and the flowchart now scope access to the agent step (the PR #38 low, applied here so
  #38's approved head does not move).

## 2026-10-01 — PR #39 round-3 review fix (0062): the gh-aw allowlist fails closed

- **Fixed — the tokenizer could be fooled.** Quoted command words, `$((…))`/`<<<`/comments read
  as heredocs, backticks, process substitution, `command ./x`, `trap ./x`, `awk system()`,
  `sed e`, and runtime scripts handed a workspace path or a non-agent command after `--` were
  all classified as gh-aw runtime. Now:
  - shell syntax the tokenizer does not model (backticks, `<(`/`>(`, `$((`, `<<<` outside single
    quotes) makes the step not-runtime;
  - heredocs are found after comment stripping;
  - a quoted command word must be a gh-aw path or `$GH_AW_*` variable;
  - `command` only with `-v`; `trap` only with a single-quoted body, which is itself checked;
  - `awk`/`sed` are not allowlisted;
  - gh-aw scripts and `$GH_AW_*` commands may not take a workspace path before `--`, and only
    an agent launch (`awf`, `copilot`, `claude`, `codex`, `gemini`) after it.
- **Judgment — `awf` is the agent boundary.** gh-aw's firewall launched with its own generated
  config (`--config` under a gh-aw path) runs the agent. What it runs is the agent class, judged
  by the Rule-of-Two verdict, not direct PR-code execution. A bare `awf -- node build.js` is
  rejected.
- Calibrated on the real home-assistant lock file: every runtime step is still exempt.
  Re-scan: 50 repos, 0 fails, 20 warns.

## 2026-10-01 — Two user decisions after the PR #39 round-4 review

- **0062 dropped (user decision).** Round 4 found five more tokenizer bypasses, and gh-aw's
  real agent launch embeds a ~1KB `bash -c` script that would also need parsing. Shell parsing
  would not converge, so the exemption, its allowlist, and its tests are removed, and
  `untrustedExecutionStep` is back to its `main` behavior. home-assistant's gh-aw workflow keeps
  2 hand-refuted false fails, documented as the R12 exception in the re-scan doc. Ticket 0062 is
  iceboxed with the history and a pointer to a structural approach (gh-aw step names).
- **A scoped shell now reads environment secrets (user decision; revises AE3).** PromptPwnd
  leaked `GEMINI_API_KEY` through a command-scoped shell (`gh issue edit --body "$KEY"`). The
  shell expands `$SECRET` into the allowed command's arguments. `Bash(cmd:*)` and
  `run_shell_command(cmd)` now count for reading env, but not as a general shell, so they do not
  count for on-disk reads or exfiltration. AE3 flips from warn to fail when the key is in env
  and an exfil leg holds; under claude's scrub it still warns. Unverified: whether Claude
  Code's permission matcher refuses `$VAR` expansion inside a scoped `Bash` rule. If it does,
  claude's scoped grants should go back to not reading env.
- Re-scan: 50 repos, 2 fails (the known gh-aw exception), 18 warns. The agent model produces no
  fails on this sample.

## 2026-10-01 — 0063: claude scoped Bash rules do admit `$VAR` expansion (documented)

- Claude Code's permissions doc (https://code.claude.com/docs/en/permissions): "A Bash rule
  matches the command text Claude writes", "A `*` in a Bash rule matches any text", and
  "Bash permission patterns that try to constrain command arguments are fragile" (its example
  includes `curl $URL`). So `Bash(gh issue view:*)` admits `gh issue view 1 "$ANTHROPIC_API_KEY"`,
  and the shell expands it. The revised AE3 stands for claude. A rule with no `*` "matches one
  exact command", which admits no injected argument (ticket 0064).
- Verified from documentation, not by running Claude Code.
- **Open finding (not acted on):** the same doc says Claude Code runs a built-in set of
  read-only commands (`cat`, `echo`, `grep`, …) "without a permission prompt in every mode". If
  that holds inside claude-code-action, a claude step with no `--allowedTools` can still read
  `.git/config` or echo env, so "default tools = none" understates access (missed fails, never
  false ones). Raised with the user.

## 2026-10-01 — 0065: SHA-pinned agents resolve through recorded release tags

- `scripts/refresh-agent-shas.sh` (read-only GitHub API) writes
  `src/analyzers/ci/agent-release-shas.ts`, mapping every release tag's commit SHA to the tag,
  for the four profiled actions (360 SHAs on 2026-10-01). A commit with several tags keeps the
  most specific one (`v1.0.238` over the moving `v1`).
- `agentProfileFor` resolves a SHA pin to its tag, then applies the profile's version range. A
  SHA of an out-of-range release (claude `v0.0.17`) stays unknown and names the release. A SHA
  that is no release (a fork, an unreleased commit) stays unknown. The per-profile `pinnedShas`
  field is gone.
- Maintenance: re-run the script when an action releases. Until then, a brand-new release's SHA
  is unknown, so it warns and never fails. Effect on the sample: home-assistant's SHA-pinned
  `actions/ai-inference` is now covered, but tool-less steps still only warn (R8).

## 2026-10-01 — 0067: agent steps reached through a workflow_run relay

- `relayedTextEvents` (injection.ts) maps each workflow to the attacker-text events reaching it
  through `workflow_run`, matching upstreams by `name:` (or file path when unnamed),
  transitively and cycle-safe.
- A `workflow_run` job with relayed text becomes an injection entry **only when its sink is an
  agent**. A relay hands over an issue/PR number, not text, so only an agent that fetches the
  issue ingests it; other sinks still need the job's own text events. The direct leg treats the
  relayed events as the trigger, and the action's own gate still applies (claude checks the
  upstream actor's write access).
- pytorch effect (previously silent, 2026-10-01 re-scan §4): `claude-distributed-triage` warns
  (direct held via `allowed_bots: '*'` on a public repo, access missing),
  `claude-issue-triage-run` warns (named `allowed_bots`), and `hardened-pr-review-run` warns
  (tool grants unreadable). No new fails.

## 2026-10-01 — 0072: crawl ledger (public-crawler U2)

- Disclosures are keyed by repo + sorted finding ids (no separate id). The duplicate guard
  refuses any new disclosure overlapping ids of a live one on the same repo, including
  `submitting` and recovered `held` entries, since those may already have been filed.
- Delta priority: listed passes whose engine **or SHA** changed come first (reasons
  `listed-pass-old-engine` / `listed-pass-changed`), then new repos, then the rest oldest-scanned
  first. The plan only named the engine case; the SHA case was added at integration so a listed
  repo that may now fail is re-vouched before anything else (AE6). Engine versions compare by
  string equality, not semver.
- Follow-up: a listed repo that stops being discovered (workflow removed, repo made private)
  never reaches the delta, so it stays listed. The site build (U7) or orchestrator (U8) should
  drop passes for repos absent from the current discovery set.

## 2026-10-01 — 0071: discovery via sharded code search (public-crawler U1)

- Deviation: crawl fixtures live in `src/crawl/fixtures/`, not the plan's `test/fixtures/crawl/`.
  `test/engine.e2e.test.ts` asserts every `test/fixtures/` directory is a declared check, so later
  crawl units put fixtures there too.
- Throttle is 9 searches per sliding 60s (strictest reading of "<10"); only `/search/` paths are
  throttled. A 403/429 carrying `retry-after` or an exhausted `x-ratelimit-remaining` is waited out
  and retried up to 5 times, then `GitHubRateLimitError` is thrown — the orchestrator treats that
  as the plan's "stop on abuse/secondary limit" signal. A 403 with no rate-limit signal is
  returned as-is.
- Sharding bisects `size:0..1000000` to depth 24; a single-byte bucket is split by 20 common
  workflow filenames. That list cannot partition a bucket, so a filename-split bucket is always
  reported `truncated` (fixed at integration: the worker's version lost unlisted filenames
  silently). Every saturated shard still collects its first 1,000 reachable hits.
- A non-200 search response (after retries) throws rather than skipping a shard; repo metadata
  404/410/451 drops the repo.

## 2026-10-01 — 0073: scan and ingest (public-crawler U3)

- `eval-scan.sh` now emits full 40-char SHAs and no longer aborts the whole run when one repo's
  JSON is unparseable (its row gets `-` counts; the crawler records `unknown`). Older evaluation
  docs keep their short SHAs.
- Verdict precedence: any fail-tier finding is `fail` regardless of exit code; otherwise a parse
  failure or any non-zero exit is `unknown`. Archetype = `${entry.kind}->${sink.kind}`, built
  only from finding structure.
- A `clone-failed` row has no SHA; it is recorded with a zero SHA so the delta retries it next run.
- `reverify` returns `resolved` when the reported ids no longer fail, even if new ids fail; those
  get their own disclosure from the next regular scan.
- Engine identity: the CLI reports `0.1.0`, which does not change when rules change, so a version
  string alone would never re-vouch listed passes after an engine fix (e.g. 0070). U8's
  orchestrator passes `engineVersion` as `<cli version>+<blastgate commit SHA>`.

## 2026-10-01 — 0074: disclosure gate and report composer (public-crawler U4)

- Escaping: one `inert()` pass over a payload-free copy of each finding before the shared
  per-finding markdown block (`markdownFinding`, now exported from `src/cli/render.ts` with
  output unchanged). It strips control/bidi/zero-width characters, caps length, and swaps the
  characters that make links, images, HTML, code spans, mentions, issue refs, autolinks, and
  table cells (`` ` < > [ ] @ #N :// www. | ``) for look-alikes. Side effect: action refs read
  `run-gemini-cli＠v0.1.21` in reports.
- The threat-model link is a bare URL, not `[text](url)`, so the inertness check can forbid `](`
  outright.
- Gate order: allowlist, then duplicate (same rule as `createDisclosure`). Config is strict
  JSON (`allowlist`, `submitMode`, `publishSite`, `throttle`), unknown keys rejected.
- `src/crawl/fixtures/disclose/real-fails.json` holds real engine fail findings, payloads
  included (fixed illustrative strings, never repo-derived), so the no-payload test is real.

## 2026-10-01 — 0077: static site (public-crawler U7)

- `renderSite(ledger, {generatedAt, discovered?})` returns a files map (`index.html` only; badges
  were deferred by the doc review). Passes sort by repo; the only time shown is the day passed
  in as `generatedAt`.
- `discovered` drops listed passes for repos no longer found (closes the U2 follow-up about
  undiscoverable repos staying listed). Credited advisories always render.
- Tests assert fail/warn/unknown repo names and any scanned counts appear nowhere, and
  "privately" appears only in the method copy.

## 2026-10-01 — 0076: advisory tracker and tripwire (public-crawler U6)

- The repository-advisory API has no close reason, so a false positive cannot be told apart from
  a policy close. Tradeoff accepted: any `closed`/`withdrawn` advisory on a submitted report
  becomes `declined` **and trips its archetype** (the gate then holds it even if allowlisted).
  Cost: a maintainer closing a real finding for policy reasons slows that archetype's rollout.
  Re-admitting a tripped archetype is a manual ledger edit (no un-trip command yet).
- Credit match: case-insensitive login in `credits` or `credits_detailed` (a `declined` credit
  does not count). `draft`/`triage` advisories become `fixed` only when the current rescan shows
  none of the reported ids still failing; a repo not rescanned this run is left alone.
- 404/other errors and malformed report URLs leave state unchanged and are flagged in the run
  summary.

## 2026-10-01 — 0075: PVR submitter (public-crawler U5)

- Deviation from the plan's step order: the disclosure gate runs **before** the PVR pre-check, so
  a non-allowlisted fail costs no API call and gets the clearer reason.
- Retry policy for held entries: "no PVR", "archetype not allowlisted", and rate-limit holds are
  retried on later runs; "submission state uncertain" (crash, transport error mid-POST, 201
  without a URL) and "submission failed (HTTP n)" are never retried automatically.
- A 403/429 or `GitHubRateLimitError` stops all submission for the run. Throttle counts
  `submitting` + `submitted` by `updatedAt`; dry runs don't count.
- Dry runs store the exact request body on the disclosure (`wouldSend`); it is left in place
  after later transitions as a record of what was reviewed.
- Integration: U5 and U6 both extended the ledger in parallel (`wouldSend`, `trippedArchetypes`);
  merged by hand, both suites kept.

## 2026-10-01 — 0078: ops wiring and runbook (public-crawler U8)

- Three subcommands, not two: `scan`, `submit`, and `publish`. A separate `publish` step means
  the registry deploy key exists only there; it verifies github.com's ed25519 host key against
  GitHub's published fingerprint (checked against `gh api meta` on 2026-10-01) before loading the
  key into a temporary ssh-agent.
- The scan job uses the job's read-only `github.token` for code search and metadata (no
  `secrets.*`). Unverified: whether REST code search accepts an Actions installation token; the
  U11 dry run must confirm it, else the scan job needs a separate read-only search token.
- `currentFails` covers repos scanned pass/warn/fail (empty = clean) and excludes unknown and
  clone-failed, so the tracker only marks `fixed` on a real clean rescan.
- Engine identity is `<cli version>+<blastgate commit>` (from `BLASTGATE_SHA`), so bumping the
  pinned crawler commit re-vouches every listed pass before new repos are scanned.
- Kill switch is the file `ops/KILL_SWITCH` in the ops repo; `--cap` defaults to 100.
- TDD note: for `publish.ts` and the orchestrator the worker wrote tests first but captured the
  red failure by moving the implementation aside afterward, rather than observing red before
  writing code. The template test, pack test, and config change followed red-first normally.
- Not exercised against real GitHub: no PVR POST, SSH push, or real ops repo run. The workflow is
  checked structurally only (pins, secret placement, concurrency, permissions). `gitPersist`'s
  rebase-and-retry path is untested. The ops repo must allow `github-actions` to push to its
  default branch.

## 2026-10-01 — code-review fixes (public-crawler)

- #1 Ledger lookups (`transition`, `recordWouldSend`) prefer the latest live entry and skip
  `resolved-before-report` ones, so a re-detected finding with the same ids no longer wedges the run.
- #2 `delta` re-queues an unchanged `fail` repo with a pending disclosure (reason
  `pending-disclosure`, ranked after listed-pass re-vouching, before new repos): a `queued` entry, a
  `held` entry with a retryable reason, or fail ids no disclosure covers. Retryable-hold rules moved
  from `submit.ts` into `ledger.ts` (`isRetryableHold`) so both share them. Cost: in dry-run mode
  `queued` entries never leave `queued`, so those repos are rescanned every run (bounded by `--cap`).
- #3 `createGitHubClient` retries GETs on 5xx and thrown transport errors (3 tries, 1s/2s backoff,
  injectable sleep). POSTs are never retried: a repeated PVR POST could file a second report.
  `discover` marks a failing shard (or a later page of it) `partial` instead of throwing; a
  persistent `GitHubRateLimitError` still propagates. A metadata failure now skips that repo and is
  counted in the log (`eligibility errors N`).
- #4 Decision: both halves. Code-search items carry `repository.private/fork/archived` (GitHub docs,
  minimal-repository schema: `private`, `fork`, `archived` all required), so `discover` drops flagged
  repos with zero metadata calls. The authoritative `checkEligible` (one `/repos` call) now runs in
  `runScan` after `delta`, walking the priority order until the cap is filled, with at most 3x cap
  checks. Known limit: if more than 2x cap ineligible repos rank first, later ones wait for a later
  run (only reachable for repos the search items did not flag, e.g. deleted since indexing).
  `discovered` (site filter) is therefore no longer metadata-verified, only item-flag-filtered.
- #5 Timeouts: `fetchTransport` aborts after 30s (`createFetchTransport({timeoutMs})`); the scan
  runner bounds `eval-scan.sh` at 2h and `--version` at 30s; `execOut` (git) at 120s with
  `GIT_TERMINAL_PROMPT=0`. `eval-scan.sh` wraps each clone (`CLONE_TIMEOUT`, 120s) and scan
  (`SCAN_TIMEOUT`, 300s) in `timeout`/`gtimeout` when present (unbounded otherwise, e.g. stock
  macOS), discards a timed-out scan's output, and reports any failed or timed-out clone as
  `clone-failed`. Tests use a stand-in `timeout` binary, so GNU `timeout` itself is unexercised here.
- #6 `parseScanResult` validates the scan-job artifact: strict repo names that appear in
  `discovered`; scan rows well-formed (40-hex sha, ISO time, bounded strings, fail iff fail ids);
  candidate ids a non-empty subset of the stored fail ids with the stored archetype; summary
  <= 1024 and description <= 65535 whose text begins with the exact `reportSummaryPrefix` /
  `reportHeader` and ends with the exact `reportFooter` (version + scanned sha) from `disclose.ts`.
  Invalid entries are dropped and counted (`submit: dropped N scan(s) and M candidate(s)`).
  Tradeoff: the middle of the description (per-finding blocks) cannot be re-derived in the submit
  job, so it stays scan-job-controlled text between a verified header and footer.
- #7 Ops-template test now matches `\bsecrets\b` on the scan job and everything before `submit:`,
  has a mutation-style negative control (`secrets['X']`, `toJSON(secrets)`, `secrets.X`,
  `secrets: inherit`), and asserts both crawler checkouts use `vars.BLASTGATE_SHA` and every
  scan-job checkout sets `persist-credentials: false`.
- #9 One `isPlainRepoName` in `github.ts` (rejects `.`/`..` segments), used by `discover`,
  `ledger` (`lsRemoteHeads`), `submit`, and the submit-job validation.
- #10 Only a 429 or a `GitHubRateLimitError` (header-signalled 403) stops a submit run. A plain 403
  on the PVR pre-check holds the repo as `no PVR (HTTP 403)` (retryable); on the POST it holds
  `submission failed (HTTP 403)` (final). Also fixed a latent `held -> held` illegal move when a
  retried hold's reason changes (now goes through `queued`).
- #14 The scan child env is an allowlist (`PATH HOME LANG LC_ALL TMPDIR TERM BLASTGATE_CLI
  EVAL_REMOTE_BASE JOBS SCAN_FLAGS SCAN_TIMEOUT CLONE_TIMEOUT`) plus caller overrides, with
  credential-looking names (`GITHUB_*`, `GH_*`, `ACTIONS_*`, `RUNNER_*`, `*TOKEN*`, `*SECRET*`, ...)
  stripped from both. Applies to `scanRepos`, `reverify`, and the CLI version probe.

## 2026-10-01 — 0070: claude's default read-only commands as tools

- Verified at source and empirically rather than from docs alone: claude-code-action v1.0.239
  tag mode pre-approves `Glob, Grep, LS, Read` under `--permission-mode acceptEdits`; Claude Code
  2.1.287 (the pinned CLI) ran `cat .git/config` with no grant, denied `echo $VAR`, and denied
  `cat` outside the working directory. Model refusals in the experiment were ignored: Blastgate
  models capability, not the model's willingness.
- Change: `claudeTools` starts from `fileRead: held` (workspace-scoped in effect: every on-disk
  credential Blastgate models lives in the workspace). Env read, shell, and network still need a
  grant. ADR-0002 amended ([5]); threat-model R4 row updated.
- Re-scan: the 50-repo sample scanned with main's and this branch's engine on the same clones
  gives identical findings (2 known gh-aw false fails, 21 warns). pytorch's outsider-triggerable
  claude step has `contents: read`, so nothing on disk to reach. A first attempt silently
  produced 0/0 because the copied CLI could not resolve `node_modules`; caught by the 0-warn
  sanity check, not trusted.
- Open: `permissions.deny`/`disallowedTools` that remove `Read` and the read-only commands are not
  modelled as removing the leg (rare; would only lower recall, never cause a false fail).

## 2026-10-01 — 0083: resilient, incremental discovery

- Trigger: the first real dry run spent 90 minutes in discovery, then a 429 that outlasted the
  client's retries threw `GitHubRateLimitError` out of `discover()` and killed the scan job,
  discarding everything. claude-code-action alone is ~19,000 hits.
- Resilience: `discover()` now catches `GitHubRateLimitError` itself and ends discovery for the
  run (`rateLimited: true`); the shard stays at the head of the queue. `runScan` also catches a
  rate-limit error escaping a custom `discover` dep and falls back to the previously known repos.
  Non-rate-limit failures keep the old per-shard `partial` behaviour.
- State (`src/crawl/discovery-state.ts`, `ops/discovery.json`): `{ schemaVersion: 1, sweep:
  { startedAt, pending: Shard[], completedAt?, truncated, partial }, repos: { <repo>:
  { lastSeenSweep } } }`. `startedAt` is the sweep id. `truncated`/`partial` are kept per sweep
  so the report is cumulative across the runs of one sweep. Chose a stored work queue (not a
  cursor) because bisection is data-dependent: the queue is the only faithful resume point.
- Sweep semantics: a run with no state, or whose sweep is complete, starts a new sweep and keeps
  the known repo set. When the queue empties the sweep completes and repos with an older
  `lastSeenSweep` are dropped. Tradeoff (my call): a sweep with any `partial` shard drops nothing,
  because a failed search proves nothing about absence; the stale repos go on the next clean sweep.
  A repo a search item flags private/fork/archived is dropped immediately.
- Budget: `discoveryBudget`, default 300 search requests (~35 min at 9/min), allowed 1..5000 (the
  cap is my choice: more than a 5 h job can spend at the throttle). Counted per search request
  attempted, including the one incomplete-results retry; the client's own rate-limit retries are
  not counted. A shard interrupted by the budget (or a rate limit) mid-paging stays pending and is
  re-run from page 1 next run, so at most one shard's first pages repeat per run. Rejected:
  checkpointing page numbers (more state, little gain).
- Persistence (KTD1): scan job writes `discoveryState` into `scan-result.json`; `parseScanResult`
  validates it strictly (schema version, known actions only, size ranges within 0..1,000,000,
  filename charset, depth, ISO dates, plain repo names, caps: 500k repos, 200k shards, 5k query
  strings) and a bad state rejects the whole result before any write, unlike candidates which are
  dropped individually, because a half-trusted queue is worse than none. The field is optional so
  an older result still parses. `gitPersist` commits `discovery.json` with the ledger in one
  commit, and `runSubmit` attaches the state to every persist so progress survives a late failure.
  `scan --discovery` loads the file (missing = fresh; corrupt = hard error rather than a silent
  restart of the sweep).
- Sharding: every action still starts with one whole-range probe; only a saturated (>= 1,000
  hits) whole-range shard is split into `DEFAULT_SIZE_SEEDS` (250-byte steps to 3,000, 500 to
  6,000, 1,000 to 12,000, 2,000 to 20,000, then 20,001..1,000,000: 29 ranges) instead of halving
  0..1,000,000. Deviation from "seed every action": seeding unconditionally would cost 29 probes
  for an action with 830 hits that needs 1 probe plus 9 pages. Saturated seeds still bisect, then
  filename-split, with the same truncated/partial reporting. Honest numbers: paging (hits / 100)
  is the floor for both strategies, so on a synthetic log-normal distribution of 19,000 hits the
  total is ~222 requests vs ~243 with plain bisection (probes ~32 vs ~53), not an order of
  magnitude. The 90-minute run (~800 requests) is therefore likely dominated by real size
  clustering (many identical template files) that forces filename splits, which seeding does not
  fix; the budget plus resume is what makes that tractable. Follow-up: look at the first real
  `truncated` list before tuning the filename variants.
- Open: the whole-range query omits `size:`; relying on GitHub treating that as all sizes (as the
  old code did).


## 2026-10-01 — 0084: claude scoped Bash grants read no env secrets

- Found during the hand review of the crawler's first held fails. Verified headless on Claude Code
  2.1.287 (the version claude-code-action v1.0.239 pins): `printf '%s' "$VAR"` is denied with
  "Part of this command (a variable) cannot be checked in advance" under `Bash(printf:*)`,
  `Bash(printf *)`, and with no rule. 0063's conclusion (documentation only) was wrong for claude.
- Change: `claudeTools` no longer grants `envRead` for a wildcard-scoped Bash rule. Unrestricted
  `Bash`, the bypass flags, codex, and gemini's scoped shell are unchanged.
- Tests that encoded 0063 (agents AE3/0064-wildcard, contract AE3) now assert the verified
  behavior.
- Re-scan on identical clones, main vs branch: the 50-repo sample is unchanged (no finding's tier
  or reason moved). Of the crawler's 3 fail repos, one drops from 4 fails to 2 (its two
  ANTHROPIC_API_KEY findings were false fails; the two persisted-GITHUB_TOKEN paths remain).
- Lesson: two capability claims about Claude Code (0063 and the pre-0070 "default tools = none")
  were wrong in opposite directions until run against the pinned CLI. Verify agent capability
  claims empirically, not from docs.

## 2026-10-01 — 0085: rate-limit telemetry in the scan job

- Correction recorded: I had suggested a separate read-only search token would "roughly triple"
  the search rate. Code search is capped at 10 requests/min even for a user token (`gh api
  rate_limit` → `code_search.limit: 10`; general search is 30), and the crawler already throttles
  to 9/min. Whether such a token helps depends on what the Actions token's quota is, so this
  measures first.
- `createGitHubClient` takes `onRateLimit(info)`, called for every rate-limited response with the
  `x-ratelimit-*` / `retry-after` header values and a route class (`search`/`core`). It never sees
  the URL: a `/repos/owner/name` path is a repo name, and run logs must not pair repos with
  anything. The crawler logs one line per event; a plain 403 is not a rate limit and is not logged.
- `ops/crawl.yml` prints `gh api rate_limit` for the Actions token before discovery.
- TDD note: the client-hook and template tests went red first; the two formatter tests were
  written just after the formatter.

## 2026-10-01 — 0086 owner-scoped check run

- Request: dispatch the crawler against Jay's own repos. Added `crawl scan --owner <login>` and a
  `workflow_dispatch` `owner` input; a scoped run skips the submit job (no reports, no commits, no
  publish), so it is safe to run with any `submitMode`.
- Decision: an owner run neither reads nor emits `discovery.json` state. Mixing `user:` shards into
  the global sweep queue would corrupt it.
- Decision: logs stay counts-only even for your own repos (existing invariant). Per-repo results
  are in the 1-day `scan-result` artifact.
- The input reaches the script only through env (`OWNER`), never `${{ inputs.owner }}` inside
  `run:`, and both `runScan` and `discover` reject anything that is not a GitHub login.
- The submit `if:` checks `github.event_name` explicitly instead of relying on null == '' coercion
  for scheduled runs.
- Verified live: `"anthropics/claude-code-action" path:.github/workflows user:jwolberg` returned
  5 hits across 4 jwolberg repos. Code search covers public repos only, so private repos are never scanned.
- Caveat: the ledger delta skips repos already scanned at the same engine version.

## 2026-10-01 — 0087 search pacing and secondary-limit backoff

- Evidence: check run 36960100294 drew 429s while code_search showed 10/10 remaining (secondary
  limits). Retry-after went 16, 1, 22, 1, then 735s, so prompt retries escalated the penalty.
- Decision: replaced the 9-per-60s sliding window with even spacing (ceil(60s/9) apart). The
  average rate is the same, with no bursts.
- Decision: a secondary limit waits max(retry-after, 60s x 2^k), with k counted client-wide and
  reset on any non-rate-limited response. The one-minute floor applies even over a shorter
  retry-after, which is more conservative than the header. GitHub warns that continuing while
  limited can get an integration banned.
- Bare-429 and "secondary rate limit" message detection applies to GETs only. A POST without a
  header signal is returned untouched so submit's stop-the-run rule (KTD) still holds; a test
  covers it. Two old tests' 30s/45s expectations moved to the 60s floor on purpose.
- Tradeoff: worst case is 60+120+240+480+960s (~31 min) of waiting before a request gives up.
  That's within the 300-min scan timeout, and cheaper than losing 6h of discovery to a run that
  stops early.

## 2026-10-02 — 0088 (part 1) discovery wall-clock limit

- Evidence: scheduled run 36969994556 spent 4h21m in discovery (58 secondary 429s; the first
  search of the fresh run already drew retry-after=650), scanned nothing, and was killed by a
  runner shutdown. Discovery progress only reaches submit through scan-result.json, so it was
  all lost.
- Added `discoveryMinutes` (default 60, max 240). Past the deadline no new search starts, and
  discovery ends like a spent budget: the shard stays queued and the run scans known repos.
- Tradeoff: the check sits before each new search, not inside the client's retry sleeps. A
  request already in flight can overshoot by its retry ladder, worst case about an hour. That
  fits the 300-min job alongside the scans, and keeps the client free of a deadline concept.
- Bug caught by the suite: the deadline was computed from the scan's injected clock but checked
  against Date.now. The scan now passes its own clock to discover.
- Runbook correction: 0087 said a separate search token "would not help". The penalty carries
  across runs, so that was too strong; reworded as untested.
- Deferred to 0088 part 2: discovery as its own job (state survives a killed scan job) and an
  optional dedicated read-only search token for it.
- Ops: config.json set to `{"discoveryBudget": 10}` on 2026-10-02 (approved), and stuck run
  37007879115 cancelled.

## 2026-10-02 — dry-run evaluation doc lives in the private ops repo

- The runbook said to write the dry-run hand review to `docs/evaluations/` in this repo, which
  is public. That review names third-party repos with unfixed vulnerabilities, so it now lives
  in the private ops repo (approved by Jay). Analyzer fixes from it (0089, 0090) use synthetic
  fixtures only.

## 2026-10-02 — 0089 branch-name checkout is base-repo code

- Found by the dry-run hand review (details in the private ops repo). `actions/checkout` with
  `ref:` set to a head branch NAME (`workflow_run.head_branch`, `head_ref`,
  `pull_request.head.ref`) and no `repository:` resolves against the base repo, so it is not
  fork code. The analyzer counted it as an untrusted checkout and reported "runs PR code".
- Commit refs (`head_sha`, `pull_request.head.sha`, `refs/pull/*`, `merge_commit_sha`) stay
  untrusted with or without `repository:`, since GitHub serves fork PR commits from the base repo.
  A ref mixing both counts as the commit.
- Decision (fail closed): a branch-name ref counts as fork code when `repository:` is set to
  anything except `${{ github.repository }}`. My first version matched only explicit head-repo
  expressions. Rescanning a real dry-run repo showed that dropped a genuine fork checkout whose
  head repo comes from a step output (`steps.pr.outputs.head_repo`). A test now covers that shape.
- Fixtures are synthetic. Of the five dry-run fails, only the one with the wrong reason changes:
  no fork-pr fail, now UNKNOWN because an unrelated workflow file in that repo fails to parse
  (duplicate YAML keys; fail closed, never reported). The other four are unchanged.

## 2026-10-02 — 0090 same-repo guard before a PR-ref fetch

- Found by the dry-run hand review (details in the private ops repo). A `run:` step that exits
  when the PR head repo != the base repo, before `git fetch … refs/pull/…`, only ever fetches
  same-repo PRs, so it is no longer an untrusted checkout.
- Narrow on purpose: the guard must use `!=`, compare a head-repo token with a base-repo token
  (`REPO`, `GITHUB_REPOSITORY`, `github.repository`; case-sensitive so `head_repo` alone
  doesn't count), sit before the fetch, and exit inside its `if … fi`. Anything else fails
  closed. Tests cover `==`, guard-after-fetch, and no-exit.
- Scope change: the login-gate half moved to 0091. The dry-run job's bot (a review bot)
  auto-acts on fork PRs, so "only runs for the bot" does not stop an outsider's PR from
  triggering it. Crediting it for fork-pr findings would create false passes.
- Verified: the refuted dry-run fail drops to warn (the agent reading the bot's text, legs
  incomplete). The other four are unchanged. The 50-repo sample has identical findings vs main.

## 2026-10-05 — 0092 per-fail approval before any report is sent

- Why: the allowlist released a whole archetype, so after go-live every new fail of that class
  would be filed unseen. Jay: a single false report could end the project.
- Chose: approval is required **in addition to** the allowlist and tripwire, not instead of them.
  The allowlist stays as a per-class kill switch; the tripwire still wins over an approval.
- Chose: approvals pin to the full commit sha the report names (its footer), per finding id.
  A moved HEAD means a new sha and so no approval. Stricter than per-repo, but the report text
  quotes file:line at that commit, so an approval of a different commit is not an approval of it.
- Change: the scan job's candidates now carry `sha`, and the submit job drops any candidate whose
  sha differs from its scan row. Scan-result artifacts from older engines are dropped (they are
  run-local and live a day, and both jobs run the same `BLASTGATE_SHA`).
- Tradeoff: approvals must be re-done if a repo pushes between review and send. Accepted; that is
  exactly the case where the reviewed lines may no longer be the reported ones.

## 2026-10-05 — 0093 review packets (`crawl review`)

- Chose: rescan at current HEAD, not the ledger's old sha. The approval pins to the sha that will
  actually be reported, and the crawler only reports HEAD (reverify refuses a stale head), so
  reviewing an older commit would approve something that can never be sent.
- Chose: quote the **whole** cited workflow, numbered, cited lines marked. Both refuted dry-run
  fails turned on a guard far from the cited line (a job `if:` and an early `exit`), so an
  excerpt around the line would have hidden them.
- Safety: packets are refused inside this public repo; clones live in a temp dir that is always
  deleted; quoted files are read only if they are regular files whose real path stays inside the
  clone (a hostile repo cannot symlink a packet into quoting local files). Payloads never appear.
- Rerun keeps a packet whose sha is unchanged so a verdict is not lost; a moved repo's packet is
  replaced with `verdict: pending`. Limitation: a kept packet is not refreshed if only the local
  engine changed. The packet flags an engine that differs from the crawler's.
- Ran the full suite with `--testTimeout=60000`: the machine's load average was ~250 from other
  apps and git-backed tests on `main` timed out at the 5s default the same way. Assertions unchanged.

## 2026-10-05 — 0094 adversarial fail skeptic

- Chose: the skeptic is a runbook prompt (docs/runbooks/crawler-skeptic.md) run as one
  fresh-context subagent per packet, not code. `.claude/` is untracked here, and the prompt is the
  product. Code side: the review index sorts refuted, doubtful, pending, could-not-refute.
- Advisory only: it edits `skeptic:` and its own section, never `verdict:` or approvals. A hostile
  repo that talks it out of a refutation can only cost a second look, never send a report.
- Checked on two synthetic packets with blind names (2026-10-05): the false fail (fork-pr blocked
  by a same-repo job `if:`, no checkout) came back **refuted** for the right reasons. The intended
  true fail came back **doubtful**, correctly: my synthetic workflow checked out a hardcoded PR
  number with no `GH_TOKEN`. It errs toward doubt, which is the safe direction. Both edited only
  the allowed lines (diffed against a fresh render).

## 2026-10-05 — 0100 skeptic required for every approval

- Jay: "make the skeptic part of the process so that there are no false positives reported."
  Chose (Jay): skeptic runs locally in Claude Code; only `could-not-refute` may reach approval.
- Enforcement is two independent checks: `crawl approve` writes approvals only from packets with
  `verdict: confirmed` AND `skeptic: could-not-refute`; and the config parser rejects any
  approval entry without `skeptic: "could-not-refute"`, so a hand-pasted entry fails to load.
  It is a convention, not a cryptographic proof: someone could type the field by hand. The
  point is that skipping the skeptic now takes a deliberate act, not an oversight.
- Measured the cheaper model (Sonnet) blind on the 33 packets of 2026-10-05 against Jay's
  verdicts: 0 false passes, but also 0 passes: both confirmed real issues came back doubtful.
  Opus passed 1 of the 2 real ones and 0 false. At the strict bar Sonnet alone would block every
  report. Jay chose Sonnet then Opus: Sonnet refutes (it may only remove), `crawl skeptic-reset` blanks the rest so Opus reads them unbiased, Opus decides. Simulated on the 33: 1 real passed, 0 false, 15 Opus runs instead of 33.
- Verified on real data with a throwaway config: approves legacy-ctm (2 findings), skips
  ai-integr8tor (skeptic doubtful), rejects a hand-pasted entry. Real ops config untouched.

## 2026-10-05 — 0101 two report tiers; the skeptic's result decides

- Jay changed the philosophy: the scans exist to help owners. Skeptic `could-not-refute` is
  reported as a **security vulnerability** (severity high); `doubtful` as a **possible security
  vulnerability** (severity medium, asks the owner to investigate). No human verdict needed.
- Kept one human brake (chose): a packet a human marks `verdict: refuted` is never approved.
- Chose: the tier is applied at send time (`tierReport`) because the scan job composes reports
  before the skeptic runs. Only the title, intro and severity change; finding blocks and footer
  are kept byte for byte. One doubtful finding makes the whole report the possible tier.
- Jay: possible-tier reports wait for 0095/0096 (`sendPossible: false`). On today's batch that
  tier would reach 9 repos, 4 of them most likely not vulnerable.
- Chose: the possible-tier wording names generic unknowns (settings only the owner can see)
  and never quotes the skeptic's own notes. Those notes come from reading attacker-controlled
  text and are model output; sending them to a stranger is an injection and accuracy risk.

## 2026-10-05 — 0099 shell/script injection described accurately

- Text spliced with `${{ }}` into `run:` or `github-script` (sinkClass `execution`) now says what
  happens: the text runs as code in the job. The fix recommends the env-var + `"$VAR"` pattern.
  The old prompt-injection wording ("e.g. an HTML comment invisible on the rendered page") stays
  only on the generic branch, where no execution sink is classified.
- Chose one sentence for both `run:` and `github-script`; the entry does not record which one,
  and the sentence is true for both. No example payload in the text, which keeps reports free of
  attacker.example strings.
- Verified on the real legacy-ctm repo via `crawl review`: new why/fix text, zero "HTML comment".

## 2026-10-05 — 0102 ask owners with PVR off to enable it

- The one confirmed vulnerability (legacy-ctm) has private vulnerability reporting disabled, so
  no report could reach it. Jay chose a public, detail-free issue asking the owner to enable PVR.
- Safety choices: only on a definite "off" answer (200, `enabled: false`), never on 401/403/404
  (a bad token must not spam strangers); one request per repo ever, written to the ledger before
  the POST; any failure is final; counts against the same throttle as reports; the text is fixed
  and names nothing (not even "CI"), so nothing about the vulnerability goes public.
- Not built: watching the request issue (closed without enabling = owner declined). Today the
  repo just stays held; a follow-up could mark it declined.

## 2026-10-06 — 0106 expire unanswered PVR requests

- `pvrRequestTtlDays` (default 90, max 365) in the ops config. Past it, every retryable `no PVR`
  hold on an asked repo becomes final as `no PVR (request expired)`, so `delta` stops treating it
  as pending. Runs in `runSubmit` right after the scans are applied, on the whole ledger, so it
  happens even when the repo is not rescanned.
- Chose 90 days to match the usual disclosure window. Skipped the optional back-off (rescan daily
  instead of every run inside the TTL): one rescan per run is cheap next to the 90-day cutoff.

## 2026-10-06 — 0104 honor a closed PVR request issue, surface owner replies

- Decided the open question from the ticket: closed counts as "declined" only while PVR is still
  off. An owner who turns PVR on and then closes the issue did what we asked, so the report goes
  out. Closed with PVR off is final (`declined (request issue closed)`) even if PVR is turned on
  later, which keeps the issue text's promise ("close this issue" = do not want to hear).
- Deviation: the ticket asked for a HITL item per reply. The crawler runs in GitHub Actions,
  where the local HITL helper does not exist, and the run log is counts-only by design (no repo
  names). So replies are counted (`owner replies N` in the submit log) and the newest counted
  reply's time is stored as `pvrRequest.repliesSeenAt`. GitHub already notifies Jay of replies,
  since the issues are filed from his account; that is the primary channel.
- The issue is read only when a candidate for that repo reaches the PVR check (rescanned, still
  failing, gate passed). A repo held for another reason (e.g. not approved) is not checked; a
  missed close then takes effect the first time it does reach the check.
- A 403/5xx/transport error on the lookup changes nothing; a rate limit stops the run like the
  PVR pre-check does.

## 2026-10-06 — 0105 close out the PVR request issue

- One comment, then `PATCH state: closed` (added `patch()` to the crawler's GitHub client; sent
  once, never retried, like a POST). `closedOutAt` is written and persisted before the comment.
  A refused comment or close is recorded as `closeOutFailedStatus` and not retried.
- Chose repo-level conditions, since one request issue covers every disclosure on the repo:
  "filed" once any disclosure there has a report URL and none is still pending; "resolved" only
  when every disclosure there is `resolved-before-report`. Final holds (declined, expired,
  uncertain) leave the issue as it is.
- Added scope: `resolveStale` in `runSubmit`. Before this, a pending entry whose repo was
  rescanned and passed stayed pending forever (`delta` only revisits fails and changed passes),
  so neither the "resolved" close-out nor the ledger would ever reflect the fix.
- Close-out counts against the throttle as one action (comment + close). An issue found already
  closed is marked `closedOutAt` without posting; that still counts toward the budget. Rare, so
  kept simple.

## 2026-10-06 — 0103 carry an approval across an unrelated commit

- Done in the submit job with GitHub's compare API (`/compare/<approved>...<head>`), since the
  submit job never clones. The approval carries only when: every finding id has an approval at
  one common older commit; compare says `ahead` (not diverged/behind); the file list is complete
  (< 300 files, GitHub's cap); and no changed path (or rename source) is under `.github/` or is an
  `action.yml`/`action.yaml` anywhere. Anything else falls back to `not approved at this commit`.
- Deviation from the ticket: it asked for "the cited workflow file is byte-identical". Chose the
  whole `.github/` tree plus any `action.yml`/`action.yaml` instead, because a finding can depend
  on a reusable workflow or local action the finding id does not name. Gap: a local action whose
  code changed but whose `action.yml` did not (e.g. its `dist/index.js`) still carries. Accepted:
  the sink and the `${{ }}` splice the finding names live in the workflow/action YAML.
- Not recorded in the ledger (no schema change): the run log has `approvals carried N`, and the
  report footer already names the new commit. Up to 3 older commits are tried per fail.
- The carried approval keeps its skeptic verdict, so the report tier (0101) is unchanged.
- `approvals carried N` counts fails the carry released at the gate this run, including ones then
  held for PVR; it can repeat across runs for the same fail. Older commits are tried in sha order
  (no dates on approvals), at most 3.

## 2026-10-06 — review fixes for 0103-0106 (fresh-context reviewer)

- Fixed: a "no longer finds" close-out could fire when finding ids shifted (engine change) while
  the repo still failed; `resolved` now also needs the latest scan of the repo to be clean.
- Fixed: a closed request issue became a final decline even when the PVR check was inconclusive
  (403/404); it now needs a definite `enabled: false`.
- Fixed: close-out is now once per repo (any entry with `closedOutAt` ends it), and
  `setPvrRequest` updates the entry that already carries the request, so the record never splits
  across a resolved entry and a later live one with the same ids.
- Fixed: a request issue that is gone (404/410) at close-out is given up on instead of re-checked
  every run.
- Known, not changed: expiry (0106) runs before the PVR check, so an owner who turns PVR on after
  the TTL is not reported to. Matches the ticket; revisit if it ever happens.
- Known, not changed: a comment that lands but whose close (PATCH) fails leaves the issue open
  with our comment; recorded as `closeOutFailedStatus`, not retried.

## 2026-10-06 — 0096: evidence names the executing step and the secret

- Chose a conservative allowlist for "runs nothing from the checkout": git plus a short list of
  shell builtins/coreutils (echo, date, cd, cat, rm, ...). Anything else, command substitution,
  loops, `case`, or a non-bash `shell:` still counts as running PR code. It only drops a fail
  whose step plainly runs nothing; it does not try to prove a step safe.
- Tradeoff: a third-party action after the checkout still never counts as running PR code
  (unchanged from 0048), so an action that builds the workspace (e.g. a Docker or Gradle build
  action) is missed. The ticket asked for this; revisit with a list of known building actions.
- `at:` is now the step's `run:` (or local `uses:`) line, not its first line. The install step
  evidence is unchanged.
- The reason now says where the job exposes the sink: the `secrets.X` reference line, or the
  `permissions:` line for a write token. A shell injection whose secret sits in a later step is
  still a fail (existing AE1 contract); the report now cites that later line instead of implying
  the injected step holds it.
- Also fixed under this ticket (same report-accuracy class): the trigger list in a fork-PR reason
  drops maintainer-only events (push, schedule, workflow_dispatch, ...).
- Two fixtures used `run: echo ...` to mean "runs PR code"; changed to `make build` / `npm test`,
  since echo is now correctly non-executing.
- Checked on the three live repos from the 2026-10-05 review (names in the private ops repo):
  each now cites the executing `run:` line and the secret's line, and none lists push.
- Not caused by this change: `src/crawl/scan.test.ts` times out locally (5s test / 10s hook) on
  main as well; all 950 tests pass with a 30s timeout.

## 2026-10-06 — 0096 review fixes (fresh-context reviewer, request-changes)

- Fixed: the "runs nothing" allowlist trusted all of git, cp, mv, tee and export. Git can run a
  command (`bisect run`, `rebase -x`, `submodule foreach`, `-c alias.x='!…'`, `core.hooksPath`),
  and a copied file can become a hook or `~/.gitconfig`. Now: git only for read/fetch/ref
  subcommands, no `-c`, no exec-style options, `config` only for user.name/email and similar;
  cp/mv/tee/touch count as executing; assigning PATH, BASH_ENV, LD_*, GIT_* and similar counts
  as executing; any redirect other than /dev/null, an fd, $GITHUB_OUTPUT or $GITHUB_STEP_SUMMARY
  counts as executing, as does any mention of GITHUB_ENV/GITHUB_PATH.
- Fixed: single `&` and process substitution `<( )` / `>( )` hid a command.
- Quoted strings are masked before the redirect and command checks, so `echo "a -> b"` is not a
  redirect.
- Rescan of the 26 failing repos unchanged in outcome: the git-only job still drops.

## 2026-10-06 — 0096 second review fixes (request-changes again)

- Fixed (high): quoted text was masked with a regex, so an apostrophe in a comment (`# don't`)
  or an escaped quote swallowed real commands. Replaced with a small single-pass shell reader
  (quotes, `$'…'`, escapes, comments, separators, redirects). Anything outside that subset
  (substitutions, subshells, heredocs, unterminated quotes) counts as executing.
- Fixed (medium): a PR can commit a bare-repo layout in a subdirectory whose config names a
  command (e.g. `remote.origin.uploadpack`), and git loads it when run from there. git now
  counts as executing after `cd`/`pushd`, with `-C`/`--git-dir`/`--work-tree`, in a step with
  `working-directory:`, or under a job/workflow `defaults.run.working-directory`. A step, job
  or workflow `env:` that sets PATH or another loader variable also counts.
- Low: grep, jq, sort, cut, tr and similar read-only tools, and a few more harmless git config
  keys (http extraheader, core.sparseCheckout), now count as non-executing.
- Rejected one reviewer probe: `echo don't` / `make build` / `echo can't` is one quoted string in
  bash, so make never runs; the reader agrees with bash.
- Rescan of the 26 failing repos: same outcome as before.

## 2026-10-06 — 0096 third review fixes

- Fixed (medium): every `${{ }}` was replaced with a placeholder, but GitHub pastes the value into
  the script before bash runs, so `echo ${{ github.event.pull_request.title }}` is shell
  injection. Only values a PR author cannot shape stay inert (SHAs, numbers, run ids, ref,
  repository names, clone URL, base ref, secrets, runner facts); any other expression counts
  as executing.
- Fixed (low): `[[ … -eq … ]]` (arithmetic evaluation runs `a[$(cmd)]`), `printf -v`, and
  assigning PS4/PROMPT_COMMAND count as executing. A variable argument to git fetch/pull/push/
  ls-remote/remote counts as executing (could be `--upload-pack=…`).
- Left as is (low, fails safe): `gh` and `curl` steps still count as executing, so a
  post-checkout comment/notify step can still be the cited line. Steps before the checkout are
  not scanned for GITHUB_PATH/GITHUB_ENV writes; that predates this PR.
- Rescan of the 26 failing repos: same outcome.

## 2026-10-06 — 0096 fourth review: shrink instead of patch

- Four review rounds each found a new way a "runs nothing" guess could hide code, so the allowlist
  is now minimal: echo, exit, true/false, set, export (no loader variables), mkdir, rm, ls, pwd,
  date, sleep, cd/pushd/popd, plus the reviewed git subcommands. Readers and testers (cat, grep,
  jq, test, [, [[, printf) are out: each has an argument form that evaluates or loads code.
- Fixed (medium): `fromJSON(…).number/.base.ref` was treated as inert, but in a workflow_run job
  the JSON can come from a PR-built artifact. Removed; any fromJSON expression counts as executing.
- Fixed (low): `${A:$T}` / `${arr[$T]}` (arithmetic evaluation) count as executing.
- Decoupled the cited line from the inert check: evidence prefers the first step that plainly
  runs build tooling (`./…`, npm, make, gradle, python, …) and falls back to the first step that
  cannot be shown to run nothing. A stricter allowlist can then only keep a fail; it no longer
  moves the citation back to a git step.
- Rescan of the 26 failing repos: same outcome, same cited lines.
