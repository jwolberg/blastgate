# Implementation Notes

Running log of decisions, deviations, and tradeoffs for human review.

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
- **Follow-up:** Repo directory is still `foothold/`; rename to `blastgate/` is a
  separate step (git remote + dir), deferred.

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
  an attacker-injectable entry. Foothold's own settings.json (block-main-merge / stop-notify /
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
