---
title: Run the public crawler (setup, operation, incident)
last-verified: 2026-10-01
anchor: RB-crawler
---

The crawler finds public repos that run AI agents in CI, scans them, lists the passes on a public
registry, and privately reports fails through GitHub private vulnerability reporting (PVR). Code
lives in `src/crawl/` (public, tested by CI); it runs from a PRIVATE ops repo using
[`ops/crawl.yml`](../../ops/crawl.yml). Design: [the plan](../plans/2026-10-01-002-feat-public-crawler-plan.md).

Everything below that creates a repo or a credential is **yours to do by hand**; nothing in the
code creates them. Ship nothing live until the go-live gate in [6] is met.

## [1] Create the repos

1. **Ops repo** `jwolberg/blastgate-crawl`, **private**. Holds the workflow, `ledger.json`,
   `discovery.json`, `config.json`, and `KILL_SWITCH` when needed. Its Actions logs and artifacts stay private;
   the public `blastgate` repo's would not.
2. **Registry repo** `jwolberg/blastgate-registry`, **public**. Pages from branch `gh-pages`
   (Settings, Pages, deploy from branch). The crawler force-pushes one orphan commit there each
   publish, so no removal ever shows in its history.
3. In the ops repo copy the template: `ops/crawl.yml` to `.github/workflows/crawl.yml`.
4. Seed `config.json` with `{}` (every default is the safe one, see [3]) and commit it. A missing
   `ledger.json` or `discovery.json` is treated as empty; the first submit run creates them.
5. Set repo variable `BLASTGATE_SHA` to the full commit SHA of `jwolberg/blastgate` to run. The
   template checks the code out at exactly that SHA; bumping it is a reviewed change.

## [2] Credentials

**Registry deploy key** (publish only):

```bash
ssh-keygen -t ed25519 -N '' -C blastgate-registry-deploy -f registry_deploy_key
gh repo deploy-key add registry_deploy_key.pub -R jwolberg/blastgate-registry --allow-write \
  -t crawler-publish
gh secret set REGISTRY_DEPLOY_KEY --env crawler -R jwolberg/blastgate-crawl < registry_deploy_key
shred -u registry_deploy_key registry_deploy_key.pub 2>/dev/null || rm -P registry_deploy_key*
```

**PVR reporting token** (`PVR_TOKEN`; the only credential that can write to strangers' repos):

- Try a **fine-grained PAT first**. Filing a report on a repo you do not own needs the "Repository
  security advisories: write" permission on that repo, which a fine-grained token scoped to your
  own repos cannot have. If GitHub will not let you create one that works across public repos,
  fall back to a **classic token with only `public_repo`**.
- **Risk acceptance (record it here when you choose).** A classic `public_repo` token can write to
  every public repo your account can reach, not just advisories. If it leaks, the blast radius is
  your account. Mitigations: use a **dedicated machine account** (no other access, no org
  membership) as the reporter; store the token only in the protected `crawler` environment; the
  scan job never sees it; set a **90-day expiry** and calendar the rotation.
- Rotation: create the new token, `gh secret set PVR_TOKEN --env crawler -R jwolberg/blastgate-crawl`,
  trigger a dry run, then revoke the old token. Set `reporterLogin` in `config.json` to the
  reporter account's login so the tracker can recognize credits.

**Protected environment.** Create environment `crawler` in the ops repo with required reviewers
(or a deployment-branch rule limited to `main`), then put both secrets in it. The submit job
declares `environment: crawler`, so a modified workflow cannot reach them unreviewed.

## [3] Config (`config.json` in the ops repo)

Strict JSON; unknown keys are rejected so a typo cannot silently flip a safety default.

| Field | Default | Meaning |
| --- | --- | --- |
| `allowlist` | `[]` | Archetypes (`<entry kind>-><sink kind>`) whose fails are auto-submitted. Empty means everything is held. |
| `submitMode` | `false` | Off is dry run: the exact request body is recorded on the disclosure (`wouldSend`), nothing is sent. |
| `publishSite` | `false` | Off builds the site but never pushes it. |
| `reporterLogin` | `""` | Login the reports are filed as. Empty skips advisory tracking. |
| `throttle` | `{perHour: 5, perDay: 20}` | Submission budget per trailing hour and day. |
| `discoveryBudget` | `300` | Max code-search requests one run spends on discovery (1 to 5000). Searches are throttled to 9/min, so 300 is about 35 minutes. |

Turn on `submitMode` and `publishSite` independently, and only after [6].

## [4] Day-to-day

- **Kill switch.** Create a file named `KILL_SWITCH` at the ops repo root (any content) and push.
  The next run stops all outbound reports regardless of config. It is separate from `submitMode`
  so an emergency stop needs no config edit. Delete the file to resume.
- **Reviewing held fails.** Open `ledger.json` and look at disclosures in state `held`; `reason`
  says why (`archetype not allowlisted`, `no PVR`, `submission state uncertain`, ...). Read the
  fail by hand (the ledger keeps archetype and finding ids; re-scan the repo locally with
  `blastgate <path> --json` for the evidence). To release an archetype, add it to `allowlist`; held
  entries for it return to `queued` on a later run.
- **Dry-run bodies.** Disclosures with `wouldSend` hold the exact JSON that would be POSTed. Read a
  sample for each archetype before enabling `submitMode`: the summary, the description, and that
  no payload text appears.
- **Tripped archetypes.** A submitted report whose advisory is closed or withdrawn becomes
  `declined` and puts its archetype in `trippedArchetypes`; the gate then holds it even if
  allowlisted. Re-admit it by removing it from that list by hand once you have judged the cause.
- **`submitting` entries.** A run that died mid-send leaves one; the next run holds it as
  `submission state uncertain` and never retries. Check the repo's advisory list yourself, then
  mark it in the ledger by hand.
- **Engine-version re-vouching.** Each scan records `engineVersion = <cli version>+<blastgate
  commit>`. Changing `BLASTGATE_SHA` therefore re-queues every listed pass first (then the rest,
  oldest first), so the pass list is re-vouched by the new engine before it ages. Do this after
  any engine fix that could turn a pass into a fail.
- **Discovery spans several runs.** GitHub code search caps at 1,000 hits per query and 10
  requests a minute, and claude-code-action alone has ~19,000 hits, so a full pass over the
  agent actions takes more requests than one run's `discoveryBudget`. Each run works a queue of
  search shards (size ranges, then filenames) until the queue empties, the budget runs out, or
  GitHub's rate limit persists; the queue and the repos found so far are committed to
  `discovery.json` by the submit job (the scan job is read-only, so it hands the new state over
  inside `scan-result.json`). The next run resumes the queue. A rate limit or exhausted budget
  never fails the job: the run goes on to scan the repos already known. The `scan: discovery ...`
  log line says whether the sweep is complete or how many shards are pending, searches spent, and
  why discovery stopped.
- **Sweeps.** When the queue empties the sweep is complete; repos it did not see are dropped from
  `discovery.json` (they no longer use an agent action), and the next run starts a new sweep,
  keeping the known repo set meanwhile. A sweep with a failed (partial) shard drops nothing,
  since absence then proves nothing. To force a fresh sweep, delete `discovery.json`; to speed up
  the first pass, raise `discoveryBudget` or dispatch the workflow repeatedly. `discovery.json` is
  machine-written and strictly validated; do not hand-edit it.
- **Rate-limit telemetry.** The scan job's first step prints the Actions token's `rate_limit`
  resources (`code_search`, `search`, `core`). Every rate-limited response then logs one
  `crawl: rate limited (<status>, <search|core>, <resource>): limit=… remaining=… used=… reset=…
  retry-after=…` line, headers only, never a URL or repo. Compare the two to tell a low token
  quota (a separate read-only search token would help) from a secondary limit (it would not).
- **Run logs** carry counts only (discovered, truncated/partial shards, verdict counts, outcome
  counts), never a repo name next to a verdict. Truncated or partial shards mean discovery missed
  some repos; the run still finishes.

## [5] Manual first run

1. Dispatch the workflow (`gh workflow run crawl.yml -R jwolberg/blastgate-crawl`) with the
   defaults. Expect: a scan, held fails, no POST, no publish.
2. Check `ledger.json` was committed and the `submit:` log line shows `mode dry-run`.

## [6] Go-live gate (plan U11)

Do not set `allowlist`, `submitMode`, or `publishSite` until all of this holds:

- Ticket **0070 is closed** (an agent step with default tools is no longer assumed to be unable to
  read files or env; otherwise a vulnerable repo could be listed as a pass).
- A dry-run crawl has been hand-reviewed: every fail has a hand verdict, a random sample of at
  least 30 passes (weighted to repos whose agents hold secrets with outsider-reachable triggers)
  has zero false passes.
- Each archetype to allowlist has at least 20 hand-confirmed fails across at least 10 owners and
  zero refuted.
- The result and your approval are written to `docs/evaluations/<date>-crawler-dry-run.md`.

Stop and ask before: the first live report, the first public site push, and on any GitHub abuse or
secondary-rate-limit response (the run stops submitting on its own and logs it).

## [7] Incident: a bad report went out

1. **Stop the flow.** Push `KILL_SWITCH` to the ops repo; set `submitMode` to `false`.
2. **Retract.** Comment on the advisory thread, apologize, say the finding was an automated false
   positive, and close or withdraw the report if you can. Do not leave a wrong claim standing.
3. **Cut the credential.** Revoke the PVR token (or the machine account's access) and clear the
   secret: `gh secret delete PVR_TOKEN --env crawler -R jwolberg/blastgate-crawl`.
4. **Contain the archetype.** Remove it from `allowlist` and add it to `trippedArchetypes` in the
   ledger. Find the cause (rule bug? stale tree?) and file a ticket; add a fixture that fails
   before the fix.
5. If the public list is wrong, set `publishSite` to `false`, fix, and republish; the registry
   keeps only one commit, so a corrected force-push replaces it.
6. Record what happened in `docs/implementation-notes.md` or a learning, and only then re-enable.
