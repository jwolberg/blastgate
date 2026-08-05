---
title: Cut a Blastgate release (npm + GitHub Marketplace Action)
last-verified: 2026-08-05
anchor: RB-release
---

One pushed `v*` tag ships both artifacts off `.github/workflows/release.yml`: the
**npm package** (`publish-npm`, with Sigstore/OIDC provenance) and the **GitHub
Marketplace Action** (`release-action` — builds `dist/`, commits it into the tag,
moves the floating `v0` tag, and cuts a GitHub Release). Do a dry run first; the
first real tag is otherwise the first time `release-action` has ever run.

## [1] One-time prerequisites

- **`NPM_TOKEN` secret.** `publish-npm` needs an npm **automation** token with
  publish rights:
  ```bash
  gh secret set NPM_TOKEN        # paste the token from npmjs.com → Access Tokens
  gh secret list                 # confirm NPM_TOKEN is listed
  ```
- **Name is free.** `blastgate` is unclaimed on npm (checked 2026-08-05). The
  Marketplace Action name (`Blastgate`, from `action.yml`) must also be unique —
  GitHub validates this when you publish the Release.
- **`gh` authenticated** with write access to the repo.

## [2] Dry run (safe — never publishes)

```bash
npm run release:dry
```

This pushes a throwaway `v0.0.0-test` tag, watches the Release workflow, and
verifies it, then deletes the tag + release. It is safe because the `-test`
suffix makes `publish-npm` skip (nothing hits npm) and marks the release a
prerelease (so `v0` is not moved). A green run prints
`DRY RUN PASSED` and confirms: the Release was created, `dist/action/index.js` is
in the tag's tree (so `uses:` will resolve), `v0` was untouched, and `publish-npm`
was skipped. Fix any `✗` before a real release. See
[`scripts/release-dry-run.sh`](../../scripts/release-dry-run.sh).

## [3] Cut the real release

```bash
npm version minor            # bumps package.json + creates the vX.Y.Z tag
git push --follow-tags       # pushes the commit AND the tag → fires release.yml
```

On the tag, `release.yml` runs both jobs in parallel: `publish-npm`
(`npm publish --provenance`) and `release-action` (build `dist/`, force-move the
version tag + `v0` to the built commit, `gh release create`). Watch it:
`gh run watch` or the Actions tab.

## [4] Publish the Action to the Marketplace (one-time)

`release-action` creates the GitHub Release but does not list it. Once, on the
first release: open the Release → **edit** → tick **"Publish this Action to the
GitHub Marketplace"**, accept the developer agreement, choose a category, save.
Subsequent releases are listed automatically.

## [5] Verify after release

```bash
npx blastgate@latest .                       # the published CLI runs
npm view blastgate dist-tags version         # version + provenance on npmjs.com
git ls-remote --tags origin v0               # the floating major tag exists
```

Then a consumer repo can add `uses: jwolberg/blastgate@v0` (see
[`adopt-blastgate.md`](adopt-blastgate.md)).

## [6] If a release is bad

- **npm:** you cannot re-publish the same version. Bump and release again;
  `npm deprecate blastgate@X.Y.Z "reason"` to warn off the bad one. Unpublish is
  only allowed within 72h and is discouraged.
- **Action:** delete the GitHub Release and re-point `v0` (`git tag -f v0 <good>;
  git push --force origin v0`), or cut a new patch — `release-action` will move
  `v0` forward on the next tag.

## [7] Notes

- **Version tags are mutable here** — `release-action` rewrites the tag to include
  the `dist` build commit. Rationale and the immutable-tag alternative
  (commit `dist/` to `main` + a `check-dist` guard) are in
  [`../implementation-notes.md`](../implementation-notes.md) (0027).
- Prerelease tags (`vX.Y.Z-rc.N`) publish to npm but do **not** advance `v0` and
  are marked `--prerelease`. Only the `-test` suffix additionally skips npm.
