#!/usr/bin/env bash
# Reproducible whole-repo evaluation scan (ticket 0051, plan KTD8).
#
# Blobless, sparse, depth-1 clones fetch only the paths Blastgate reads, then scan each
# repo with the locally built CLI (`npm run build` first). Clones are cached in WORKDIR
# and reused across runs; delete WORKDIR to re-fetch HEAD.
#
# Usage: scripts/eval-scan.sh <workdir> <outdir> [repo-list]
#   outdir gets one <owner>__<repo>.json per repo (findings, payloads included — local
#   evaluation only, do not publish) plus index.tsv: repo, sha, exit code, fail, warn.
#   SCAN_FLAGS adds CLI flags to every scan, e.g. SCAN_FLAGS=--public for a public sample.
#   A clone whose checkout is missing tracked files (a network timeout mid-checkout) is
#   re-cloned once; one that still cannot be completed is reported as `clone-failed`, never
#   scanned as a clean 0/0 (0066). EVAL_REMOTE_BASE and BLASTGATE_CLI override the clone
#   source and the scanner (tests).
set -euo pipefail

WORKDIR=${1:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
OUTDIR=${2:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
LIST=${3:-"$(dirname "$0")/eval-repos.txt"}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI="${BLASTGATE_CLI:-$ROOT/dist/cli/index.js}"
REMOTE_BASE="${EVAL_REMOTE_BASE:-https://github.com}"
[ -f "$CLI" ] || { echo "build first: npm run build" >&2; exit 2; }
mkdir -p "$WORKDIR" "$OUTDIR"

# The paths Blastgate reads (whole-repo mode).
SPARSE=(/.github/ /.gitlab-ci.yml /.circleci/ /.mcp.json /.claude/ /.cursor/ /package.json
  /package-lock.json /yarn.lock /pnpm-lock.yaml /.npmrc /.yarnrc.yml /Gemfile.lock
  /setup.py /requirements.txt)

# Clone (or re-clone) a repo's sparse paths; non-zero if the clone fails.
clone_sparse() {
  local repo=$1 dir=$2
  rm -rf "$dir"
  git clone -q --depth 1 --filter=blob:none --sparse "$REMOTE_BASE/$repo.git" "$dir" &&
    git -C "$dir" sparse-checkout set --no-cone "${SPARSE[@]}"
}

# A complete clone: it has a commit, and every tracked file in the sparse set is checked out.
clone_complete() {
  local dir=$1
  [ -d "$dir/.git" ] &&
    git -C "$dir" rev-parse -q --verify HEAD >/dev/null &&
    [ -z "$(git -C "$dir" status --porcelain --untracked-files=no 2>/dev/null)" ]
}

scan_one() {
  local repo=$1 name=${1//\//__}
  local dir="$WORKDIR/$name"
  if ! clone_complete "$dir"; then
    clone_sparse "$repo" "$dir" 2>"$OUTDIR/$name.clone.err" || true
    if ! clone_complete "$dir"; then
      printf '%s\t-\tclone-failed\t-\t-\n' "$repo"
      return 0
    fi
  fi
  local sha code
  sha=$(git -C "$dir" rev-parse --short HEAD)
  set +e
  # shellcheck disable=SC2086 # SCAN_FLAGS is a deliberately word-split flag list
  node "$CLI" "$dir" --json --include-payloads ${SCAN_FLAGS:-} >"$OUTDIR/$name.json" 2>"$OUTDIR/$name.err"
  code=$?
  set -e
  node -e '
    const f = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8") || "[]");
    const n = (t) => f.filter((x) => x.tier === t).length;
    console.log([process.argv[2], process.argv[3], process.argv[4], n("fail"), n("warn")].join("\t"));
  ' "$OUTDIR/$name.json" "$repo" "$sha" "$code"
}
export -f scan_one clone_sparse clone_complete
export WORKDIR OUTDIR CLI SCAN_FLAGS REMOTE_BASE
export SPARSE_DECL; SPARSE_DECL=$(declare -p SPARSE)

grep -v '^\s*\(#\|$\)' "$LIST" \
  | xargs -P "${JOBS:-6}" -I{} bash -c 'eval "$SPARSE_DECL"; scan_one "$@"' _ {} \
  | sort >"$OUTDIR/index.tsv"

printf 'repo\tsha\texit\tfail\twarn\n'
cat "$OUTDIR/index.tsv"
