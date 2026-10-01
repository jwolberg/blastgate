#!/usr/bin/env bash
# Reproducible whole-repo evaluation scan (ticket 0051, plan KTD8).
#
# Blobless, sparse, depth-1 clones fetch only the paths Blastgate reads, then scan each
# repo with the locally built CLI (`npm run build` first). Clones are cached in WORKDIR
# and reused across runs; delete WORKDIR to re-fetch HEAD.
#
# Usage: scripts/eval-scan.sh <workdir> <outdir> [repo-list]
#   outdir gets one <owner>__<repo>.json per repo (findings, payloads included — local
#   evaluation only, do not publish) plus index.tsv: repo, full 40-char sha, exit code, fail, warn.
#   SCAN_FLAGS adds CLI flags to every scan, e.g. SCAN_FLAGS=--public for a public sample.
#   A clone whose checkout is missing tracked files (a network timeout mid-checkout) is
#   re-cloned once; one that still cannot be completed is reported as `clone-failed`, never
#   scanned as a clean 0/0 (0066). EVAL_REMOTE_BASE and BLASTGATE_CLI override the clone
#   source and the scanner (tests).
#   One hung repo must not stall the run: each clone is bounded by CLONE_TIMEOUT seconds
#   (default 120) and each scan by SCAN_TIMEOUT (default 300), using GNU `timeout` (or
#   `gtimeout`) when installed and running unbounded otherwise (e.g. stock macOS). A timed-out
#   clone is `clone-failed`; a timed-out scan is exit 124 with its output discarded, which the
#   crawler records as `unknown` — never a pass. git never prompts for credentials.
set -euo pipefail

WORKDIR=${1:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
OUTDIR=${2:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
LIST=${3:-"$(dirname "$0")/eval-repos.txt"}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI="${BLASTGATE_CLI:-$ROOT/dist/cli/index.js}"
REMOTE_BASE="${EVAL_REMOTE_BASE:-https://github.com}"
CLONE_TIMEOUT="${CLONE_TIMEOUT:-120}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-300}"
export GIT_TERMINAL_PROMPT=0
[ -f "$CLI" ] || { echo "build first: npm run build" >&2; exit 2; }
mkdir -p "$WORKDIR" "$OUTDIR"

# The paths Blastgate reads (whole-repo mode).
SPARSE=(/.github/ /.gitlab-ci.yml /.circleci/ /.mcp.json /.claude/ /.cursor/ /package.json
  /package-lock.json /yarn.lock /pnpm-lock.yaml /.npmrc /.yarnrc.yml /Gemfile.lock
  /setup.py /requirements.txt)

# Run a command under a time limit when a timeout binary exists; otherwise run it unbounded.
with_timeout() {
  local secs=$1; shift
  if command -v timeout >/dev/null 2>&1; then timeout -k 10 "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout -k 10 "$secs" "$@"
  else "$@"
  fi
}

# Clone (or re-clone) a repo's sparse paths; non-zero if the clone fails.
clone_sparse() {
  local repo=$1 dir=$2
  rm -rf "$dir"
  with_timeout "$CLONE_TIMEOUT" git clone -q --depth 1 --filter=blob:none --sparse "$REMOTE_BASE/$repo.git" "$dir" &&
    with_timeout "$CLONE_TIMEOUT" git -C "$dir" sparse-checkout set --no-cone "${SPARSE[@]}"
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
    # A clone that failed or timed out is never trusted, even if it left a plausible tree.
    if ! clone_sparse "$repo" "$dir" 2>"$OUTDIR/$name.clone.err" || ! clone_complete "$dir"; then
      rm -rf "$dir"
      printf '%s\t-\tclone-failed\t-\t-\n' "$repo"
      return 0
    fi
  fi
  local sha code
  sha=$(git -C "$dir" rev-parse HEAD)
  set +e
  # shellcheck disable=SC2086 # SCAN_FLAGS is a deliberately word-split flag list
  with_timeout "$SCAN_TIMEOUT" node "$CLI" "$dir" --json --include-payloads ${SCAN_FLAGS:-} >"$OUTDIR/$name.json" 2>"$OUTDIR/$name.err"
  code=$?
  set -e
  # A timed-out scan may have left a partial file: discard it so it can never parse as a verdict.
  if [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; then : >"$OUTDIR/$name.json"; fi
  node -e '
    // Unparseable output must not abort the whole run: report "-" counts, the crawler
    // treats that row as unknown.
    let fail = "-", warn = "-";
    try {
      const f = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8") || "[]");
      const n = (t) => f.filter((x) => x.tier === t).length;
      fail = n("fail"); warn = n("warn");
    } catch {}
    console.log([process.argv[2], process.argv[3], process.argv[4], fail, warn].join("\t"));
  ' "$OUTDIR/$name.json" "$repo" "$sha" "$code"
}
export -f scan_one clone_sparse clone_complete with_timeout
export WORKDIR OUTDIR CLI SCAN_FLAGS REMOTE_BASE CLONE_TIMEOUT SCAN_TIMEOUT GIT_TERMINAL_PROMPT
export SPARSE_DECL; SPARSE_DECL=$(declare -p SPARSE)

grep -v '^\s*\(#\|$\)' "$LIST" \
  | xargs -P "${JOBS:-6}" -I{} bash -c 'eval "$SPARSE_DECL"; scan_one "$@"' _ {} \
  | sort >"$OUTDIR/index.tsv"

printf 'repo\tsha\texit\tfail\twarn\n'
cat "$OUTDIR/index.tsv"
