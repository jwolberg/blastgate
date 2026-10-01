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
set -euo pipefail

WORKDIR=${1:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
OUTDIR=${2:?usage: eval-scan.sh <workdir> <outdir> [repo-list]}
LIST=${3:-"$(dirname "$0")/eval-repos.txt"}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI="$ROOT/dist/cli/index.js"
[ -f "$CLI" ] || { echo "build first: npm run build" >&2; exit 2; }
mkdir -p "$WORKDIR" "$OUTDIR"

# The paths Blastgate reads (whole-repo mode).
SPARSE=(/.github/ /.gitlab-ci.yml /.circleci/ /.mcp.json /.claude/ /.cursor/ /package.json
  /package-lock.json /yarn.lock /pnpm-lock.yaml /.npmrc /.yarnrc.yml /Gemfile.lock
  /setup.py /requirements.txt)

scan_one() {
  local repo=$1 name=${1//\//__}
  local dir="$WORKDIR/$name"
  if [ ! -d "$dir/.git" ]; then
    git clone -q --depth 1 --filter=blob:none --sparse "https://github.com/$repo.git" "$dir"
    git -C "$dir" sparse-checkout set --no-cone "${SPARSE[@]}"
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
export -f scan_one
export WORKDIR OUTDIR CLI SCAN_FLAGS
export SPARSE_DECL; SPARSE_DECL=$(declare -p SPARSE)

grep -v '^\s*\(#\|$\)' "$LIST" \
  | xargs -P "${JOBS:-6}" -I{} bash -c 'eval "$SPARSE_DECL"; scan_one "$@"' _ {} \
  | sort >"$OUTDIR/index.tsv"

printf 'repo\tsha\texit\tfail\twarn\n'
cat "$OUTDIR/index.tsv"
