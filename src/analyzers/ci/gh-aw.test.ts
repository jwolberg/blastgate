import { describe, expect, it } from 'vitest';
import { isGhAwRuntimeStep } from './parse';

/**
 * 0062 (PR #39 review): a step in a gh-aw job is exempt from 0048 execution evidence only
 * when every command in it is gh-aw runtime or inert plumbing. Anything unrecognized is
 * treated as running the PR's code (an allowlist, not a denylist).
 */
describe('isGhAwRuntimeStep — allowlist (0062)', () => {
  it.each([
    ['bash "${RUNNER_TEMP}/gh-aw/actions/configure_git_credentials.sh"'],
    ['mkdir -p "${RUNNER_TEMP}/gh-aw/safeoutputs"\nmkdir -p /tmp/gh-aw/safeoutputs'],
    ['if [ ! -f /tmp/gh-aw/out.json ]; then\n  echo \'{"items":[]}\' > /tmp/gh-aw/out.json\nfi'],
    ['cat > /tmp/gh-aw/mcp.json << GH_AW_EOF\n{\n  "mcpServers": {}\n}\nGH_AW_EOF'],
    ['ID=$(openssl rand -base64 45 | tr -d "/+=")\necho "::add-mask::${ID}"'],
    ['bash "${RUNNER_TEMP}/gh-aw/actions/run.sh" -- awf --config x -- copilot -c y'],
    ['GH_AW_NPM_ROOT="$(npm root -g 2>/dev/null || true)"'],
    ['"$GH_AW_NODE_EXEC" --version'],
    ["trap 'rm -f /tmp/gh-aw/x; echo done' EXIT"],
    [
      'cat << GH_AW_EOF | "$GH_AW_NODE" "${RUNNER_TEMP}/gh-aw/actions/start.cjs"\n{"a": 1}\nGH_AW_EOF',
    ],
    [
      'awf --config "${RUNNER_TEMP}/gh-aw/awf-config.json" --container-workdir "${GITHUB_WORKSPACE}" -- /bin/bash -c \'copilot --x\'',
    ],
  ])('runtime: %s', (run) => {
    expect(isGhAwRuntimeStep(run)).toBe(true);
  });

  it.each([
    ['bash /tmp/gh-aw/runtime.sh\nnode build.js'],
    ['bash /tmp/gh-aw/r.sh && docker build .'],
    ['bash /tmp/gh-aw/r.sh; $GITHUB_WORKSPACE/x.sh'],
    ['bash /tmp/gh-aw/r.sh; "${GITHUB_WORKSPACE}/x.sh"'],
    ['bash /tmp/gh-aw/r.sh; eval "$(cat x)"'],
    ['bash /tmp/gh-aw/r.sh; time node x'],
    ['bash /tmp/gh-aw/r.sh; bash -c "./x"'],
    ['bash /tmp/gh-aw/r.sh; pnpm dlx foo'],
    ['bash /tmp/gh-aw/r.sh; deno run x.ts'],
    ['bash /tmp/gh-aw/r.sh && ./scripts/build.sh'],
    ['make test # see /tmp/gh-aw/ docs'],
    ['echo $(./evil.sh)'],
    ['FOO=1 ./x'],
    ['. ./x'],
    ['if [ -f x ]; then ./x; fi'],
    ['find . -name x -exec sh {} \\;'],
    ['git config core.hooksPath .githooks && git commit -m x'],
    ['awk -f prog.awk input'],
    ['npm ci'],
    // PR #39 round-3 review: tokenizer bypasses must fail closed.
    ['bash /tmp/gh-aw/r.sh\n"./scripts/build.sh"'],
    ["bash /tmp/gh-aw/r.sh\n'./x'"],
    ['bash /tmp/gh-aw/r.sh\n"node" x.js'],
    ['bash /tmp/gh-aw/r.sh\necho $((1<<2))\n./scripts/build.sh'],
    ['bash /tmp/gh-aw/r.sh\ncat <<< x\n./scripts/build.sh'],
    ['bash /tmp/gh-aw/r.sh # note <<X\n./scripts/build.sh'],
    ['bash /tmp/gh-aw/r.sh\necho `./scripts/build.sh`'],
    ['bash /tmp/gh-aw/r.sh\necho "`./scripts/build.sh`"'],
    ['bash /tmp/gh-aw/r.sh\ndiff <(./x) y'],
    ['bash /tmp/gh-aw/r.sh\ncommand ./x'],
    ['bash /tmp/gh-aw/r.sh\ntrap ./x EXIT'],
    ["bash /tmp/gh-aw/r.sh\ntrap './x' EXIT"],
    ['bash /tmp/gh-aw/r.sh\nawk \'BEGIN{system("./x")}\''],
    ["bash /tmp/gh-aw/r.sh\nsed -e '1e ./x' f"],
    ['"$GH_AW_NODE_EXEC" build.js'],
    ['awf -- node build.js'],
    ['source /tmp/gh-aw/a.sh ./x'],
    ['bash "${RUNNER_TEMP}/gh-aw/run.sh" -- node build.js'],
  ])('runs PR code: %s', (run) => {
    expect(isGhAwRuntimeStep(run)).toBe(false);
  });
});
