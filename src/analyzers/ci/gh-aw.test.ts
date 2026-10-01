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
  ])('runs PR code: %s', (run) => {
    expect(isGhAwRuntimeStep(run)).toBe(false);
  });
});
