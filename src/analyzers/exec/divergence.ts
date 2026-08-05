/**
 * CI-divergent execution detector (0021).
 *
 * The AISI Mythos-5 dropper was "guarded by an environment check designed to skip
 * execution in CI so the code would not run where it might be noticed." This finds
 * that tradecraft: code that *branches on whether it is running in CI / a container
 * / an interactive terminal* to change what it does. Precision is the point (R14) —
 * merely reading or logging an env var is not a signal; testing it in a branch is.
 *
 * This is a deterministic, offline string scan (no AST): a heuristic tuned for a
 * very low false-positive rate on the shapes that actually appear in droppers, not
 * a proof. It runs over the repo's OWN install/build scripts and newly-added or
 * changed files (the attacker-controllable diff), never third-party dep bodies.
 */

export type DivergenceKind = 'ci' | 'container' | 'tty';

export interface Divergence {
  kind: DivergenceKind;
  /** The marker that was matched (env var name, path, or api), for the finding text. */
  marker: string;
}

/**
 * Uppercase CI/build environment variables. Case-sensitive and whole-word so `CI`
 * never matches inside `capacity`, and `process.env.CI` in a plain read is ignored
 * unless it sits in a branch/test position (see the operator patterns below).
 */
const CI_MARKERS = [
  'CI',
  'CONTINUOUS_INTEGRATION',
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'TF_BUILD',
  'JENKINS_URL',
  'CIRCLECI',
  'TRAVIS',
  'BUILDKITE',
  'RUNNER_OS',
  'RUNNER_NAME',
];

const MARKER_ALT = CI_MARKERS.join('|');
const OPT_ENV_PREFIX = String.raw`(?:process\.env\.|env\.|\$\{?)?`;

/**
 * A CI marker is "branched on" when it is:
 *  - preceded by a negation or an opening test paren:  `!process.env.CI`, `if (CI`
 *  - or followed by a JS comparison/logical/ternary op: `CI === ''`, `CI ?`, `CI &&`
 *  - or used inside a POSIX shell test:                 `[ -z "$CI" ]`, `[ -n "$GITHUB_ACTIONS" ]`
 */
const CI_BRANCH_PATTERNS: RegExp[] = [
  new RegExp(String.raw`[!(]\s*${OPT_ENV_PREFIX}(?:${MARKER_ALT})\b`),
  new RegExp(String.raw`\b(?:${MARKER_ALT})\b\s*(?:===|!==|==|!=|&&|\|\||\?)`),
  new RegExp(String.raw`\[\s*-[znf]\s+"?\$\{?(?:${MARKER_ALT})\}?"?\s*\]`),
];

/** Which specific marker produced a hit, for the finding text (best-effort). */
function firstCiMarker(source: string): string | undefined {
  for (const m of CI_MARKERS) {
    if (new RegExp(String.raw`\b${m}\b`).test(source)) {
      return m;
    }
  }
  return undefined;
}

/** Container-detection primitives — specific enough that presence alone is the signal. */
const CONTAINER_PATTERNS: Array<[RegExp, string]> = [
  [/\/\.dockerenv/, '/.dockerenv'],
  [/\/proc\/(?:1|self)\/cgroup/, '/proc/1/cgroup'],
];

/** Interactive-terminal detection — dormant-unless-a-human-is-watching. */
const TTY_PATTERNS: Array<[RegExp, string]> = [
  [/\.isTTY\b/, 'isTTY'],
  [/\bisatty\s*\(/, 'isatty'],
  [/\[\s*-t\s+[012]\s*\]/, 'test -t'],
  [/\btty\s+-s\b/, 'tty -s'],
];

/**
 * Scan a source string for CI/container/TTY-divergent execution. Returns one entry
 * per distinct (kind, marker) signal; an empty array means no divergence found.
 */
export function detectDivergence(source: string): Divergence[] {
  const hits: Divergence[] = [];
  const seen = new Set<string>();
  const add = (kind: DivergenceKind, marker: string): void => {
    const key = `${kind}:${marker}`;
    if (!seen.has(key)) {
      seen.add(key);
      hits.push({ kind, marker });
    }
  };

  if (CI_BRANCH_PATTERNS.some((re) => re.test(source))) {
    add('ci', firstCiMarker(source) ?? 'CI');
  }
  for (const [re, marker] of CONTAINER_PATTERNS) {
    if (re.test(source)) {
      add('container', marker);
    }
  }
  for (const [re, marker] of TTY_PATTERNS) {
    if (re.test(source)) {
      add('tty', marker);
    }
  }

  return hits;
}
