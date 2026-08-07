/**
 * Parse a `yarn.lock` to a map of resolved package → version (0040).
 *
 * yarn's lockfile does not record whether a package runs install-time code (unlike
 * npm's `hasInstallScript`), so — like the RubyGems path — the analyzer cannot rule
 * install execution out offline and treats an added/bumped dep as install-capable.
 * This parser only needs the resolved name→version set for the base→head diff.
 *
 * A resolved block is an *unindented* header line of one or more comma-separated
 * descriptors ending in `:`, followed by an indented `version` line. This one shape
 * covers both yarn v1 "classic" (`version "1.3.0"`, descriptors `name@^1.0.0`) and
 * common Berry v2+ (`version: 1.3.0`, descriptors `"name@npm:^1.0.0"`). Exotic Berry
 * protocols (`@patch:`, `@workspace:`, git/file refs) may not yield a clean version
 * and are skipped — scoped to the common cases (see the ticket's design notes).
 */

/** The package name from a lockfile descriptor: `@scope/name@range` → `@scope/name`. */
function descriptorName(descriptor: string): string {
  const d = descriptor.trim().replace(/^"|"$/g, '');
  // Scoped names start with '@'; the range/protocol '@' is then the *second* '@'.
  const at = d.startsWith('@') ? d.indexOf('@', 1) : d.indexOf('@');
  return at === -1 ? '' : d.slice(0, at);
}

export function parseYarnLock(content: string): Map<string, string> {
  const deps = new Map<string, string>();
  let names: string[] = [];
  for (const line of content.split(/\r?\n/)) {
    if (line.trim() === '' || line.startsWith('#')) {
      continue;
    }
    // Unindented line = a new block header. Descriptors precede a trailing ':'.
    if (!/^\s/.test(line)) {
      names = line.endsWith(':')
        ? line
            .slice(0, -1)
            .split(',')
            .map(descriptorName)
            .filter((n) => n !== '')
        : [];
      continue;
    }
    // Indented `version` line (v1: `version "1.3.0"`, Berry: `version: 1.3.0`).
    const m = /^\s+version:?\s+"?(\d[^"\s]*)"?/.exec(line);
    if (m && names.length > 0) {
      for (const name of names) {
        deps.set(name, m[1]!);
      }
      names = [];
    }
  }
  return deps;
}
