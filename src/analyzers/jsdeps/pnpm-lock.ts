/**
 * Parse a `pnpm-lock.yaml` to a map of resolved package → version (0040).
 *
 * Like yarn, pnpm's lockfile does not carry npm's `hasInstallScript` flag, so an
 * added/bumped dep is treated as install-capable (RubyGems parity). Only the
 * resolved name→version set from the `packages:` map is needed for the diff.
 *
 * The `packages:` keys differ across lockfile versions — v5 `/@scope/name/1.2.3`,
 * v6 `/@scope/name@1.2.3(peer)`, v9 `@scope/name@1.2.3` — so `pkgFromKey`
 * normalizes all three, stripping any `(peer)` / `_peer` suffix. Non-registry
 * entries (git/file/link protocols, or any key without a digit-leading version)
 * are skipped — scoped to the common cases (see the ticket's design notes).
 */

import { parse } from 'yaml';

/** Normalize a pnpm `packages:` key to `{ pkg, version }` across v5/v6/v9 forms. */
export function pkgFromKey(key: string): { pkg: string; version: string } | null {
  // Strip a trailing peer-deps group `(react@18.0.0)` (v6/v9); names never contain '('.
  const k = key.replace(/\(.*\)$/, '');
  // v6/v9: [/]name@version  (scoped: /@scope/name@version)
  let m = /^\/?((?:@[^/]+\/)?[^/@][^/]*)@(\d[^@]*)$/.exec(k);
  if (m) {
    return { pkg: m[1]!, version: m[2]! };
  }
  // v5: /name/version  (scoped: /@scope/name/version, optional `_peer` suffix)
  m = /^\/((?:@[^/]+\/)?[^/]+)\/(\d[^/]*?)(?:_.*)?$/.exec(k);
  if (m) {
    return { pkg: m[1]!, version: m[2]! };
  }
  return null;
}

export function parsePnpmLock(content: string): Map<string, string> {
  const deps = new Map<string, string>();
  const doc = parse(content) as { packages?: Record<string, unknown> } | null;
  const packages = doc?.packages;
  if (!packages || typeof packages !== 'object') {
    return deps;
  }
  for (const key of Object.keys(packages)) {
    const parsed = pkgFromKey(key);
    if (parsed) {
      deps.set(parsed.pkg, parsed.version);
    }
  }
  return deps;
}
