/**
 * npm registry packument access for the provenance-regression check (U8, KTD6).
 *
 * This is the *only* part of Blastgate that touches the network, and it runs only
 * behind the explicit `--provenance` flag — the dependency/CI/agent analyzers and
 * the reachability gate are fully offline. The `dist.attestations` presence is the
 * sole provenance primitive; a fetch failure is a soft null (never a gate fail).
 * The network is behind `PackumentSource` so tests run against recorded packuments.
 */

export interface Packument {
  versions?: Record<string, { dist?: { attestations?: unknown } }>;
}

/** The raw fetch boundary — the real one hits the registry; tests inject recordings. */
export interface PackumentSource {
  fetch(pkg: string): Promise<Packument | null>;
}

/** Provenance for a specific version: true/false if known, null if unknown (fetch failed / version absent). */
export function readProvenance(packument: Packument | null, version: string): boolean | null {
  if (!packument) {
    return null;
  }
  const entry = packument.versions?.[version];
  if (!entry) {
    return null;
  }
  return entry.dist?.attestations !== undefined;
}

export interface ProvenanceFetcher {
  hasProvenance(pkg: string, version: string): Promise<boolean | null>;
}

/**
 * Wrap a source with a per-package cache: one fetch serves every version of a
 * package, so a base+head check of the same `pkg` makes a single request.
 */
export function cachedFetcher(source: PackumentSource): ProvenanceFetcher {
  const cache = new Map<string, Promise<Packument | null>>();
  return {
    hasProvenance(pkg, version) {
      let pending = cache.get(pkg);
      if (!pending) {
        pending = source.fetch(pkg);
        cache.set(pkg, pending);
      }
      return pending.then((packument) => readProvenance(packument, version));
    },
  };
}

/** The live registry source: `GET https://registry.npmjs.org/<pkg>`; any failure → null (soft). */
export function httpSource(): PackumentSource {
  return {
    async fetch(pkg) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${pkg.replace(/\//g, '%2F')}`);
        if (!res.ok) {
          return null;
        }
        return (await res.json()) as Packument;
      } catch {
        return null;
      }
    },
  };
}
