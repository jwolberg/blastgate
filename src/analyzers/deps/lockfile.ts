import type { DependencyNode } from '../../graph/types';

export interface LockPackage {
  version?: string;
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
}

interface Lockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
}

/** `node_modules/@scope/name` → `@scope/name`; the last node_modules segment wins for nested deps. */
export function packageName(nodeModulesPath: string): string {
  return nodeModulesPath.replace(/^.*node_modules\//, '');
}

/** A top-level dependency has exactly one `node_modules/` segment. */
function isDirectDependency(nodeModulesPath: string): boolean {
  return /^node_modules\/(@[^/]+\/)?[^/]+$/.test(nodeModulesPath);
}

export function parsePackagesMap(json: string): Record<string, LockPackage> {
  const data = JSON.parse(json) as Lockfile;
  return data.packages ?? {};
}

/**
 * Parse a package-lock.json (v2/v3 `packages` map) into dependency nodes. The
 * `hasInstallScript` flag is read straight from the lockfile — an offline signal,
 * no install and no network (KTD11). Throws on invalid JSON.
 */
export function parseLockfile(json: string): DependencyNode[] {
  const packages = parsePackagesMap(json);
  const nodes: DependencyNode[] = [];
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '') {
      continue; // the root project itself
    }
    const pkg = packageName(path);
    const version = entry.version ?? '0.0.0';
    nodes.push({
      id: `dep:${pkg}@${version}`,
      kind: 'dependency',
      pkg,
      version,
      isDirect: isDirectDependency(path),
      hasInstallScript: entry.hasInstallScript === true,
    });
  }
  return nodes;
}
