import { packageName, parsePackagesMap } from './lockfile';

export interface DepChange {
  pkg: string;
  version: string;
  change: 'added' | 'changed';
}

/**
 * Diff two package-lock.json `packages` maps by key (KTD5). A key in head but not
 * base is `added`; a key in both whose version / resolved / integrity differs is
 * `changed`. Offline, pure git+JSON.
 */
export function diffLockfiles(baseJson: string | null, headJson: string): DepChange[] {
  const head = parsePackagesMap(headJson);
  const base = baseJson ? parsePackagesMap(baseJson) : {};
  const changes: DepChange[] = [];
  for (const [path, h] of Object.entries(head)) {
    if (path === '') {
      continue;
    }
    const pkg = packageName(path);
    const version = h.version ?? '0.0.0';
    const b = base[path];
    if (!b) {
      changes.push({ pkg, version, change: 'added' });
    } else if (
      b.version !== h.version ||
      b.resolved !== h.resolved ||
      b.integrity !== h.integrity
    ) {
      changes.push({ pkg, version, change: 'changed' });
    }
  }
  return changes;
}
