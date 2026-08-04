export interface NpmrcFinding {
  key: string;
  value: string;
}

const SECURITY_KEYS = new Set([
  'registry',
  'ca',
  'cafile',
  'always-auth',
  '_auth',
  'proxy',
  'https-proxy',
]);

function isSecurityRelevant(key: string, value: string): boolean {
  if (key === 'strict-ssl') {
    return value === 'false'; // only a disabled TLS check is a signal
  }
  if (SECURITY_KEYS.has(key)) {
    return true;
  }
  return /:registry$/.test(key) || /_authToken$/.test(key);
}

/** Extract security-relevant `.npmrc` settings (registry redirects, MITM enablers, auth). */
export function parseNpmrc(content: string): NpmrcFinding[] {
  const findings: NpmrcFinding[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1) {
      continue;
    }
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (isSecurityRelevant(key, value)) {
      findings.push({ key, value });
    }
  }
  return findings;
}

/**
 * Security-relevant `.npmrc` settings newly present or changed vs. the base. With
 * no base (whole-repo mode) every security-relevant head setting is surfaced.
 */
export function diffNpmrc(
  base: string | null | undefined,
  head: string | null | undefined,
): NpmrcFinding[] {
  if (!head) {
    return [];
  }
  const headFindings = parseNpmrc(head);
  if (base === null || base === undefined) {
    return headFindings;
  }
  const baseMap = new Map(parseNpmrc(base).map((f) => [f.key, f.value]));
  return headFindings.filter((f) => baseMap.get(f.key) !== f.value);
}
