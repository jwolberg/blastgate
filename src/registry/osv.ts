/**
 * OSV.dev advisory source (0036) — the production `AdvisorySource`. osv.dev is free,
 * keyless, and batchable; this is the only network touch besides `--provenance`, and
 * it runs solely under the opt-in `--advisories` flag. A non-OK response or a network
 * error yields no advisories (enrichment is best-effort and never breaks a scan).
 */

import type { Advisory } from '../findings/finding';
import type { AdvisorySource } from '../enrichment/advisories';

interface OsvVuln {
  id: string;
  summary?: string;
}

/** Query https://api.osv.dev/v1/query for advisories affecting a package (version if known). */
export function osvHttpSource(): AdvisorySource {
  return {
    async query(name, ecosystem, version) {
      const body = JSON.stringify({
        package: { name, ecosystem },
        ...(version ? { version } : {}),
      });
      let res: Response;
      try {
        res = await fetch('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
        });
      } catch {
        return [];
      }
      if (!res.ok) {
        return [];
      }
      const data = (await res.json()) as { vulns?: OsvVuln[] };
      return (data.vulns ?? []).map((v): Advisory => ({
        id: v.id,
        package: name,
        summary: v.summary,
      }));
    },
  };
}
