/**
 * Static registry site (U7, R5/R6/R9, KTD5/KTD8) — a self-contained page listing ONLY repos whose
 * latest scan is `pass`, plus credited advisories. Pure: ledger in, files map out (the publisher
 * writes it). No client JS, no external assets, no counts, and no mention of any non-pass repo:
 * a repo that stops passing simply is not rendered, so the published history never shows a removal.
 */

import type { Ledger } from './ledger';

export interface SiteOptions {
  /** Shown as the page's "Updated" date; the only timestamp in the output. */
  generatedAt: string;
  /** If given, passes for repos outside this set are omitted (no longer discovered). */
  discovered?: ReadonlySet<string>;
}

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Date part of an ISO timestamp; falls back to the raw string. */
const day = (iso: string): string => /^\d{4}-\d{2}-\d{2}/.exec(iso)?.[0] ?? iso;

const byName = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const STYLE = `
:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--link:#0969da}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--link:#4493f8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:46rem;margin:0 auto;padding:1.5rem 16px 3rem}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:2rem 0 .5rem}
a{color:var(--link)}
.muted{color:var(--muted);font-size:.9rem}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:.85rem;color:var(--muted);font-weight:600}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
`.trim();

const METHOD = `<section id="method">
<h2>What a pass means</h2>
<p>A pass means no proven attacker path to a secret or code-write credential was found at that commit, as of that date, by that engine version. It is not a security guarantee.</p>
<p>Failures are reported privately to maintainers and never published.</p>
</section>`;

export function renderSite(ledger: Ledger, opts: SiteOptions): Record<string, string> {
  const passes = Object.keys(ledger.repos)
    .filter((repo) => ledger.repos[repo]?.verdict === 'pass')
    .filter((repo) => opts.discovered === undefined || opts.discovered.has(repo))
    .sort(byName);

  const passRows = passes
    .map((repo) => {
      const s = ledger.repos[repo];
      if (!s) return '';
      const r = esc(repo);
      return `<tr><td><a href="https://github.com/${r}">${r}</a></td><td class="mono"><a href="https://github.com/${r}/commit/${esc(s.fullSha)}">${esc(s.fullSha.slice(0, 7))}</a></td><td>${esc(day(s.scannedAt))}</td><td class="mono">${esc(s.engineVersion)}</td></tr>`;
    })
    .join('\n');

  const advisories = ledger.disclosures
    .filter((d) => d.state === 'published-credited' && d.ghsaId !== undefined)
    .map((d) => ({ repo: d.repo, ghsaId: d.ghsaId as string }))
    .sort((a, b) => byName(a.repo, b.repo) || byName(a.ghsaId, b.ghsaId));

  const advisoryRows = advisories
    .map((a) => {
      const r = esc(a.repo);
      const g = esc(a.ghsaId);
      const href = `https://github.com/${r}/security/advisories/${esc(encodeURIComponent(a.ghsaId))}`;
      return `<tr><td><a href="https://github.com/${r}">${r}</a></td><td class="mono"><a href="${href}">${g}</a></td></tr>`;
    })
    .join('\n');

  const passSection =
    passes.length === 0
      ? '<p class="muted">No repositories listed yet.</p>'
      : `<div class="wrap"><table>
<thead><tr><th>Repository</th><th>Commit</th><th>Scan date</th><th>Engine</th></tr></thead>
<tbody>
${passRows}
</tbody>
</table></div>`;

  const advisorySection =
    advisories.length === 0
      ? ''
      : `<section id="advisories">
<h2>Credited advisories</h2>
<div class="wrap"><table>
<thead><tr><th>Repository</th><th>Advisory</th></tr></thead>
<tbody>
${advisoryRows}
</tbody>
</table></div>
</section>`;

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blastgate registry</title>
<style>
${STYLE}
</style>
</head>
<body>
<main>
<h1>Blastgate registry</h1>
<p class="muted">Updated ${esc(day(opts.generatedAt))}</p>
<section id="passes">
<h2>Passing repositories</h2>
${passSection}
</section>
${advisorySection}
${METHOD}
</main>
</body>
</html>
`;
  return { 'index.html': html };
}
