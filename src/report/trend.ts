/**
 * Static HTML trend report (0037, dashboard phase 1) — a self-contained page over a
 * directory of run records. No server, no auth, no external assets (same medium as
 * `--format md`); it is written to a file or piped, and opened in a browser. Pure:
 * records in, HTML string out.
 */

import type { RunRecord } from './run-record';

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const VERDICT_COLOR: Record<string, string> = {
  fail: '#c2410c',
  unknown: '#a16207',
  warn: '#a16207',
  pass: '#15803d',
};

/** An inline SVG sparkline of total findings per run, colored by that run's verdict. */
function sparkline(records: RunRecord[]): string {
  if (records.length === 0) {
    return '';
  }
  const w = 640;
  const h = 120;
  const pad = 8;
  const max = Math.max(1, ...records.map((r) => r.findingCount));
  const n = records.length;
  const barW = (w - pad * 2) / n;
  const bars = records
    .map((r, i) => {
      const bh = ((h - pad * 2) * r.findingCount) / max;
      const x = pad + i * barW;
      const y = h - pad - bh;
      const color = VERDICT_COLOR[r.verdict] ?? '#64748b';
      return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${(barW * 0.8).toFixed(1)}" height="${bh.toFixed(1)}" fill="${color}" rx="2"><title>${esc(r.timestamp)} — ${r.findingCount} finding(s), ${esc(r.verdict)}</title></rect>`;
    })
    .join('');
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-label="findings per run">${bars}</svg>`;
}

function rows(records: RunRecord[]): string {
  return [...records]
    .reverse() // newest first in the table
    .map((r) => {
      const color = VERDICT_COLOR[r.verdict] ?? '#64748b';
      return `<tr>
        <td class="mono">${esc(r.timestamp)}</td>
        <td><span class="badge" style="background:${color}">${esc(r.verdict.toUpperCase())}</span></td>
        <td class="num">${r.failCount}</td>
        <td class="num">${r.warnCount}</td>
        <td class="num">${r.findingCount}</td>
        <td class="mono">${esc(r.sha ?? '—')}</td>
      </tr>`;
    })
    .join('');
}

/** Render a self-contained HTML trend report over the given run records. */
export function renderTrendReport(records: RunRecord[]): string {
  const latest = records[records.length - 1];
  const summary = latest
    ? `Latest run: <b>${esc(latest.verdict.toUpperCase())}</b> · ${latest.failCount} fail · ${latest.warnCount} warn · ${records.length} run(s) recorded`
    : 'No runs recorded yet.';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blastgate — trend</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif; margin: 0; padding: 32px; max-width: 860px; margin-inline: auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #64748b; margin: 0 0 24px; }
  .card { border: 1px solid #cbd5e1; border-radius: 10px; padding: 20px; margin-bottom: 24px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
  .badge { color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  @media (prefers-color-scheme: dark) { .card { border-color: #334155; } th, td { border-color: #1e293b; } }
</style>
</head>
<body>
  <h1>🛡 Blastgate — trend</h1>
  <p class="sub">${summary}</p>
  <div class="card">${sparkline(records) || 'No runs to chart.'}</div>
  <table>
    <thead><tr><th>Recorded</th><th>Verdict</th><th class="num">Fail</th><th class="num">Warn</th><th class="num">Total</th><th>SHA</th></tr></thead>
    <tbody>${rows(records)}</tbody>
  </table>
</body>
</html>
`;
}
