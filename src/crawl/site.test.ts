import { describe, expect, it } from 'vitest';
import {
  applyScan,
  createDisclosure,
  emptyLedger,
  type Ledger,
  type ScanVerdict,
  transition,
} from './ledger';
import { renderSite } from './site';

const GEN = '2026-10-01T12:00:00Z';
const sha = (c: string): string => c.repeat(40);

function scanned(
  ledger: Ledger,
  repo: string,
  verdict: ScanVerdict,
  c = 'a',
  at = '2026-09-30T08:00:00Z',
): Ledger {
  return applyScan(ledger, repo, {
    fullSha: sha(c),
    engineVersion: '0.9.1',
    verdict,
    scannedAt: at,
    failFindings: [],
  });
}

function mixed(): Ledger {
  let l = emptyLedger();
  l = scanned(l, 'good/zeta', 'pass', 'b');
  l = scanned(l, 'good/alpha', 'pass', 'c');
  l = scanned(l, 'badco/warnrepo', 'warn');
  l = scanned(l, 'badco/failrepo', 'fail');
  l = scanned(l, 'badco/unkrepo', 'unknown');
  l = scanned(l, 'badco/clonerepo', 'clone-failed');
  return l;
}

const site = (l: Ledger, opts: { discovered?: ReadonlySet<string> } = {}): string =>
  renderSite(l, { generatedAt: GEN, ...opts })['index.html'] as string;

const METHOD_RE = /<section id="method">[\s\S]*?<\/section>/;

/** The page minus the fixed method copy, where nothing negative may appear. */
function outsideMethod(html: string): string {
  return html.replace(METHOD_RE, '');
}

function credited(l: Ledger, repo: string, id: string, ghsaId: string, final: boolean): Ledger {
  let out = createDisclosure(l, {
    repo,
    findingIds: [id],
    archetype: 'x',
    state: 'queued',
    now: GEN,
  });
  const key = { repo, findingIds: [id] };
  out = transition(out, key, 'submitting', { now: GEN });
  out = transition(out, key, 'submitted', { now: GEN, reportUrl: 'https://x/y', ghsaId });
  if (final) out = transition(out, key, 'published-credited', { now: GEN });
  return out;
}

describe('renderSite', () => {
  it('returns a single index.html file with the title', () => {
    const files = renderSite(mixed(), { generatedAt: GEN });
    expect(Object.keys(files)).toEqual(['index.html']);
    expect(files['index.html']).toContain('<title>Blastgate registry</title>');
  });

  it('renders only pass repos, linked, with short sha, date, engine version (AE2)', () => {
    const html = site(mixed());
    expect(html).toContain('<a href="https://github.com/good/alpha">good/alpha</a>');
    expect(html).toContain('<a href="https://github.com/good/zeta">good/zeta</a>');
    expect(html).toContain(
      `<a href="https://github.com/good/alpha/commit/${sha('c')}">ccccccc</a>`,
    );
    expect(html).toContain('2026-09-30');
    expect(html).toContain('0.9.1');
    expect(html.indexOf('good/alpha')).toBeLessThan(html.indexOf('good/zeta'));
    for (const hidden of ['warnrepo', 'failrepo', 'unkrepo', 'clonerepo', 'badco']) {
      expect(html).not.toContain(hidden);
    }
  });

  it('omits a repo whose latest scan is a fail after an earlier pass (AE6)', () => {
    let l = scanned(emptyLedger(), 'good/flip', 'pass', 'a');
    l = scanned(l, 'good/flip', 'fail', 'b');
    expect(site(l)).not.toContain('good/flip');
  });

  it('lists only published-credited advisories', () => {
    let l = emptyLedger();
    l = credited(l, 'own/submitted', 'F0', 'GHSA-aaaa-bbbb-cc00', false);
    l = credited(l, 'own/credited', 'F1', 'GHSA-aaaa-bbbb-cc01', true);
    l = createDisclosure(l, {
      repo: 'own/held',
      findingIds: ['F2'],
      archetype: 'x',
      state: 'held',
      now: GEN,
    });
    const html = site(l);
    expect(html).toContain(
      '<a href="https://github.com/own/credited/security/advisories/GHSA-aaaa-bbbb-cc01">GHSA-aaaa-bbbb-cc01</a>',
    );
    expect(html).toContain('own/credited');
    for (const r of ['own/submitted', 'own/held', 'cc00']) {
      expect(html).not.toContain(r);
    }
  });

  it('escapes HTML metacharacters in every field', () => {
    let l = emptyLedger();
    l = applyScan(l, 'a<b>/"c&d', {
      fullSha: sha('d'),
      engineVersion: '<script>1</script>',
      verdict: 'pass',
      scannedAt: '2026-09-30"><img src=x>',
      failFindings: [],
    });
    l = credited(l, 'o<x>/r&', 'F', 'GHSA"><b>', true);
    const html = site(l);
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<img');
    expect(html).not.toContain('<b>');
    expect(html).not.toContain('a<b>');
    expect(html).toContain('a&lt;b&gt;/&quot;c&amp;d');
    expect(html).toContain('&lt;script&gt;1&lt;/script&gt;');
  });

  it('is byte-identical across renders regardless of insertion order', () => {
    const a = mixed();
    const b = scanned(scanned(emptyLedger(), 'good/alpha', 'pass', 'c'), 'good/zeta', 'pass', 'b');
    expect(site(a)).toBe(site(a));
    expect(site(a)).toBe(site(b));
  });

  it('drops passes not in the discovered set, keeps them when none is given', () => {
    const l = mixed();
    const html = site(l, { discovered: new Set(['good/alpha']) });
    expect(html).toContain('good/alpha');
    expect(html).not.toContain('good/zeta');
    expect(site(l)).toContain('good/zeta');
  });

  it('shows no negative wording or counts outside the fixed method copy', () => {
    const body = outsideMethod(site(mixed())).toLowerCase();
    for (const word of ['fail', 'warn', 'unknown', 'scanned', 'privately', 'clone']) {
      expect(body).not.toContain(word);
    }
    expect(body).not.toMatch(/\b\d+\s+(repos?|repositories|passes)\b/);
  });

  it('states the pass meaning and private-failure policy in the method section', () => {
    const html = site(mixed());
    const method = METHOD_RE.exec(html)?.[0] ?? '';
    expect(method).toContain('no proven attacker path to a secret or code-write credential');
    expect(method).toContain('at that commit, as of that date, by that engine version');
    expect(method).toContain('not a security guarantee');
    expect(method).toContain('reported privately to maintainers and never published');
    expect(html.split('privately').length - 1).toBe(1);
  });

  it('has light/dark styles, a viewport meta, and no external assets or scripts', () => {
    const html = site(mixed());
    expect(html).toContain('prefers-color-scheme: dark');
    expect(html).toContain('name="viewport"');
    expect(html).not.toMatch(/<script|<link|src=/);
    const urls = html.match(/https?:\/\/[^"'\s<)]+/g) ?? [];
    expect(urls.every((u) => u.startsWith('https://github.com/'))).toBe(true);
  });

  it('renders an empty registry without throwing', () => {
    expect(site(emptyLedger())).toContain('Blastgate registry');
  });
});
