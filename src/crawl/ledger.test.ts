import { describe, expect, it } from 'vitest';
import {
  DISCLOSURE_STATES,
  type DisclosureState,
  type Ledger,
  type ScanVerdict,
  applyScan,
  createDisclosure,
  delta,
  emptyLedger,
  expirePvrRequests,
  isRetryableHold,
  type Disclosure,
  lsRemoteHeads,
  parseLedger,
  recordWouldSend,
  recoverSubmitting,
  serializeLedger,
  setPvrRequest,
  transition,
  tripArchetype,
  UNCERTAIN_REASON,
} from './ledger';

const sha = (c: string): string => c.repeat(40);
const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-02T00:00:00.000Z';
const V = '0.9.0';

function scanned(
  ledger: Ledger,
  repo: string,
  s: string,
  v = V,
  verdict: ScanVerdict = 'pass',
  at = T0,
): Ledger {
  return applyScan(ledger, repo, {
    fullSha: s,
    engineVersion: v,
    verdict,
    scannedAt: at,
    failFindings: [],
  });
}

const base = (repo: string, ids: string[], state: 'held' | 'queued' = 'held') => ({
  repo,
  findingIds: ids,
  archetype: 'k',
  state,
  now: T0,
});

describe('parse / serialize', () => {
  it('round-trips without loss', () => {
    let l = emptyLedger();
    l = applyScan(l, 'b/two', {
      fullSha: sha('b'),
      engineVersion: V,
      verdict: 'fail',
      scannedAt: T0,
      failFindings: [{ id: 'e=>s', archetype: 'pr-title-injection' }],
    });
    l = scanned(l, 'a/one', sha('a'));
    l = createDisclosure(l, {
      repo: 'b/two',
      findingIds: ['e=>s'],
      archetype: 'pr-title-injection',
      state: 'held',
      now: T0,
    });
    const text = serializeLedger(l);
    expect(parseLedger(text)).toEqual(l);
    expect(serializeLedger(parseLedger(text))).toBe(text);
  });

  it('serializes with stable key order regardless of insertion order', () => {
    const a = scanned(scanned(emptyLedger(), 'z/z', sha('a')), 'a/a', sha('b'));
    const b = scanned(scanned(emptyLedger(), 'a/a', sha('b')), 'z/z', sha('a'));
    expect(serializeLedger(a)).toBe(serializeLedger(b));
    expect(serializeLedger(a).indexOf('"a/a"')).toBeLessThan(serializeLedger(a).indexOf('"z/z"'));
  });

  it('round-trips an empty ledger', () => {
    expect(parseLedger(serializeLedger(emptyLedger()))).toEqual(emptyLedger());
  });

  const goodScan = {
    fullSha: sha('a'),
    engineVersion: V,
    verdict: 'pass',
    scannedAt: T0,
    failFindings: [],
  };
  it.each([
    ['empty string', ''],
    ['not json', '{nope'],
    ['null', 'null'],
    ['array', '[]'],
    ['missing schemaVersion', '{"repos":{},"disclosures":[]}'],
    ['unknown schemaVersion', '{"schemaVersion":2,"repos":{},"disclosures":[]}'],
    ['missing repos', '{"schemaVersion":1,"disclosures":[]}'],
    [
      'bad sha',
      JSON.stringify({
        schemaVersion: 1,
        repos: { 'a/b': { ...goodScan, fullSha: 'abc' } },
        disclosures: [],
      }),
    ],
    [
      'bad verdict',
      JSON.stringify({
        schemaVersion: 1,
        repos: { 'a/b': { ...goodScan, verdict: 'great' } },
        disclosures: [],
      }),
    ],
    [
      'bad disclosure state',
      JSON.stringify({
        schemaVersion: 1,
        repos: {},
        disclosures: [
          {
            repo: 'a/b',
            findingIds: ['x'],
            archetype: 'k',
            state: 'sent',
            createdAt: T0,
            updatedAt: T0,
          },
        ],
      }),
    ],
  ])('throws loudly on malformed input: %s', (_name, text) => {
    expect(() => parseLedger(text)).toThrow();
  });
});

describe('PVR enable request record (0102)', () => {
  const key = { repo: 'a/b', findingIds: ['x'] };
  const l0 = createDisclosure(emptyLedger(), base('a/b', ['x'], 'queued'));

  it('round-trips through serialize/parse, pending then completed', () => {
    const pending = setPvrRequest(l0, key, { at: T0 }, T0);
    expect(parseLedger(serializeLedger(pending)).disclosures[0]?.pvrRequest).toEqual({ at: T0 });
    const done = setPvrRequest(
      pending,
      key,
      { at: T0, url: 'https://github.com/a/b/issues/1' },
      T1,
    );
    expect(parseLedger(serializeLedger(done)).disclosures[0]?.pvrRequest).toEqual({
      at: T0,
      url: 'https://github.com/a/b/issues/1',
    });
    const failed = setPvrRequest(pending, key, { at: T0, failedStatus: 410 }, T1);
    expect(parseLedger(serializeLedger(failed)).disclosures[0]?.pvrRequest).toEqual({
      at: T0,
      failedStatus: 410,
    });
  });

  it('rejects a malformed record', () => {
    const text = (pvrRequest: unknown) =>
      JSON.stringify({
        ...JSON.parse(serializeLedger(l0)),
        disclosures: [{ ...JSON.parse(serializeLedger(l0)).disclosures[0], pvrRequest }],
      });
    expect(() => parseLedger(text({}))).toThrow(/pvrRequest/);
    expect(() => parseLedger(text({ at: T0, url: 5 }))).toThrow(/pvrRequest/);
    expect(() => parseLedger(text({ at: T0, failedStatus: 'x' }))).toThrow(/pvrRequest/);
    expect(() => parseLedger(text({ at: T0, extra: 1 }))).toThrow(/pvrRequest/);
  });
});

describe('applyScan', () => {
  it('records the scan and does not mutate the input', () => {
    const l0 = emptyLedger();
    const l1 = scanned(l0, 'a/one', sha('a'));
    expect(l0.repos['a/one']).toBeUndefined();
    expect(l1.repos['a/one']?.verdict).toBe('pass');
  });

  it('rejects a non-40-char sha', () => {
    expect(() => scanned(emptyLedger(), 'a/one', 'abc123')).toThrow(/sha/i);
  });
});

describe('delta (R2)', () => {
  const cap = 100;

  it('AE1: unchanged sha + engine stay out of the delta', () => {
    const l = scanned(emptyLedger(), 'a/one', sha('a'));
    const d = delta(l, new Map([['a/one', sha('a')]]), V, cap);
    expect(d.selected).toEqual([]);
  });

  it('a changed sha is included', () => {
    const l = scanned(emptyLedger(), 'a/one', sha('a'), V, 'warn');
    const d = delta(l, new Map([['a/one', sha('b')]]), V, cap);
    expect(d.selected).toEqual([{ repo: 'a/one', reason: 'changed' }]);
  });

  it('a listed pass whose sha changed is re-vouched before new repos (AE6)', () => {
    const l = scanned(emptyLedger(), 'a/listed', sha('a'));
    const heads = new Map([
      ['a/new', sha('c')],
      ['a/listed', sha('b')],
    ]);
    const d = delta(l, heads, V, cap);
    expect(d.selected).toEqual([
      { repo: 'a/listed', reason: 'listed-pass-changed' },
      { repo: 'a/new', reason: 'new' },
    ]);
  });

  it('a new repo is included', () => {
    const d = delta(emptyLedger(), new Map([['a/new', sha('a')]]), V, cap);
    expect(d.selected).toEqual([{ repo: 'a/new', reason: 'new' }]);
  });

  it('a listed pass on an older engine comes before new repos', () => {
    const l = scanned(emptyLedger(), 'a/old', sha('a'), '0.8.0');
    const heads = new Map([
      ['a/new', sha('c')],
      ['a/old', sha('a')],
    ]);
    const d = delta(l, heads, V, cap);
    expect(d.selected).toEqual([
      { repo: 'a/old', reason: 'listed-pass-old-engine' },
      { repo: 'a/new', reason: 'new' },
    ]);
  });

  it('a non-pass on an older engine is rescanned as old-engine', () => {
    const l = scanned(emptyLedger(), 'a/warned', sha('a'), '0.8.0', 'warn');
    const d = delta(l, new Map([['a/warned', sha('a')]]), V, cap);
    expect(d.selected).toEqual([{ repo: 'a/warned', reason: 'old-engine' }]);
  });

  it('orders listed, new, then oldest-scanned; the cap keeps the highest priority', () => {
    let l = scanned(emptyLedger(), 'a/older', sha('1'), V, 'warn', '2026-01-01T00:00:00.000Z');
    l = scanned(l, 'a/newer', sha('2'), V, 'warn', '2026-06-01T00:00:00.000Z');
    l = scanned(l, 'a/listed', sha('3'), '0.1.0', 'pass', '2026-09-01T00:00:00.000Z');
    const heads = new Map([
      ['a/older', sha('9')],
      ['a/newer', sha('9')],
      ['a/listed', sha('3')],
      ['a/fresh', sha('9')],
    ]);
    expect(delta(l, heads, V, 10).selected.map((s) => s.repo)).toEqual([
      'a/listed',
      'a/fresh',
      'a/older',
      'a/newer',
    ]);
    const capped = delta(l, heads, V, 2);
    expect(capped.selected.map((s) => s.repo)).toEqual(['a/listed', 'a/fresh']);
    expect(capped.deferred).toBe(2);
    expect(delta(l, heads, V, 0).selected).toEqual([]);
  });

  it('skips and reports a repo whose head is null', () => {
    const l = scanned(emptyLedger(), 'a/one', sha('a'));
    const heads = new Map<string, string | null>([
      ['a/one', null],
      ['a/new', null],
    ]);
    const d = delta(l, heads, V, cap);
    expect(d.selected).toEqual([]);
    expect([...d.skipped].sort()).toEqual(['a/new', 'a/one']);
  });

  it('handles an empty ledger and empty heads', () => {
    expect(delta(emptyLedger(), new Map(), V, cap)).toEqual({
      selected: [],
      skipped: [],
      deferred: 0,
    });
  });
});

describe('disclosure transitions (KTD4/KTD6)', () => {
  const key = { repo: 'a/one', findingIds: ['f1', 'f2'] };
  const mk = (state: 'held' | 'queued' = 'held'): Ledger =>
    createDisclosure(emptyLedger(), base('a/one', ['f1', 'f2'], state));

  it('held -> queued is allowed and bumps updatedAt only', () => {
    const l = transition(mk(), key, 'queued', { now: T1 });
    expect(l.disclosures[0]?.state).toBe('queued');
    expect(l.disclosures[0]?.updatedAt).toBe(T1);
    expect(l.disclosures[0]?.createdAt).toBe(T0);
  });

  it('matches the disclosure regardless of finding id order', () => {
    const l = transition(mk(), { repo: 'a/one', findingIds: ['f2', 'f1'] }, 'queued', { now: T1 });
    expect(l.disclosures[0]?.state).toBe('queued');
  });

  it('submitted -> queued is rejected', () => {
    let l = mk('queued');
    l = transition(l, key, 'submitting', { now: T0 });
    l = transition(l, key, 'submitted', { now: T0, reportUrl: 'https://x/y' });
    expect(l.disclosures[0]?.reportUrl).toBe('https://x/y');
    expect(() => transition(l, key, 'queued', { now: T1 })).toThrow(/illegal/i);
  });

  it('submitted requires a reportUrl', () => {
    const l = transition(mk('queued'), key, 'submitting', { now: T0 });
    expect(() => transition(l, key, 'submitted', { now: T1 })).toThrow(/reportUrl/);
  });

  it('published-credited can record a ghsaId', () => {
    let l = transition(mk('queued'), key, 'submitting', { now: T0 });
    l = transition(l, key, 'submitted', { now: T0, reportUrl: 'u' });
    l = transition(l, key, 'published-credited', { now: T1, ghsaId: 'GHSA-aaaa-bbbb-cccc' });
    expect(l.disclosures[0]?.ghsaId).toBe('GHSA-aaaa-bbbb-cccc');
  });

  it('throws for an unknown disclosure', () => {
    expect(() =>
      transition(mk(), { repo: 'x/y', findingIds: ['f1'] }, 'queued', { now: T1 }),
    ).toThrow(/no disclosure/i);
  });

  it('illegal transition matrix: only the documented edges pass', () => {
    const allowed: Record<DisclosureState, DisclosureState[]> = {
      held: ['queued', 'resolved-before-report'],
      queued: ['held', 'submitting', 'resolved-before-report'],
      submitting: ['submitted', 'held'],
      submitted: ['fixed', 'declined', 'published-credited'],
      fixed: ['published-credited'],
      declined: [],
      'published-credited': [],
      'resolved-before-report': [],
    };
    for (const from of DISCLOSURE_STATES) {
      for (const to of DISCLOSURE_STATES) {
        const l: Ledger = {
          ...emptyLedger(),
          disclosures: [
            {
              repo: 'a/one',
              findingIds: ['f1', 'f2'],
              archetype: 'k',
              state: from,
              reportUrl: 'u',
              createdAt: T0,
              updatedAt: T0,
            },
          ],
        };
        const run = () => transition(l, key, to, { now: T1, reportUrl: 'u', reason: 'r' });
        if (allowed[from].includes(to)) expect(run, `${from}->${to}`).not.toThrow();
        else expect(run, `${from}->${to}`).toThrow(/illegal/i);
      }
    }
  });
});

describe('recoverSubmitting (AE7)', () => {
  it('turns submitting into held with the uncertain reason and leaves others alone', () => {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1'], 'queued'));
    l = createDisclosure(l, base('b/two', ['g1'], 'queued'));
    l = transition(l, { repo: 'a/one', findingIds: ['f1'] }, 'submitting', { now: T0 });
    const r = recoverSubmitting(l, T1);
    const a = r.disclosures.find((d) => d.repo === 'a/one');
    expect(a?.state).toBe('held');
    expect(a?.reason).toBe('submission state uncertain');
    expect(a?.updatedAt).toBe(T1);
    expect(r.disclosures.find((d) => d.repo === 'b/two')?.state).toBe('queued');
  });

  it('is a no-op on a ledger with nothing submitting', () => {
    const l = createDisclosure(emptyLedger(), base('a/one', ['f1']));
    expect(recoverSubmitting(l, T1)).toEqual(l);
  });
});

describe('duplicate guard (KTD6.5)', () => {
  it('rejects a disclosure overlapping finding ids already submitted for that repo', () => {
    const k = { repo: 'a/one', findingIds: ['f1', 'f2'] };
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1', 'f2'], 'queued'));
    l = transition(l, k, 'submitting', { now: T0 });
    l = transition(l, k, 'submitted', { now: T0, reportUrl: 'u' });
    expect(() => createDisclosure(l, base('a/one', ['f2', 'f3'], 'queued'))).toThrow(/already/i);
  });

  it('also rejects while submitting or after recovery to held (may have been filed)', () => {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1'], 'queued'));
    l = transition(l, { repo: 'a/one', findingIds: ['f1'] }, 'submitting', { now: T0 });
    expect(() => createDisclosure(l, base('a/one', ['f1'], 'queued'))).toThrow();
    expect(() => createDisclosure(recoverSubmitting(l, T1), base('a/one', ['f1']))).toThrow();
  });

  it('allows the same ids on a different repo, and different ids on the same repo', () => {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1']));
    l = createDisclosure(l, base('b/two', ['f1']));
    l = createDisclosure(l, base('a/one', ['f9']));
    expect(l.disclosures).toHaveLength(3);
  });

  it('allows a new disclosure after resolved-before-report', () => {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1']));
    l = transition(l, { repo: 'a/one', findingIds: ['f1'] }, 'resolved-before-report', { now: T0 });
    expect(() => createDisclosure(l, base('a/one', ['f1']))).not.toThrow();
  });

  it('only held or queued are valid initial states, and ids must be non-empty', () => {
    expect(() =>
      createDisclosure(emptyLedger(), { ...base('a/one', ['f1']), state: 'submitted' as never }),
    ).toThrow();
    expect(() => createDisclosure(emptyLedger(), base('a/one', []))).toThrow();
  });
});

describe('lsRemoteHeads', () => {
  it('resolves heads with an injected exec and nulls failures', async () => {
    const calls: string[][] = [];
    const exec = async (args: string[]): Promise<string> => {
      calls.push(args);
      if (args.some((a) => a.includes('/bad/repo'))) throw new Error('boom');
      if (args.some((a) => a.includes('/empty/repo'))) return '';
      return `${sha('d')}\tHEAD\n`;
    };
    const heads = await lsRemoteHeads(['ok/repo', 'bad/repo', 'empty/repo'], {
      exec,
      concurrency: 2,
    });
    expect(heads.get('ok/repo')).toBe(sha('d'));
    expect(heads.get('bad/repo')).toBeNull();
    expect(heads.get('empty/repo')).toBeNull();
    expect(calls).toHaveLength(3);
  });

  it('bounds concurrency', async () => {
    let inFlight = 0;
    let peak = 0;
    const exec = async (): Promise<string> => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return `${sha('d')}\tHEAD\n`;
    };
    const repos = Array.from({ length: 12 }, (_, i) => `o/r${i}`);
    const heads = await lsRemoteHeads(repos, { exec, concurrency: 3 });
    expect(heads.size).toBe(12);
    expect(peak).toBeLessThanOrEqual(3);
  });

  it('refuses a name that is not a plain owner/repo without calling exec', async () => {
    let called = 0;
    const exec = async (): Promise<string> => {
      called++;
      return '';
    };
    const heads = await lsRemoteHeads(['--upload-pack=x/y', '../x', 'owner/..', 'owner/.'], {
      exec,
      concurrency: 1,
    });
    expect(called).toBe(0);
    expect(heads.get('--upload-pack=x/y')).toBeNull();
    expect(heads.get('owner/..')).toBeNull();
    expect(heads.get('owner/.')).toBeNull();
  });
});

describe('tripped archetypes (KTD6.2 tripwire)', () => {
  it('tripArchetype adds a sorted, unique entry and does not mutate', () => {
    const l0 = emptyLedger();
    const l1 = tripArchetype(tripArchetype(l0, 'zeta', T0), 'alpha', T0);
    const l2 = tripArchetype(l1, 'alpha', T1);
    expect(l1.trippedArchetypes).toEqual(['alpha', 'zeta']);
    expect(l2.trippedArchetypes).toEqual(['alpha', 'zeta']);
    expect(l0.trippedArchetypes).toBeUndefined();
  });

  it('round-trips, and a ledger without the key parses as untripped (backward compatible)', () => {
    const l = tripArchetype(emptyLedger(), 'b', T0);
    expect(parseLedger(serializeLedger(l)).trippedArchetypes).toEqual(['b']);
    expect(serializeLedger(emptyLedger())).not.toContain('trippedArchetypes');
    const old = '{"schemaVersion":1,"repos":{},"disclosures":[]}';
    expect(parseLedger(old).trippedArchetypes ?? []).toEqual([]);
  });

  it('rejects a malformed trippedArchetypes', () => {
    const bad = '{"schemaVersion":1,"repos":{},"disclosures":[],"trippedArchetypes":"x"}';
    expect(() => parseLedger(bad)).toThrow(/trippedArchetypes/);
  });
});

describe('wouldSend (dry-run record)', () => {
  const body = { summary: 's', description: 'd', severity: 'high', vulnerabilities: [] };

  it('records the body on a queued disclosure and round-trips it', () => {
    let l = createDisclosure(emptyLedger(), base('a/b', ['x'], 'queued'));
    l = recordWouldSend(l, { repo: 'a/b', findingIds: ['x'] }, body, T1);
    expect(l.disclosures[0]?.wouldSend).toEqual(body);
    expect(l.disclosures[0]?.state).toBe('queued');
    expect(l.disclosures[0]?.updatedAt).toBe(T1);
    expect(parseLedger(serializeLedger(l))).toEqual(l);
  });

  it('refuses a non-queued disclosure and a malformed stored value', () => {
    const l = createDisclosure(emptyLedger(), base('a/b', ['x'], 'held'));
    expect(() => recordWouldSend(l, { repo: 'a/b', findingIds: ['x'] }, body, T1)).toThrow();
    const q = recordWouldSend(
      createDisclosure(emptyLedger(), base('a/b', ['x'], 'queued')),
      { repo: 'a/b', findingIds: ['x'] },
      body,
      T1,
    );
    const bad = JSON.parse(serializeLedger(q));
    bad.disclosures[0].wouldSend = 'nope';
    expect(() => parseLedger(JSON.stringify(bad))).toThrow(/wouldSend/);
  });
});

describe('re-detected finding after resolved-before-report (review #1)', () => {
  const key = { repo: 'a/one', findingIds: ['f1'] };

  function resolvedThenRedetected(): Ledger {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1'], 'queued'));
    l = transition(l, key, 'resolved-before-report', { now: T0 });
    return createDisclosure(l, { ...base('a/one', ['f1'], 'queued'), now: T1 });
  }

  it('transition works on the live entry, not the earlier terminal one', () => {
    let l = resolvedThenRedetected();
    l = transition(l, key, 'submitting', { now: T1 });
    l = transition(l, key, 'submitted', { now: T1, reportUrl: 'https://example.test/r' });
    expect(l.disclosures.map((d) => d.state)).toEqual(['resolved-before-report', 'submitted']);
  });

  it('recordWouldSend works on the live entry', () => {
    const l = recordWouldSend(resolvedThenRedetected(), key, { summary: 's' }, T1);
    expect(l.disclosures.map((d) => d.state)).toEqual(['resolved-before-report', 'queued']);
    expect(l.disclosures[1]?.wouldSend).toEqual({ summary: 's' });
    expect(l.disclosures[0]?.wouldSend).toBeUndefined();
  });

  it('with only the terminal entry left, a move is still refused', () => {
    let l = createDisclosure(emptyLedger(), base('a/one', ['f1'], 'queued'));
    l = transition(l, key, 'resolved-before-report', { now: T0 });
    expect(() => transition(l, key, 'submitting', { now: T1 })).toThrow(/illegal move/);
  });
});

describe('delta: pending disclosures (review #2)', () => {
  const failScan = (l: Ledger, repo: string, ids: string[], s = sha('a')): Ledger =>
    applyScan(l, repo, {
      fullSha: s,
      engineVersion: V,
      verdict: 'fail',
      scannedAt: T0,
      failFindings: ids.map((id) => ({ id, archetype: 'k' })),
    });
  const heads = (repo: string, s = sha('a')) => new Map([[repo, s]]);
  const withDisclosure = (state: DisclosureState, reason?: string, ids = ['f1']): Ledger => {
    let l = failScan(emptyLedger(), 'a/one', ids);
    l = createDisclosure(l, { ...base('a/one', ids, 'held') });
    const key = { repo: 'a/one', findingIds: ids };
    const to = (s: DisclosureState, o: Partial<{ reason: string; reportUrl: string }> = {}) => {
      l = transition(l, key, s, { now: T1, ...o });
    };
    if (state === 'held') {
      if (reason) l = { ...l, disclosures: l.disclosures.map((d) => ({ ...d, reason })) };
    } else if (state === 'queued') to('queued');
    else if (state === 'resolved-before-report') to('resolved-before-report');
    else {
      to('queued');
      to('submitting');
      if (state === 'submitted' || state === 'fixed' || state === 'declined') {
        to('submitted', { reportUrl: 'https://example.test/r' });
        if (state !== 'submitted') to(state);
      }
    }
    return l;
  };
  const sel = (l: Ledger) => delta(l, heads('a/one'), V, 100).selected;

  it('re-queues an unchanged fail repo whose disclosure is queued', () => {
    expect(sel(withDisclosure('queued'))).toEqual([
      { repo: 'a/one', reason: 'pending-disclosure' },
    ]);
  });

  it.each(['no PVR', 'no PVR (HTTP 403)', 'archetype not allowlisted', 'rate limited (HTTP 429)'])(
    're-queues a fail repo held for the retryable reason "%s"',
    (reason) => {
      expect(sel(withDisclosure('held', reason))).toEqual([
        { repo: 'a/one', reason: 'pending-disclosure' },
      ]);
    },
  );

  it.each([UNCERTAIN_REASON, 'submission failed (HTTP 500)', 'duplicate'])(
    'does not re-queue a fail repo held for the non-retryable reason "%s"',
    (reason) => {
      expect(sel(withDisclosure('held', reason))).toEqual([]);
    },
  );

  it.each(['submitted', 'fixed', 'declined', 'resolved-before-report'] as const)(
    'does not re-queue a fail repo whose disclosure is %s',
    (state) => {
      expect(sel(withDisclosure(state))).toEqual([]);
    },
  );

  it('re-queues a fail repo with finding ids no disclosure covers yet', () => {
    expect(sel(failScan(emptyLedger(), 'a/one', ['f1']))).toEqual([
      { repo: 'a/one', reason: 'pending-disclosure' },
    ]);
    // one id covered by a final disclosure, the other not
    const partial = withDisclosure('held', UNCERTAIN_REASON, ['f1']);
    const l = failScan(partial, 'a/one', ['f1', 'f2']);
    expect(sel(l)).toEqual([{ repo: 'a/one', reason: 'pending-disclosure' }]);
  });

  it('never re-queues an unchanged non-fail repo', () => {
    expect(sel(scanned(emptyLedger(), 'a/one', sha('a'), V, 'warn'))).toEqual([]);
  });

  it('ranks after listed passes and before new repos', () => {
    let l = withDisclosure('queued');
    l = scanned(l, 'a/listed', sha('c'), '0.1.0');
    const hs = new Map([
      ['a/new', sha('d')],
      ['a/one', sha('a')],
      ['a/listed', sha('c')],
    ]);
    expect(delta(l, hs, V, 100).selected.map((s) => s.repo)).toEqual([
      'a/listed',
      'a/one',
      'a/new',
    ]);
  });
});

describe('expirePvrRequests (0106)', () => {
  const DAY = 86_400_000;
  const asked = (reason: string, at = T0, repo = 'o/r', ids = ['o/r#1']): Ledger => {
    let l = createDisclosure(emptyLedger(), {
      repo,
      findingIds: ids,
      archetype: 'a',
      state: 'held',
      reason,
      now: at,
    });
    l = setPvrRequest(
      l,
      { repo, findingIds: ids },
      { at, url: `https://github.com/${repo}/issues/1` },
      at,
    );
    return l;
  };
  const at = (days: number): string => new Date(Date.parse(T0) + days * DAY).toISOString();

  it('leaves a request inside the TTL alone', () => {
    const l = asked('no PVR (enable requested)');
    expect(expirePvrRequests(l, at(89), 90)).toBe(l);
  });

  it('past the TTL the hold becomes final and the repo is no longer pending', () => {
    let l = asked('no PVR (enable requested)');
    l = applyScan(l, 'o/r', {
      fullSha: sha('a'),
      engineVersion: V,
      verdict: 'fail',
      scannedAt: T0,
      failFindings: [{ id: 'o/r#1', archetype: 'a' }],
    });
    const heads = new Map([['o/r', sha('a')]]);
    expect(delta(l, heads, V, 10).selected).toHaveLength(1);
    const x = expirePvrRequests(l, at(91), 90);
    expect(x.disclosures[0]).toMatchObject({ state: 'held', reason: 'no PVR (request expired)' });
    expect(isRetryableHold(x.disclosures[0] as Disclosure)).toBe(false);
    expect(delta(x, heads, V, 10).selected).toHaveLength(0);
  });

  it('also expires a failed request and every other no-PVR hold on that repo', () => {
    let l = asked('no PVR (enable request failed: HTTP 410)');
    l = createDisclosure(l, {
      repo: 'o/r',
      findingIds: ['o/r#2'],
      archetype: 'b',
      state: 'held',
      reason: 'no PVR (enable requested)',
      now: at(80),
    });
    const x = expirePvrRequests(l, at(91), 90);
    expect(x.disclosures.map((d) => d.reason)).toEqual([
      'no PVR (request expired)',
      'no PVR (request expired)',
    ]);
  });

  it('never touches other states, other reasons, or repos never asked', () => {
    let l = asked('not approved at this commit');
    l = createDisclosure(l, {
      repo: 'o/other',
      findingIds: ['x'],
      archetype: 'a',
      state: 'held',
      reason: 'no PVR',
      now: T0,
    });
    expect(expirePvrRequests(l, at(400), 90)).toBe(l);
  });
});
