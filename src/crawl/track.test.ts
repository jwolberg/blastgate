import { describe, expect, it } from 'vitest';
import { type HttpRequest, type HttpResponse, createGitHubClient } from './github';
import { type Ledger, createDisclosure, emptyLedger, transition } from './ledger';
import { trackAll } from './track';

const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-05T00:00:00.000Z';
const ME = 'blastgate-bot';
const URL_A = 'https://github.com/acme/widgets/security/advisories/GHSA-aaaa-bbbb-cccc';
const API_A = 'https://api.github.com/repos/acme/widgets/security-advisories/GHSA-aaaa-bbbb-cccc';
const KEY = { repo: 'acme/widgets', findingIds: ['f1'] };

type Routes = Record<string, { status: number; json: unknown }>;

function submitted(repo = 'acme/widgets', ids = ['f1'], url = URL_A, archetype = 'arch-x'): Ledger {
  let l = createDisclosure(emptyLedger(), {
    repo,
    findingIds: ids,
    archetype,
    state: 'queued',
    now: T0,
  });
  const key = { repo, findingIds: ids };
  l = transition(l, key, 'submitting', { now: T0 });
  return transition(l, key, 'submitted', { now: T0, reportUrl: url });
}

async function run(ledger: Ledger, routes: Routes, currentFails?: Map<string, Set<string>>) {
  const seen: HttpRequest[] = [];
  const transport = async (req: HttpRequest): Promise<HttpResponse> => {
    seen.push(req);
    const r = routes[req.url] ?? { status: 404, json: { message: 'Not Found' } };
    return { status: r.status, headers: {}, json: r.json };
  };
  const client = createGitHubClient({ transport, now: () => 0, sleep: async () => {} });
  const res = await trackAll({ ledger, client, reporterLogin: ME, now: T1, currentFails });
  return { ...res, seen };
}

const credited = {
  state: 'published',
  ghsa_id: 'GHSA-aaaa-bbbb-cccc',
  credits_detailed: [{ user: { login: 'Blastgate-Bot' }, type: 'reporter', state: 'accepted' }],
};

describe('trackAll (R9, KTD6.2)', () => {
  it('published + reporter credited -> published-credited, records the GHSA id', async () => {
    const r = await run(submitted(), { [API_A]: { status: 200, json: credited } });
    expect(r.ledger.disclosures[0]).toMatchObject({
      state: 'published-credited',
      ghsaId: 'GHSA-aaaa-bbbb-cccc',
      updatedAt: T1,
    });
    expect(r.flagged).toEqual([]);
    expect(r.seen).toHaveLength(1);
  });

  it('credit may appear only in the legacy credits array', async () => {
    const json = { state: 'published', credits: [{ login: ME, type: 'finder' }] };
    const r = await run(submitted(), { [API_A]: { status: 200, json } });
    expect(r.ledger.disclosures[0]?.state).toBe('published-credited');
  });

  it('a declined credit does not count', async () => {
    const json = {
      state: 'published',
      credits_detailed: [{ user: { login: ME }, type: 'reporter', state: 'declined' }],
    };
    const r = await run(submitted(), { [API_A]: { status: 200, json } });
    expect(r.ledger.disclosures[0]?.state).toBe('fixed');
  });

  it('published without the reporter credit -> fixed', async () => {
    const json = {
      state: 'published',
      credits_detailed: [{ user: { login: 'someone-else' }, type: 'reporter', state: 'accepted' }],
    };
    const r = await run(submitted(), { [API_A]: { status: 200, json } });
    expect(r.ledger.disclosures[0]?.state).toBe('fixed');
  });

  it('a fixed disclosure whose advisory later publishes with credit -> published-credited', async () => {
    const fixed = transition(submitted(), KEY, 'fixed', { now: T0 });
    const r = await run(fixed, { [API_A]: { status: 200, json: credited } });
    expect(r.ledger.disclosures[0]?.state).toBe('published-credited');
  });

  it('a fixed disclosure still uncredited is left alone', async () => {
    const fixed = transition(submitted(), KEY, 'fixed', { now: T0 });
    const r = await run(fixed, { [API_A]: { status: 200, json: { state: 'published' } } });
    expect(r.ledger.disclosures[0]?.state).toBe('fixed');
    expect(r.ledger.disclosures[0]?.updatedAt).toBe(T0);
  });

  it.each(['closed', 'withdrawn'])('%s -> declined and trips the archetype', async (state) => {
    const r = await run(submitted(), { [API_A]: { status: 200, json: { state } } });
    expect(r.ledger.disclosures[0]?.state).toBe('declined');
    expect(r.ledger.trippedArchetypes).toEqual(['arch-x']);
  });

  it('404 leaves the state unchanged and is flagged', async () => {
    const l = submitted();
    const r = await run(l, {});
    expect(r.ledger).toEqual(l);
    expect(r.flagged).toHaveLength(1);
    expect(r.flagged[0]).toContain('acme/widgets');
    expect(r.flagged[0]).toContain('404');
  });

  it('other HTTP errors leave the state unchanged and are flagged', async () => {
    const l = submitted();
    const r = await run(l, { [API_A]: { status: 500, json: null } });
    expect(r.ledger).toEqual(l);
    expect(r.flagged).toHaveLength(1);
  });

  it('a malformed reportUrl is flagged, never requested', async () => {
    const l = submitted('acme/widgets', ['f1'], 'https://example.com/nope');
    const r = await run(l, {});
    expect(r.seen).toHaveLength(0);
    expect(r.flagged).toHaveLength(1);
    expect(r.ledger).toEqual(l);
  });

  it('a still-open advisory stays submitted', async () => {
    const l = submitted();
    for (const state of ['draft', 'triage']) {
      const r = await run(l, { [API_A]: { status: 200, json: { state } } });
      expect(r.ledger).toEqual(l);
    }
  });

  it('open advisory whose current scan no longer fails those ids -> fixed', async () => {
    const r = await run(
      submitted('acme/widgets', ['f1', 'f2']),
      { [API_A]: { status: 200, json: { state: 'triage' } } },
      new Map([['acme/widgets', new Set(['other'])]]),
    );
    expect(r.ledger.disclosures[0]?.state).toBe('fixed');
  });

  it('keeps submitted while any id still fails, or the repo was not rescanned', async () => {
    const l = submitted('acme/widgets', ['f1', 'f2']);
    const routes = { [API_A]: { status: 200, json: { state: 'draft' } } };
    const still = await run(l, routes, new Map([['acme/widgets', new Set(['f2'])]]));
    expect(still.ledger.disclosures[0]?.state).toBe('submitted');
    const none = await run(l, routes, new Map());
    expect(none.ledger.disclosures[0]?.state).toBe('submitted');
  });

  it('ignores disclosures that are not submitted or fixed', async () => {
    const l = createDisclosure(emptyLedger(), {
      repo: 'acme/widgets',
      findingIds: ['f1'],
      archetype: 'arch-x',
      state: 'held',
      now: T0,
    });
    const r = await run(l, {});
    expect(r.seen).toHaveLength(0);
    expect(r.ledger).toEqual(l);
  });
});
