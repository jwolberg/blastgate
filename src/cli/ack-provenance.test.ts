import { describe, expect, it } from 'vitest';
import { runEngine } from '../engine/gate';
import { collectInputs, type RepoFs } from './collect';

/**
 * 0019: `.blastgate/acknowledged.json` is read from the untrusted branch being
 * scanned, so a PR could commit an ack for the exact finding its own change
 * triggers and self-downgrade the gate. Only acks already on the trusted base ref
 * are honored; head-introduced acks are ignored and surfaced.
 */

/** A fork-triggerable job holding a credential — a single fail finding. */
const WORKFLOW = [
  'on:',
  '  pull_request_target:',
  'jobs:',
  '  test:',
  '    steps:',
  '      - run: npm ci',
  '        env:',
  '          AWS: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
].join('\n');

function memFs(files: Record<string, string>, base?: Record<string, string>): RepoFs {
  return {
    read: (p) => (p in files ? files[p]! : null),
    listWorkflows: () =>
      Object.keys(files).filter((p) => /^\.github\/workflows\/.*\.ya?ml$/.test(p)),
    gitShow: (_ref, p) => (base && p in base ? base[p]! : null),
  };
}
const ackJson = (id: string) => JSON.stringify({ acknowledged: [{ id, reason: 'accepted' }] });
const workflowFiles = (extra: Record<string, string> = {}) => ({
  '.github/workflows/ci.yml': WORKFLOW,
  ...extra,
});

/** The id of the single fail finding, with no acks in play. */
function failId(): string {
  const r = runEngine(collectInputs(memFs(workflowFiles(), {}), { base: 'BASE' }));
  const f = r.findings.find((x) => x.tier === 'fail');
  expect(f, 'a baseline fail finding').toBeDefined();
  return f!.id;
}

describe('ack provenance (0019)', () => {
  it('a head-introduced ack is IGNORED — the finding still fails, and it is surfaced', () => {
    const id = failId();
    const inputs = collectInputs(
      memFs(workflowFiles({ '.blastgate/acknowledged.json': ackJson(id) }), {}),
      { base: 'BASE' },
    );
    expect(inputs.acknowledged).toBeUndefined();
    expect(inputs.acknowledgedIgnored?.map((a) => a.id)).toContain(id);

    const r = runEngine(inputs);
    expect(r.verdict).toBe('fail');
    expect(r.diagnostics.some((d) => d.level === 'warn' && /ignored/.test(d.message))).toBe(true);
  });

  it('an ack already on the base ref IS honored — the finding downgrades to warn', () => {
    const id = failId();
    const inputs = collectInputs(
      memFs(workflowFiles({ '.blastgate/acknowledged.json': ackJson(id) }), {
        '.blastgate/acknowledged.json': ackJson(id),
      }),
      { base: 'BASE' },
    );
    expect(inputs.acknowledged?.map((a) => a.id)).toContain(id);
    expect(runEngine(inputs).verdict).toBe('warn');
  });

  it('without a base ref (local whole-repo scan), committed head acks are honored', () => {
    const id = failId();
    const inputs = collectInputs(
      memFs(workflowFiles({ '.blastgate/acknowledged.json': ackJson(id) })),
      {},
    );
    expect(inputs.acknowledged?.map((a) => a.id)).toContain(id);
  });
});
