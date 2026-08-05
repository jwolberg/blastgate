import { describe, expect, it } from 'vitest';
import type { Finding } from '../findings/finding';
import { applyPolicy, parsePolicy, ruleKey, type AcceptRule } from './policy';

/** A reachable-secret fail finding (AE1 shape) for the policy tests. */
function failFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'entry:fork-pr:.github/workflows/ci.yml#test=>sink:secret:AWS_SECRET_ACCESS_KEY',
    tier: 'fail',
    score: 333,
    path: ['fork PR reaches job test', 'ci.yml#test', 'AWS_SECRET_ACCESS_KEY'],
    pathNodeIds: ['entry:fork-pr', 'job', 'sink'],
    hops: 2,
    entry: { kind: 'fork-pr', label: 'fork PR reaches job test' },
    sink: { kind: 'credential', identity: 'AWS_SECRET_ACCESS_KEY' },
    reason: 'job is fork-triggerable and holds the secret',
    remediation: 'remove the secret from the untrusted job',
    owasp: { agentic: 'ASI03' },
    labels: ['ASI03:2026'],
    ...over,
  };
}

describe('parsePolicy', () => {
  it('parses a specific accept rule (by sink identity) with a reason and expiry', () => {
    const { rules, diagnostics } = parsePolicy(
      JSON.stringify({
        accept: [
          { sink: 'AWS_SECRET_ACCESS_KEY', reason: 'read-only, scoped', expires: '2026-12-31' },
        ],
      }),
    );
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ sink: 'AWS_SECRET_ACCESS_KEY', expires: '2026-12-31' });
    expect(diagnostics).toHaveLength(0);
  });

  it('rejects a blanket wildcard rule at parse time with a diagnostic (no silent kill switch)', () => {
    const { rules, diagnostics } = parsePolicy(
      JSON.stringify({ accept: [{ sink: '*', reason: 'allow everything' }] }),
    );
    expect(rules).toHaveLength(0);
    expect(diagnostics.some((d) => /specific|wildcard|blanket/i.test(d.message))).toBe(true);
  });

  it('rejects an archetype-only rule — an archetype names no specific target', () => {
    const { rules, diagnostics } = parsePolicy(
      JSON.stringify({ accept: [{ archetype: 'fork-pr', reason: 'accept all fork PRs' }] }),
    );
    expect(rules).toHaveLength(0);
    expect(diagnostics.length).toBeGreaterThan(0);
  });

  it('rejects a rule with no reason (audit trail is required)', () => {
    const { rules, diagnostics } = parsePolicy(
      JSON.stringify({ accept: [{ sink: 'AWS_SECRET_ACCESS_KEY' }] }),
    );
    expect(rules).toHaveLength(0);
    expect(diagnostics.length).toBeGreaterThan(0);
  });

  it('is tolerant of malformed input — yields no rules and never throws, never fails open', () => {
    expect(parsePolicy('not json {').rules).toHaveLength(0);
    expect(parsePolicy(null).rules).toHaveLength(0);
    expect(parsePolicy(undefined).rules).toHaveLength(0);
    expect(parsePolicy('{}').rules).toHaveLength(0);
  });
});

describe('applyPolicy', () => {
  it('downgrades a matching fail finding to warn, recording the reason', () => {
    const rule: AcceptRule = { sink: 'AWS_SECRET_ACCESS_KEY', reason: 'reviewed — scoped' };
    const [f] = applyPolicy([failFinding()], [rule], {});
    expect(f!.tier).toBe('warn');
    expect(f!.acknowledged).toBe('reviewed — scoped');
  });

  it('narrows by archetype + sink together (both must match)', () => {
    const rule: AcceptRule = { archetype: 'fork-pr', sink: 'AWS_SECRET_ACCESS_KEY', reason: 'ok' };
    expect(applyPolicy([failFinding()], [rule], {})[0]!.tier).toBe('warn');
    // Same sink but a different archetype is NOT accepted by this rule.
    const other = failFinding({ entry: { kind: 'new-dependency', label: 'x' } });
    expect(applyPolicy([other], [rule], {})[0]!.tier).toBe('fail');
  });

  it('does not apply an expired rule (past its review-by date)', () => {
    const rule: AcceptRule = { id: failFinding().id, reason: 'old', expires: '2020-01-01' };
    const [f] = applyPolicy([failFinding()], [rule], { now: '2026-08-05' });
    expect(f!.tier).toBe('fail');
  });

  it('applies a not-yet-expired rule', () => {
    const rule: AcceptRule = { id: failFinding().id, reason: 'still valid', expires: '2099-01-01' };
    expect(applyPolicy([failFinding()], [rule], { now: '2026-08-05' })[0]!.tier).toBe('warn');
  });

  it('leaves a non-matching finding untouched', () => {
    const rule: AcceptRule = { sink: 'SOME_OTHER_SECRET', reason: 'x' };
    expect(applyPolicy([failFinding()], [rule], {})[0]!.tier).toBe('fail');
  });
});

describe('ruleKey (self-approval base-vs-head identity, ignores reason)', () => {
  it('is stable across a reason edit but distinct across selector/expiry changes', () => {
    const a: AcceptRule = { sink: 'AWS_SECRET_ACCESS_KEY', reason: 'first' };
    const b: AcceptRule = { sink: 'AWS_SECRET_ACCESS_KEY', reason: 'reworded' };
    const c: AcceptRule = { sink: 'AWS_SECRET_ACCESS_KEY', reason: 'x', expires: '2027-01-01' };
    expect(ruleKey(a)).toBe(ruleKey(b));
    expect(ruleKey(a)).not.toBe(ruleKey(c));
  });
});
