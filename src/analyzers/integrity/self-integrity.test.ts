import { describe, expect, it } from 'vitest';
import { runEngine } from '../../engine/gate';
import { gateEnforcementRemoved } from './self-integrity';

const HOOKS_WITH_GATE = JSON.stringify({
  hooks: {
    PreToolUse: [{ matcher: 'Bash', hooks: [{ command: '${CLAUDE_PLUGIN_ROOT}/bin/blastgate' }] }],
  },
});
const HOOKS_WITHOUT = JSON.stringify({ hooks: { PreToolUse: [] } });

describe('gateEnforcementRemoved (0024)', () => {
  it('true: base wired blastgate, head no longer does', () => {
    expect(
      gateEnforcementRemoved({
        path: 'plugin/hooks/hooks.json',
        base: HOOKS_WITH_GATE,
        head: HOOKS_WITHOUT,
      }),
    ).toBe(true);
  });
  it('true: the gate file was deleted outright', () => {
    expect(
      gateEnforcementRemoved({
        path: 'plugin/hooks/hooks.json',
        base: HOOKS_WITH_GATE,
        head: null,
      }),
    ).toBe(true);
  });
  it('false: still wired at head (unchanged or edited but intact)', () => {
    expect(
      gateEnforcementRemoved({
        path: 'plugin/hooks/hooks.json',
        base: HOOKS_WITH_GATE,
        head: HOOKS_WITH_GATE,
      }),
    ).toBe(false);
  });
  it('false: the repo never wired the gate (no base reference)', () => {
    expect(gateEnforcementRemoved({ path: '.mcp.json', base: '{}', head: '{}' })).toBe(false);
  });
});

describe('analyzeSelfIntegrity + engine (0024)', () => {
  it('removing the gate hook produces a warn finding', () => {
    const result = runEngine({
      selfIntegrity: {
        files: [{ path: 'plugin/hooks/hooks.json', base: HOOKS_WITH_GATE, head: HOOKS_WITHOUT }],
      },
    });
    expect(result.verdict).toBe('warn');
    const f = result.findings.find((x) => x.entry.kind === 'gate-tamper');
    expect(f, 'a gate-tamper finding').toBeDefined();
    expect(f!.tier).toBe('warn');
  });
  it('an intact gate yields no finding', () => {
    const result = runEngine({
      selfIntegrity: {
        files: [{ path: 'plugin/hooks/hooks.json', base: HOOKS_WITH_GATE, head: HOOKS_WITH_GATE }],
      },
    });
    expect(result.verdict).toBe('pass');
  });
});
