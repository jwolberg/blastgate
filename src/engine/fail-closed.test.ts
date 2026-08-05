import { describe, expect, it } from 'vitest';
import type { Diagnostic } from '../analyzers/types';
import type { Finding } from '../findings/finding';
import { hookOutput } from '../cli/gate';
import { renderText, scanExitCode } from '../cli/render';
import { gateBlocks, gateFails, runEngine, verdictOf } from './gate';

/**
 * Fail-closed gate semantics (0020): a run that could not fully evaluate an input
 * must surface a distinct UNKNOWN verdict — never a false PASS. CI blocks on
 * UNKNOWN; the local hook warns loudly but allows.
 */

const failFinding = { tier: 'fail' } as Finding;
const warnFinding = { tier: 'warn' } as Finding;
const errorDiag: Diagnostic = { level: 'error', message: 'failed to parse package-lock.json' };
const warnDiag: Diagnostic = { level: 'warn', message: 'unpinned action' };

describe('verdictOf precedence: fail > unknown > warn > pass', () => {
  it('pass with no findings and no diagnostics', () => {
    expect(verdictOf([], [])).toBe('pass');
  });
  it('warn on a warn finding', () => {
    expect(verdictOf([warnFinding], [])).toBe('warn');
  });
  it('fail on a fail finding', () => {
    expect(verdictOf([failFinding], [])).toBe('fail');
  });
  it('UNKNOWN when an error diagnostic means the run could not be evaluated', () => {
    expect(verdictOf([], [errorDiag])).toBe('unknown');
  });
  it('UNKNOWN overrides a warn finding (could-not-evaluate beats a low-sev finding)', () => {
    expect(verdictOf([warnFinding], [errorDiag])).toBe('unknown');
  });
  it('a real fail still dominates an error diagnostic', () => {
    expect(verdictOf([failFinding], [errorDiag])).toBe('fail');
  });
  it('a warn-level diagnostic is not an evaluation failure', () => {
    expect(verdictOf([], [warnDiag])).toBe('pass');
  });
});

describe('gate predicates', () => {
  it('gateFails is true only for a real fail', () => {
    expect(gateFails('fail')).toBe(true);
    expect(gateFails('unknown')).toBe(false);
  });
  it('gateBlocks (CI) blocks on fail AND unknown, not warn/pass', () => {
    expect(gateBlocks('fail')).toBe(true);
    expect(gateBlocks('unknown')).toBe(true);
    expect(gateBlocks('warn')).toBe(false);
    expect(gateBlocks('pass')).toBe(false);
  });
});

describe('surfaces treat UNKNOWN correctly', () => {
  const unknown = { verdict: 'unknown' as const, findings: [], diagnostics: [errorDiag] };

  it('scan/CI exit code is non-zero on UNKNOWN', () => {
    expect(scanExitCode(unknown)).toBe(1);
  });
  it('renderText shows UNKNOWN and the error, never PASS', () => {
    const out = renderText(unknown);
    expect(out).toContain('UNKNOWN');
    expect(out).not.toContain('PASS');
    expect(out).toContain('failed to parse package-lock.json');
  });
  it('local hook allows (exit 0) but warns loudly on UNKNOWN — never a silent pass', () => {
    const { exitCode, stderr, stdout } = hookOutput('pre-commit', unknown);
    expect(exitCode).toBe(0);
    expect(stderr ?? '').toMatch(/UNKNOWN/);
    expect(stdout).not.toContain('permissionDecision'); // not a deny; a warning
  });
});

describe('runEngine end-to-end fail-closed', () => {
  it('a malformed package-lock.json yields UNKNOWN, not PASS', () => {
    const result = runEngine({ deps: { headLockfile: '{ this is not json' } });
    expect(result.verdict).toBe('unknown');
    expect(scanExitCode(result)).toBe(1);
    expect(result.diagnostics.some((d) => d.level === 'error')).toBe(true);
  });
});
