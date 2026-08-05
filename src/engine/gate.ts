/**
 * Engine — fail-threshold gate + top-level entrypoint (U7 step 3).
 *
 * KTD4: the gate exits fail (non-zero) only on a reachable secret/credential path;
 * lower-sensitivity capability paths are reported as warnings without failing.
 * `runEngine` is the single entrypoint every surface (CLI, Action, plugin, MCP)
 * rides — no surface re-implements build → checks → gate (KTD10).
 */

import type { Diagnostic } from '../analyzers/types';
import type { Finding, Verdict } from '../findings/finding';
import { exceedsReachabilityCap, MAX_REACHABILITY_PAIRS, reachabilityCost } from '../graph/caps';
import { applyAcknowledgements } from './acknowledge';
import { buildGraph, type EngineInputs } from './build';
import { assembleFindings } from './checks';

export interface GateResult {
  verdict: Verdict;
  /** Ranked findings, most-severe first. */
  findings: Finding[];
  /** Merged analyzer diagnostics (parse errors, hygiene warnings). */
  diagnostics: Diagnostic[];
}

/**
 * Whole-run verdict (KTD4, fail-closed 0020). Precedence fail > unknown > warn >
 * pass: a real reachable secret path fails; otherwise an `error`-level diagnostic
 * means a layer could not be evaluated, so the run is `unknown` (never a false
 * pass); otherwise a capability path warns; otherwise pass.
 */
export function verdictOf(findings: Finding[], diagnostics: Diagnostic[] = []): Verdict {
  if (findings.some((f) => f.tier === 'fail')) {
    return 'fail';
  }
  if (diagnostics.some((d) => d.level === 'error')) {
    return 'unknown';
  }
  if (findings.some((f) => f.tier === 'warn')) {
    return 'warn';
  }
  return 'pass';
}

/** A real reachable secret/credential finding (KTD4) — distinct from `unknown`. */
export function gateFails(verdict: Verdict): boolean {
  return verdict === 'fail';
}

/**
 * The CI/scan blocking predicate: block on a real fail OR an un-evaluable run
 * (`unknown`). Fail-closed — a gate that could not evaluate must not wave a change
 * through. warn/pass do not block (0020).
 */
export function gateBlocks(verdict: Verdict): boolean {
  return verdict === 'fail' || verdict === 'unknown';
}

export interface EngineOptions {
  /**
   * Ceiling on entry×sink pairs before the reachability search is skipped and the
   * run fails closed to UNKNOWN (0018). Defaults to `MAX_REACHABILITY_PAIRS`.
   */
  maxPairs?: number;
}

/** Build the graph, assemble ranked findings, apply acknowledgements, gate — the one engine. */
export function runEngine(inputs: EngineInputs, opts: EngineOptions = {}): GateResult {
  const build = buildGraph(inputs);
  const cap = opts.maxPairs ?? MAX_REACHABILITY_PAIRS;
  const diagnostics = [...build.diagnostics];

  // Bound the pairwise reachability search: over the cap, fail closed to UNKNOWN
  // (never hang, never a false pass) instead of running an attacker-inflated O(E×S).
  if (exceedsReachabilityCap(build.graph, cap)) {
    diagnostics.push({
      level: 'error',
      message:
        `attack graph too large to evaluate safely ` +
        `(${reachabilityCost(build.graph)} entry×sink pairs exceed the ${cap} cap); ` +
        `failing closed as UNKNOWN`,
    });
    return { verdict: verdictOf([], diagnostics), findings: [], diagnostics };
  }

  const findings = applyAcknowledgements(assembleFindings(build), inputs.acknowledged ?? []);
  return { verdict: verdictOf(findings, diagnostics), findings, diagnostics };
}
