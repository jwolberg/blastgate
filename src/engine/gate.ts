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

/** Whole-run verdict from per-finding tiers (KTD4). */
export function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => f.tier === 'fail')) {
    return 'fail';
  }
  if (findings.some((f) => f.tier === 'warn')) {
    return 'warn';
  }
  return 'pass';
}

/** The gate exits non-zero only on a fail verdict; warn and pass exit 0 (KTD4). */
export function gateFails(verdict: Verdict): boolean {
  return verdict === 'fail';
}

/** Build the graph, assemble ranked findings, apply acknowledgements, gate — the one engine. */
export function runEngine(inputs: EngineInputs): GateResult {
  const build = buildGraph(inputs);
  const findings = applyAcknowledgements(assembleFindings(build), inputs.acknowledged ?? []);
  return { verdict: verdictOf(findings), findings, diagnostics: build.diagnostics };
}
