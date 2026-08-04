/**
 * Blastgate — cross-layer attack-path engine.
 *
 * One graph across three layers (dependencies / install-scripts, CI jobs +
 * secrets, committed agent/MCP grants); a finding is a reachable path from an
 * attacker-controllable entry point to a sensitive sink. Every surface (CLI,
 * GitHub Action, Claude Code plugin) consumes this library — no surface
 * re-implements the engine.
 *
 * See docs/plans/2026-08-04-001-feat-blastgate-attack-path-gate-plan.md.
 */

export const VERSION = '0.1.0';
