import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runEngine } from '../src/engine/gate';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * U14 self-scan (AE-style): Blastgate's own committed plugin `.mcp.json` declares a
 * project-scoped stdio server (`blastgate mcp`, `BLASTGATE_PROJECT_DIR:
 * ${CLAUDE_PROJECT_DIR}`). The U6 classifier must treat it as an in-baseline tool
 * server — no self-inflicted finding — otherwise the plugin would flag itself on
 * install.
 */
describe('plugin self-scan', () => {
  it("does not flag Blastgate's own committed plugin/.mcp.json", () => {
    const mcpJson = readFileSync(join(repoRoot, 'plugin', '.mcp.json'), 'utf8');
    const result = runEngine({ agent: { mcpJson } });
    expect(result.verdict).toBe('pass');
    expect(result.findings).toHaveLength(0);
  });
});
