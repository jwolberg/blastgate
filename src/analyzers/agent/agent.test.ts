import { describe, expect, it } from 'vitest';
import { analyzeAgents } from './index';

const fsServer = JSON.stringify({
  mcpServers: {
    fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
  },
});
const blastgateServer = JSON.stringify({
  mcpServers: {
    checker: {
      command: 'npx',
      args: ['-y', 'blastgate', 'mcp'],
      env: { BLASTGATE_PROJECT_DIR: '${CLAUDE_PROJECT_DIR}' },
    },
  },
});

describe('analyzeAgents — MCP servers', () => {
  it('flags a filesystem server pointed outside the repo root (AE4)', () => {
    const r = analyzeAgents({ mcpJson: fsServer });
    const grant = r.nodes.find((n) => n.kind === 'agent-grant');
    expect(grant && grant.kind === 'agent-grant' && grant.capabilityClass).toBe('filesystem');
    expect(grant && grant.kind === 'agent-grant' && grant.exceedsBaseline).toBe(true);
    expect(
      r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'injectable-agent-surface'),
    ).toBe(true);
    expect(r.nodes.some((n) => n.kind === 'sink' && n.sinkKind === 'privileged-capability')).toBe(
      true,
    );
    expect(r.edges.some((e) => e.edge.kind === 'reaches')).toBe(true);
  });

  it('does not flag a project-scoped tool server — no self-inflicted finding', () => {
    const r = analyzeAgents({ mcpJson: blastgateServer });
    expect(r.nodes.some((n) => n.kind === 'agent-grant' && n.exceedsBaseline)).toBe(false);
    expect(r.nodes.some((n) => n.kind === 'entry')).toBe(false);
  });

  it('resolves ${HOME} indirection to an out-of-repo path', () => {
    const server = JSON.stringify({
      mcpServers: { fs: { command: 'npx', args: ['server-fs', '${HOME}/.ssh'] } },
    });
    const r = analyzeAgents({ mcpJson: server });
    expect(
      r.nodes.some(
        (n) => n.kind === 'agent-grant' && n.capabilityClass === 'filesystem' && n.exceedsBaseline,
      ),
    ).toBe(true);
  });
});

describe('analyzeAgents — settings permissions', () => {
  it('flags Bash(devbox run *) as unrestricted shell but not Bash(npm run test *)', () => {
    const settings = JSON.stringify({
      permissions: { allow: ['Bash(npm run test *)', 'Bash(devbox run *)'] },
    });
    const r = analyzeAgents({ claudeSettings: settings });
    const shell = r.nodes.filter((n) => n.kind === 'agent-grant' && n.capabilityClass === 'shell');
    expect(
      shell.some(
        (n) => n.kind === 'agent-grant' && n.exceedsBaseline && n.scope.includes('devbox'),
      ),
    ).toBe(true);
    expect(
      shell.some(
        (n) => n.kind === 'agent-grant' && n.exceedsBaseline && n.scope.includes('npm run test'),
      ),
    ).toBe(false);
  });

  it('flags WebFetch(domain:*) but not a scoped domain', () => {
    const r = analyzeAgents({
      claudeSettings: JSON.stringify({
        permissions: { allow: ['WebFetch(domain:*)', 'WebFetch(domain:github.com)'] },
      }),
    });
    const net = r.nodes.filter((n) => n.kind === 'agent-grant' && n.capabilityClass === 'network');
    expect(net.some((n) => n.kind === 'agent-grant' && n.exceedsBaseline)).toBe(true);
    expect(net.filter((n) => n.kind === 'agent-grant' && !n.exceedsBaseline)).toHaveLength(1);
  });

  it('treats a committed command hook as a deterministic privileged capability, not an injectable surface (U18)', () => {
    const settings = JSON.stringify({
      hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: './x.sh' }] }] },
    });
    const r = analyzeAgents({ claudeSettings: settings });
    // still recorded as an over-baseline shell grant
    expect(
      r.nodes.some(
        (n) => n.kind === 'agent-grant' && n.capabilityClass === 'shell' && n.exceedsBaseline,
      ),
    ).toBe(true);
    // but the entry is a privileged-hook — NOT a prompt-injectable agent surface
    const entry = r.nodes.find((n) => n.kind === 'entry');
    expect(entry && entry.kind === 'entry' && entry.entryKind).toBe('privileged-hook');
    expect(
      r.nodes.some((n) => n.kind === 'entry' && n.entryKind === 'injectable-agent-surface'),
    ).toBe(false);
    // clean two-node path label; no injected middleman → a `reaches` edge, never `injects`
    expect(entry && entry.kind === 'entry' && entry.label).toBe(
      '.claude/settings.json (committed hook)',
    );
    expect(r.edges.some((e) => e.edge.kind === 'reaches')).toBe(true);
    expect(r.edges.some((e) => e.edge.kind === 'injects')).toBe(false);
  });
});

describe('analyzeAgents — no config / malformed', () => {
  it('emits nothing and does not crash when there is no agent config', () => {
    const r = analyzeAgents({});
    expect(r.nodes).toEqual([]);
    expect(r.diagnostics).toEqual([]);
  });

  it('returns a parse-error diagnostic on malformed JSON', () => {
    const r = analyzeAgents({ mcpJson: '{ bad json' });
    expect(r.diagnostics.some((d) => d.level === 'error')).toBe(true);
  });
});
