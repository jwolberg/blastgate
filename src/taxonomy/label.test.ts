import { describe, expect, it } from 'vitest';
import type { ReachPath } from '../graph/reachability';
import type { AttackNode, EntryKind, EntryNode, SinkNode } from '../graph/types';
import { labelPath } from './label';
import { agenticLabel, mcpLabel } from './owasp';

function entry(entryKind: EntryKind): EntryNode {
  return { id: 'e', kind: 'entry', entryKind, exposure: 1, label: 'e' };
}
function secretSink(): SinkNode {
  return { id: 's', kind: 'sink', sinkKind: 'secret', identity: 'AWS_SECRET_ACCESS_KEY' };
}
function pathThrough(entryKind: EntryKind, mids: AttackNode[]): ReachPath {
  const e = entry(entryKind);
  const sink = secretSink();
  const nodes = [e, ...mids, sink];
  return { entry: e, sink, nodes, hops: nodes.length - 1 };
}

const depNode: AttackNode = {
  id: 'd',
  kind: 'dependency',
  pkg: 'evil',
  version: '1.0.0',
  isDirect: true,
  hasInstallScript: true,
};
const jobNode: AttackNode = {
  id: 'j',
  kind: 'ci-job',
  workflow: 'ci.yml',
  job: 'test',
  triggers: ['pull_request'],
  secrets: ['AWS_SECRET_ACCESS_KEY'],
  forkTriggerable: true,
  runsInstall: true,
};
const overBaselineGrant: AttackNode = {
  id: 'g',
  kind: 'agent-grant',
  source: '.mcp.json',
  capabilityClass: 'filesystem',
  scope: '/',
  exceedsBaseline: true,
};

describe('labelPath', () => {
  it('labels an install-script → secret path MCP04 / ASI04', () => {
    expect(labelPath(pathThrough('new-dependency', [depNode, jobNode]))).toEqual({
      agentic: 'ASI04',
      mcp: 'MCP04',
    });
  });

  it('labels an agent over-privilege path MCP02', () => {
    const labels = labelPath(pathThrough('injectable-agent-surface', [overBaselineGrant]));
    expect(labels.mcp).toBe('MCP02');
    expect(labels.agentic).toBe('ASI01');
  });

  it('labels a committed command hook ASI03 / MCP02 — scope creep, not ASI01 goal hijack (U18)', () => {
    const labels = labelPath(pathThrough('privileged-hook', []));
    expect(labels.agentic).toBe('ASI03');
    expect(labels.mcp).toBe('MCP02');
  });

  it('leaves the MCP label unset for a pure CI fork-PR finding (no applicable MCP category)', () => {
    const labels = labelPath(pathThrough('fork-pr', [jobNode]));
    expect(labels.agentic).toBe('ASI03');
    expect(labels.mcp).toBeUndefined();
  });

  it('formats versioned category labels', () => {
    expect(agenticLabel('ASI04')).toBe('ASI04:2026');
    expect(mcpLabel('MCP02')).toBe('MCP02:2025');
  });
});
