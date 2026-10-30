/**
 * Open-time execution analyzer (0114, `blastgate --pre-open`).
 *
 * Every other layer asks whether a stranger's change can reach a CI secret. This one asks
 * the question a developer has before opening a clone they did not write: does committed
 * editor/agent config run a command as me the moment I open it? The testmetest campaign
 * (JFrog, 2026-10-26) armed 42 real repos this way — a Claude/Gemini `SessionStart` hook,
 * a Cursor MCP server, or a VS Code `folderOpen` task running a 13 MB obfuscated
 * `.github/init.js` that steals GitHub/npm tokens. Here the repo itself is the attacker.
 *
 * Findings: a hook, status line, or folderOpen task always runs repo-authored commands on
 * open, so it reaches the developer's credentials. An MCP server is only a finding when it
 * launches a file committed to the repo; one that runs a published package is left to the
 * capability analyzer (`../agent`). Pure: the collector reads the configs and their
 * targets; nothing here touches the filesystem or executes anything.
 */

import { locateSource, type KeyPath } from '../ci/locate';
import { type AnalyzerResult, emptyResult } from '../types';

/** Committed config that can run a command when a workspace is opened. */
export const OPEN_EXEC_CONFIG_PATHS = [
  '.claude/settings.json',
  '.gemini/settings.json',
  '.mcp.json',
  '.cursor/mcp.json',
  '.vscode/tasks.json',
];

export interface OpenExecConfig {
  path: string;
  content: string;
}

/** Size facts about a repo file a command runs; `null` when the file is not in the repo. */
export interface OpenExecTarget {
  size: number;
  longestLine: number;
}

export interface OpenExecInputs {
  configs: OpenExecConfig[];
  targets: Record<string, OpenExecTarget | null>;
}

export interface AutoRunCommand {
  file: string;
  /** 1-based line of the command, when the parser can place it. */
  line?: number;
  kind: 'hook' | 'status-line' | 'helper' | 'mcp-server' | 'task';
  /** What fires it, e.g. `Claude Code SessionStart hook`. */
  trigger: string;
  command: string;
  /** An MCP server's `command` and `args`, unjoined, so a path with a space stays whole. */
  argv?: string[];
}

/** `.claude/settings.json` keys whose value is a shell command Claude Code runs itself. */
const CLAUDE_HELPERS = ['apiKeyHelper', 'awsAuthRefresh', 'otelHeadersHelper'];

/** VS Code task keys that override `command` per platform. */
const TASK_PLATFORMS = ['windows', 'linux', 'osx'];

/** The tool that reads each MCP config file. */
const MCP_TOOL: Record<string, string> = {
  '.mcp.json': 'Claude Code',
  '.cursor/mcp.json': 'Cursor',
  '.gemini/settings.json': 'Gemini CLI',
};

/** A target this large is not a plausible hand-written hook script (init.js was 13 MB). */
const LARGE_TARGET_BYTES = 1_000_000;
/** A line this long is minified or encoded, not source a reviewer can read. */
const LONG_LINE_CHARS = 10_000;

/** Index just past the JSON string starting at `i` (which is a `"`). */
function skipString(text: string, i: number): number {
  for (i++; i < text.length && text[i] !== '"'; i++) {
    if (text[i] === '\\') {
      i++;
    }
  }
  return i + 1;
}

/**
 * Blank out a BOM, JSONC comments, and trailing commas (VS Code's tasks.json allows them)
 * with spaces, so offsets — and so source lines — are unchanged for the locator. Comments
 * go first, so a trailing comma followed by a comment is still seen as trailing.
 */
function stripJsonc(text: string): string {
  const out = text.split('');
  if (out[0] === '\uFEFF') {
    out[0] = ' ';
  }
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k++) {
      if (out[k] !== '\n') {
        out[k] = ' ';
      }
    }
  };
  for (let i = 0; i < text.length;) {
    if (text[i] === '"') {
      i = skipString(text, i);
    } else if (text[i] === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? text.length : end;
      blank(i, stop);
      i = stop;
    } else if (text[i] === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? text.length : end + 2;
      blank(i, stop);
      i = stop;
    } else {
      i++;
    }
  }
  const bare = out.join('');
  for (let i = 0; i < bare.length;) {
    if (bare[i] === '"') {
      i = skipString(bare, i);
      continue;
    }
    if (bare[i] === ',') {
      let j = i + 1;
      while (j < bare.length && /\s/.test(bare[j]!)) {
        j++;
      }
      if (bare[j] === '}' || bare[j] === ']') {
        out[i] = ' ';
      }
    }
    i++;
  }
  return out.join('');
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function argString(a: unknown): string | undefined {
  if (typeof a === 'string') {
    return a;
  }
  return isRecord(a) && typeof a.value === 'string' ? a.value : undefined;
}

function argList(args: unknown): string[] {
  return Array.isArray(args) ? args.map(argString).filter((a) => a !== undefined) : [];
}

function withArgs(command: string, args: unknown): string {
  return [command, ...argList(args)].join(' ');
}

/** `{ Event: [{ matcher, hooks: [{ type: 'command', command }] }] }` — Claude and Gemini share it. */
function hookCommands(
  hooks: unknown,
  tool: string,
  emit: (kind: AutoRunCommand['kind'], trigger: string, command: string, at: KeyPath) => void,
): void {
  if (!isRecord(hooks)) {
    return;
  }
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) {
      continue;
    }
    groups.forEach((group, gi) => {
      const list = isRecord(group) ? group.hooks : undefined;
      if (!Array.isArray(list)) {
        return;
      }
      list.forEach((hook, hi) => {
        if (isRecord(hook) && hook.type === 'command' && typeof hook.command === 'string') {
          emit('hook', `${tool} ${event} hook`, hook.command, [
            'hooks',
            event,
            gi,
            'hooks',
            hi,
            'command',
          ]);
        }
      });
    });
  }
}

function parseConfig(config: OpenExecConfig): { data: unknown; text: string } {
  const text = stripJsonc(config.content);
  return { data: JSON.parse(text) as unknown, text };
}

/**
 * The commands a config file runs without the developer asking (0114). Throws on a config
 * that is not valid JSON(C) — the analyzer turns that into a fail-closed diagnostic.
 */
export function autoRunCommands(config: OpenExecConfig): AutoRunCommand[] {
  const { data, text } = parseConfig(config);
  const locator = locateSource(text);
  const out: AutoRunCommand[] = [];
  const emit = (
    kind: AutoRunCommand['kind'],
    trigger: string,
    command: string,
    at: KeyPath,
    argv?: string[],
  ): void => {
    const line = locator.line(at);
    out.push({
      file: config.path,
      ...(line !== undefined ? { line } : {}),
      kind,
      trigger,
      command,
      ...(argv ? { argv } : {}),
    });
  };
  if (!isRecord(data)) {
    return out;
  }

  if (config.path === '.claude/settings.json') {
    const status = data.statusLine;
    if (isRecord(status) && status.type === 'command' && typeof status.command === 'string') {
      emit('status-line', 'Claude Code status line', status.command, ['statusLine', 'command']);
    }
    for (const key of CLAUDE_HELPERS) {
      const command = data[key];
      if (typeof command === 'string') {
        emit('helper', `Claude Code ${key}`, command, [key]);
      }
    }
    hookCommands(data.hooks, 'Claude Code', emit);
  }
  if (config.path === '.gemini/settings.json') {
    hookCommands(data.hooks, 'Gemini CLI', emit);
  }

  const tool = MCP_TOOL[config.path];
  if (tool && isRecord(data.mcpServers)) {
    for (const [name, server] of Object.entries(data.mcpServers)) {
      if (isRecord(server) && typeof server.command === 'string') {
        emit(
          'mcp-server',
          `${tool} MCP server "${name}"`,
          withArgs(server.command, server.args),
          ['mcpServers', name, 'command'],
          [server.command, ...argList(server.args)],
        );
      }
    }
  }

  if (config.path === '.vscode/tasks.json' && Array.isArray(data.tasks)) {
    data.tasks.forEach((task, i) => {
      if (!isRecord(task) || !isRecord(task.runOptions) || task.runOptions.runOn !== 'folderOpen') {
        return;
      }
      const label = typeof task.label === 'string' ? task.label : `#${i}`;
      const trigger = `VS Code folderOpen task "${label}"`;
      if (typeof task.command === 'string') {
        emit('task', trigger, withArgs(task.command, task.args), ['tasks', i, 'command']);
      } else if (typeof task.script === 'string') {
        emit('task', trigger, `npm run ${task.script}`, ['tasks', i, 'script']);
      }
      for (const platform of TASK_PLATFORMS) {
        const o = task[platform];
        if (isRecord(o) && typeof o.command === 'string') {
          emit('task', trigger, withArgs(o.command, o.args ?? task.args), [
            'tasks',
            i,
            platform,
            'command',
          ]);
        }
      }
    });
  }
  return out;
}

/** Project-root variables a hook or task uses to reach repo files. */
const ROOT_VARS =
  /"?\$\{?(?:CLAUDE_PROJECT_DIR|GEMINI_PROJECT_DIR|workspaceFolder|workspaceRoot)\}?"?\//g;

/**
 * Repo-relative script files a command runs (`node .github/init.js`, `"$CLAUDE_PROJECT_DIR"/x.sh`).
 * Absolute, home-relative, and parent-escaping paths are not repo files.
 */
export function repoLocalFiles(command: string): string[] {
  const normalized = command.replace(ROOT_VARS, '');
  const re =
    /(?:^|[\s'"=(;&|])([\w.\-/~]+\.(?:[cm]?js|jsx|ts|tsx|sh|py|ps1|rb|php|pl|bat|cmd|node))\b/gi;
  const files = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(normalized)) !== null) {
    const path = m[1]!;
    if (path.startsWith('/') || path.startsWith('~') || path.split('/').includes('..')) {
      continue;
    }
    files.add(path.replace(/^\.\//, ''));
  }
  return [...files];
}

/**
 * Each MCP `command`/arg taken whole as a possible repo path (`my dir/s.js`, `./server`);
 * the collector keeps only the ones that exist. Flags, URLs, and paths that leave the repo
 * are dropped.
 */
function argvCandidates(argv: string[]): string[] {
  return argv
    .map((a) => a.replace(ROOT_VARS, '').replace(/^\.\//, ''))
    .filter(
      (a) =>
        a !== '' &&
        !a.startsWith('-') &&
        !/^[/~\\]/.test(a) &&
        !a.includes('://') &&
        !a.split(/[/\\]/).includes('..'),
    );
}

/** Repo paths a command may run: script paths in its text, plus whole MCP argv tokens. */
function candidateTargets(cmd: AutoRunCommand): string[] {
  return [...new Set([...repoLocalFiles(cmd.command), ...argvCandidates(cmd.argv ?? [])])];
}

/** Every repo file any committed config would run on open — what the collector must read. */
export function openExecTargets(configs: OpenExecConfig[]): string[] {
  const files = new Set<string>();
  for (const config of configs) {
    try {
      for (const cmd of autoRunCommands(config)) {
        candidateTargets(cmd).forEach((f) => files.add(f));
      }
    } catch {
      /* malformed config: the analyzer reports it */
    }
  }
  return [...files];
}

function targetNotes(path: string, t: OpenExecTarget): string[] {
  const notes: string[] = [];
  if (t.size >= LARGE_TARGET_BYTES) {
    notes.push(`${path} is ${(t.size / 1_000_000).toFixed(1)} MB`);
  }
  if (t.longestLine >= LONG_LINE_CHARS) {
    notes.push(
      `${path} has a ${t.longestLine.toLocaleString('en-US')}-character line (minified or obfuscated)`,
    );
  }
  return notes;
}

const SINK_ID = 'sink:open-exec:developer-credentials';

export function analyzeOpenExec(inputs: OpenExecInputs): AnalyzerResult {
  const result = emptyResult();
  let sinkAdded = false;
  for (const config of inputs.configs) {
    let commands: AutoRunCommand[];
    try {
      commands = autoRunCommands(config);
    } catch (err) {
      result.diagnostics.push({
        level: 'error',
        message: `failed to parse ${config.path}: ${(err as Error).message}`,
      });
      continue;
    }
    commands.forEach((cmd, i) => {
      const targets = candidateTargets(cmd).filter((f) => inputs.targets[f]);
      // A published MCP package is a capability question (../agent), not repo code on open.
      if (cmd.kind === 'mcp-server' && targets.length === 0) {
        return;
      }
      if (!sinkAdded) {
        result.nodes.push({
          id: SINK_ID,
          kind: 'sink',
          sinkKind: 'credential',
          identity: 'your local credentials (GitHub, npm, cloud, SSH)',
        });
        sinkAdded = true;
      }
      if (cmd.line === undefined) {
        // JSON.parse found the command but the locator could not place it (e.g. duplicate
        // keys). Without a line the finding would only warn, so fail closed instead.
        result.diagnostics.push({
          level: 'error',
          message:
            `${cmd.file}: could not locate the ${cmd.trigger} command (duplicate keys?); ` +
            `failing closed`,
        });
      }
      const entryId = `entry:open-time-exec:${cmd.file}:${i}`;
      result.nodes.push({
        id: entryId,
        kind: 'entry',
        entryKind: 'open-time-exec',
        exposure: 3,
        label: `${cmd.trigger} (${cmd.file})`,
        ...(cmd.line !== undefined ? { evidence: { file: cmd.file, line: cmd.line } } : {}),
        openExec: {
          trigger: cmd.trigger,
          command: cmd.command,
          targets,
          notes: targets.flatMap((f) => targetNotes(f, inputs.targets[f]!)),
        },
      });
      result.edges.push({ from: entryId, to: SINK_ID, edge: { kind: 'reaches' } });
    });
  }
  return result;
}
