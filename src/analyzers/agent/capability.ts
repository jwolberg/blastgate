import type { CapabilityClass } from '../../graph/types';

/** A parsed capability grant from a committed agent/MCP config (KTD8). */
export interface Grant {
  source: string;
  capabilityClass: CapabilityClass;
  scope: string;
  exceedsBaseline: boolean;
}

/** Env vars that resolve inside the repo/workspace, vs. ones that escape it. */
const IN_REPO_VARS = new Set([
  'CLAUDE_PROJECT_DIR',
  'BLASTGATE_PROJECT_DIR',
  'GITHUB_WORKSPACE',
  'CLAUDE_PLUGIN_ROOT',
  'PWD',
]);
const HOME_VARS = new Set(['HOME', 'USERPROFILE']);

/** Resolve `${VAR}` / `${VAR:-default}` to a marker so scope can be classified without the runtime value. */
export function resolveVars(s: string): string {
  return s.replace(/\$\{([A-Za-z0-9_]+)(:-[^}]*)?\}/g, (_full, name: string) => {
    if (IN_REPO_VARS.has(name)) {
      return '<REPO>';
    }
    if (HOME_VARS.has(name)) {
      return '<HOME>';
    }
    return `<${name}>`;
  });
}

function looksLikePath(resolved: string): boolean {
  return resolved === '/' || /^(\/|~|\.\.?\/|<[A-Z_]+>)/.test(resolved);
}

export function isPathOutsideRepo(rawPath: string): boolean {
  const p = resolveVars(rawPath);
  if (p === '/' || p.startsWith('~') || p.includes('<HOME>')) {
    return true;
  }
  if (p.startsWith('<REPO>') || p.startsWith('./')) {
    return false;
  }
  if (/(^|\/)\.\.(\/|$)/.test(p)) {
    return true;
  }
  return p.startsWith('/');
}

export interface McpServer {
  url?: string;
  type?: string;
  command?: string;
  args?: string[];
}

function hostOf(url: string): string {
  try {
    return new URL(resolveVars(url)).host || url;
  } catch {
    return url;
  }
}

/**
 * Map an MCP server declaration to capability grants. A remote server is a network
 * grant; an stdio server is inspected: a `bash -c`/`sh -c` command is a shell
 * grant, a filesystem path argument outside the repo is a filesystem grant, and
 * anything else is an in-baseline tool-providing server (so a normal
 * project-scoped server — e.g. Blastgate's own — is not flagged).
 */
export function classifyServer(source: string, name: string, server: McpServer): Grant[] {
  if (typeof server.url === 'string') {
    const host = hostOf(server.url);
    return [
      {
        source,
        capabilityClass: 'network',
        scope: host,
        exceedsBaseline: host.includes('<') || host === '',
      },
    ];
  }

  const grants: Grant[] = [];
  const command = server.command ?? '';
  const args = (server.args ?? []).filter((a): a is string => typeof a === 'string');

  if (/^(bash|sh|zsh)$/.test(command) && args.includes('-c')) {
    grants.push({
      source,
      capabilityClass: 'shell',
      scope: `${command} -c`,
      exceedsBaseline: true,
    });
  }
  for (const arg of args) {
    const resolved = resolveVars(arg);
    if (looksLikePath(resolved) && isPathOutsideRepo(arg)) {
      grants.push({
        source,
        capabilityClass: 'filesystem',
        scope: resolved,
        exceedsBaseline: true,
      });
    }
  }
  if (grants.length === 0) {
    grants.push({ source, capabilityClass: 'tool', scope: name, exceedsBaseline: false });
  }
  return grants;
}

/** Bash rules whose prefix is a known env/exec wrapper are effectively unrestricted shell. */
const WRAPPER_BYPASS = /^\s*(npx|docker\s+exec|devbox\s+run|env|bash|sh|xargs|nohup|time)\b/;

function bashExceedsBaseline(spec: string | undefined): boolean {
  if (!spec || spec.trim() === '*') {
    return true;
  }
  return WRAPPER_BYPASS.test(spec);
}

/** Classify a `.claude/settings.json` permission rule (`Tool` or `Tool(specifier)`). */
export function classifyRule(source: string, rule: string): Grant | null {
  const m = /^([A-Za-z_]+)(?:\((.*)\))?$/.exec(rule.trim());
  if (!m || !m[1]) {
    return null;
  }
  const tool = m[1];
  const spec = m[2];
  switch (tool) {
    case 'Bash':
      return {
        source,
        capabilityClass: 'shell',
        scope: spec ?? '*',
        exceedsBaseline: bashExceedsBaseline(spec),
      };
    case 'Read':
    case 'Edit':
    case 'Write':
      return {
        source,
        capabilityClass: 'filesystem',
        scope: spec ?? '.',
        exceedsBaseline: spec !== undefined && isPathOutsideRepo(spec),
      };
    case 'WebFetch':
      return {
        source,
        capabilityClass: 'network',
        scope: spec ?? '*',
        exceedsBaseline: spec === undefined || /domain:\*/.test(spec),
      };
    default:
      return { source, capabilityClass: 'tool', scope: rule, exceedsBaseline: false };
  }
}

/** A committed `type: command` hook runs outside the permission gate — always a shell grant. */
export function hasCommandHook(hooks: unknown): boolean {
  if (Array.isArray(hooks)) {
    return hooks.some(hasCommandHook);
  }
  if (hooks && typeof hooks === 'object') {
    const record = hooks as Record<string, unknown>;
    if (record.type === 'command') {
      return true;
    }
    return Object.values(record).some(hasCommandHook);
  }
  return false;
}
