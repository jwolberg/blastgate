import { parse } from 'yaml';

export interface StepSpec {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
}

export interface JobSpec {
  permissions?: unknown;
  steps?: StepSpec[];
  env?: Record<string, unknown>;
  secrets?: unknown;
}

export interface WorkflowSpec {
  on?: unknown;
  permissions?: unknown;
  jobs?: Record<string, JobSpec>;
}

/** Parse Actions YAML (KTD7). `yaml`'s 1.2 core schema keeps `on:` a string key. Throws on invalid YAML. */
export function parseWorkflow(yamlText: string): WorkflowSpec {
  return (parse(yamlText) ?? {}) as WorkflowSpec;
}

const UNTRUSTED_EVENTS = new Set([
  'pull_request',
  'pull_request_target',
  'workflow_run',
  'issue_comment',
  'pull_request_review',
  'pull_request_review_comment',
]);

/** Normalize the three legal `on:` forms (string, array, map) to an event-name list. */
export function normalizeTriggers(on: unknown): string[] {
  if (typeof on === 'string') {
    return [on];
  }
  if (Array.isArray(on)) {
    return on.filter((x): x is string => typeof x === 'string');
  }
  if (on && typeof on === 'object') {
    return Object.keys(on as Record<string, unknown>);
  }
  return [];
}

export function untrustedTriggers(triggers: string[]): string[] {
  return triggers.filter((t) => UNTRUSTED_EVENTS.has(t));
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((v) => collectStrings(v, out));
  } else if (value && typeof value === 'object') {
    Object.values(value as Record<string, unknown>).forEach((v) => collectStrings(v, out));
  }
}

const SECRET_RE = /\bsecrets\.([A-Za-z0-9_]+)/g;
const TOJSON_SECRETS_RE = /toJSON\(\s*secrets\s*\)/;

/**
 * Expression-aware secret scan: matches `secrets.X` anywhere in the job's string
 * scalars (env / with / run / if), including inside `format(...)`, and detects the
 * bulk `toJSON(secrets)` form. `GITHUB_TOKEN` is governed by permissions, not this
 * scan, so it is excluded here.
 */
export function findSecretRefs(job: JobSpec): { names: string[]; usesAllSecrets: boolean } {
  const strings: string[] = [];
  collectStrings(job, strings);
  const names = new Set<string>();
  let usesAllSecrets = false;
  for (const s of strings) {
    SECRET_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SECRET_RE.exec(s)) !== null) {
      if (m[1] && m[1] !== 'GITHUB_TOKEN') {
        names.add(m[1]);
      }
    }
    if (TOJSON_SECRETS_RE.test(s)) {
      usesAllSecrets = true;
    }
  }
  return { names: [...names], usesAllSecrets };
}

const INSTALL_RE = /\b(npm\s+(ci|install|i)|yarn(\s+install)?|pnpm\s+(install|i))\b/;

/** A step that runs a dependency install (where a poisoned lifecycle script would execute). */
export function hasInstallStep(job: JobSpec): boolean {
  return (job.steps ?? []).some((step) => {
    if (typeof step.run === 'string' && INSTALL_RE.test(step.run)) {
      return true;
    }
    return typeof step.uses === 'string' && /^actions\/setup-node@/.test(step.uses);
  });
}

/** Pinned ⇔ `@<40-hex-sha>` (or a docker `@sha256:` digest); local `./` actions carry no external risk. */
export function isPinnedAction(uses: string): boolean {
  if (uses.startsWith('./') || uses.startsWith('../')) {
    return true;
  }
  const at = uses.lastIndexOf('@');
  if (at === -1) {
    return false;
  }
  const ref = uses.slice(at + 1);
  return /^[0-9a-f]{40}$/i.test(ref) || /^sha256:[0-9a-f]{64}$/i.test(ref);
}

export function unpinnedActions(job: JobSpec): string[] {
  return (job.steps ?? [])
    .map((s) => s.uses)
    .filter((u): u is string => typeof u === 'string')
    .filter((u) => !isPinnedAction(u));
}

export interface TokenPermissions {
  raw: string;
  overBroad: boolean;
  known: boolean;
}

/** Resolve effective GITHUB_TOKEN permissions: job-level overrides workflow-level; absent = inherited/unknown. */
export function resolvePermissions(workflow: WorkflowSpec, job: JobSpec): TokenPermissions {
  const p = job.permissions ?? workflow.permissions;
  if (p === undefined) {
    return { raw: 'inherited (repo default)', overBroad: false, known: false };
  }
  if (p === 'write-all') {
    return { raw: 'write-all', overBroad: true, known: true };
  }
  if (p === 'read-all') {
    return { raw: 'read-all', overBroad: false, known: true };
  }
  if (p && typeof p === 'object') {
    const entries = Object.entries(p as Record<string, unknown>);
    const overBroad = entries.some(([, v]) => v === 'write');
    const raw = entries.map(([k, v]) => `${k}:${String(v)}`).join(', ') || '{}';
    return { raw, overBroad, known: true };
  }
  return { raw: String(p), overBroad: false, known: true };
}
