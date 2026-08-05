// src/analyzers/types.ts
function emptyResult() {
  return { nodes: [], edges: [], diagnostics: [] };
}
function applyResult(ag, result) {
  for (const node of result.nodes) {
    ag.addNode(node);
  }
  for (const e of result.edges) {
    ag.addEdge(e.from, e.to, e.edge);
  }
}

// src/analyzers/agent/config-diff.ts
var AGENT_INSTRUCTION_PATHS = [
  "CLAUDE.md",
  "AGENTS.md",
  ".cursorrules",
  ".github/copilot-instructions.md"
];
function classifyConfigChange(f) {
  if (f.head === null) {
    return null;
  }
  if (f.base === null) {
    return "added";
  }
  return f.base === f.head ? null : "changed";
}
function analyzeAgentDiff(inputs) {
  const result = emptyResult();
  for (const f of inputs.files) {
    const change = classifyConfigChange(f);
    if (!change) {
      continue;
    }
    const entryId = `entry:agent-config-change:${f.path}`;
    const sinkId = `sink:agent-config:${f.path}`;
    const entry = {
      id: entryId,
      kind: "entry",
      entryKind: "agent-config-change",
      exposure: 3,
      label: `agent instruction file ${f.path} ${change} by this change`
    };
    const sink = {
      id: sinkId,
      kind: "sink",
      sinkKind: "privileged-capability",
      identity: `agent instructions (${f.path})`
    };
    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: "injects" } });
  }
  return result;
}

// src/analyzers/agent/capability.ts
var IN_REPO_VARS = /* @__PURE__ */ new Set([
  "CLAUDE_PROJECT_DIR",
  "BLASTGATE_PROJECT_DIR",
  "GITHUB_WORKSPACE",
  "CLAUDE_PLUGIN_ROOT",
  "PWD"
]);
var HOME_VARS = /* @__PURE__ */ new Set(["HOME", "USERPROFILE"]);
function resolveVars(s) {
  return s.replace(/\$\{([A-Za-z0-9_]+)(:-[^}]*)?\}/g, (_full, name) => {
    if (IN_REPO_VARS.has(name)) {
      return "<REPO>";
    }
    if (HOME_VARS.has(name)) {
      return "<HOME>";
    }
    return `<${name}>`;
  });
}
function looksLikePath(resolved) {
  return resolved === "/" || /^(\/|~|\.\.?\/|<[A-Z_]+>)/.test(resolved);
}
function isPathOutsideRepo(rawPath) {
  const p = resolveVars(rawPath);
  if (p === "/" || p.startsWith("~") || p.includes("<HOME>")) {
    return true;
  }
  if (p.startsWith("<REPO>") || p.startsWith("./")) {
    return false;
  }
  if (/(^|\/)\.\.(\/|$)/.test(p)) {
    return true;
  }
  return p.startsWith("/");
}
function hostOf(url) {
  try {
    return new URL(resolveVars(url)).host || url;
  } catch {
    return url;
  }
}
function classifyServer(source, name, server) {
  if (typeof server.url === "string") {
    const host = hostOf(server.url);
    return [
      {
        source,
        capabilityClass: "network",
        scope: host,
        exceedsBaseline: host.includes("<") || host === ""
      }
    ];
  }
  const grants = [];
  const command = server.command ?? "";
  const args = (server.args ?? []).filter((a) => typeof a === "string");
  if (/^(bash|sh|zsh)$/.test(command) && args.includes("-c")) {
    grants.push({
      source,
      capabilityClass: "shell",
      scope: `${command} -c`,
      exceedsBaseline: true
    });
  }
  for (const arg of args) {
    const resolved = resolveVars(arg);
    if (looksLikePath(resolved) && isPathOutsideRepo(arg)) {
      grants.push({
        source,
        capabilityClass: "filesystem",
        scope: resolved,
        exceedsBaseline: true
      });
    }
  }
  if (grants.length === 0) {
    grants.push({ source, capabilityClass: "tool", scope: name, exceedsBaseline: false });
  }
  return grants;
}
var WRAPPER_BYPASS = /^\s*(npx|docker\s+exec|devbox\s+run|env|bash|sh|xargs|nohup|time)\b/;
function bashExceedsBaseline(spec) {
  if (!spec || spec.trim() === "*") {
    return true;
  }
  return WRAPPER_BYPASS.test(spec);
}
function classifyRule(source, rule) {
  const m = /^([A-Za-z_]+)(?:\((.*)\))?$/.exec(rule.trim());
  if (!m || !m[1]) {
    return null;
  }
  const tool = m[1];
  const spec = m[2];
  switch (tool) {
    case "Bash":
      return {
        source,
        capabilityClass: "shell",
        scope: spec ?? "*",
        exceedsBaseline: bashExceedsBaseline(spec)
      };
    case "Read":
    case "Edit":
    case "Write":
      return {
        source,
        capabilityClass: "filesystem",
        scope: spec ?? ".",
        exceedsBaseline: spec !== void 0 && isPathOutsideRepo(spec)
      };
    case "WebFetch":
      return {
        source,
        capabilityClass: "network",
        scope: spec ?? "*",
        exceedsBaseline: spec === void 0 || /domain:\*/.test(spec)
      };
    default:
      return { source, capabilityClass: "tool", scope: rule, exceedsBaseline: false };
  }
}
function hasCommandHook(hooks) {
  if (Array.isArray(hooks)) {
    return hooks.some(hasCommandHook);
  }
  if (hooks && typeof hooks === "object") {
    const record = hooks;
    if (record.type === "command") {
      return true;
    }
    return Object.values(record).some(hasCommandHook);
  }
  return false;
}

// src/analyzers/agent/index.ts
function parseServers(source, json, result) {
  try {
    const data = JSON.parse(json);
    const servers = data.mcpServers ?? {};
    return Object.entries(servers).flatMap(
      ([name, server]) => classifyServer(source, name, server)
    );
  } catch (err) {
    result.diagnostics.push({
      level: "error",
      message: `failed to parse ${source}: ${err.message}`
    });
    return [];
  }
}
function parseSettings(json, result) {
  try {
    const data = JSON.parse(json);
    const grants = [];
    const rules = [...data.permissions?.allow ?? [], ...data.permissions?.ask ?? []];
    for (const rule of rules) {
      const grant = classifyRule(".claude/settings.json", rule);
      if (grant) {
        grants.push(grant);
      }
    }
    if (hasCommandHook(data.hooks)) {
      grants.push({
        source: ".claude/settings.json (hook)",
        capabilityClass: "shell",
        scope: "command hook",
        exceedsBaseline: true,
        // Deterministic: a hook fires on an event, not because an injected prompt steered
        // the agent into it — so it is a privileged capability to review, not an injectable
        // surface (U18). The ` (hook)` source suffix keeps its entry id distinct from a
        // permission-rule shell grant on the same file.
        injectable: false
      });
    }
    return grants;
  } catch (err) {
    result.diagnostics.push({
      level: "error",
      message: `failed to parse .claude/settings.json: ${err.message}`
    });
    return [];
  }
}
function emitGrant(result, grant, index) {
  const grantId = `grant:${grant.source}:${grant.capabilityClass}:${index}`;
  result.nodes.push({
    id: grantId,
    kind: "agent-grant",
    source: grant.source,
    capabilityClass: grant.capabilityClass,
    scope: grant.scope,
    exceedsBaseline: grant.exceedsBaseline
  });
  if (!grant.exceedsBaseline) {
    return;
  }
  const entryId = `entry:agent:${grant.source}`;
  const sinkId = `sink:capability:${grant.capabilityClass}:${grant.scope}`;
  result.nodes.push({
    id: sinkId,
    kind: "sink",
    sinkKind: "privileged-capability",
    identity: `${grant.capabilityClass}:${grant.scope}`
  });
  if (grant.injectable === false) {
    const location = grant.source.replace(/ \(hook\)$/, "");
    result.nodes.push({
      id: entryId,
      kind: "entry",
      entryKind: "privileged-hook",
      exposure: 1,
      label: `${location} (committed hook)`
    });
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: "reaches" } });
  } else {
    result.nodes.push({
      id: entryId,
      kind: "entry",
      entryKind: "injectable-agent-surface",
      exposure: 2,
      label: `injectable agent surface (${grant.source})`
    });
    result.edges.push({ from: entryId, to: grantId, edge: { kind: "injects" } });
    result.edges.push({ from: grantId, to: sinkId, edge: { kind: "reaches" } });
  }
  result.diagnostics.push({
    level: "warn",
    message: `${grant.source}: ${grant.capabilityClass} grant "${grant.scope}" exceeds the least-privilege baseline (OWASP MCP02)`
  });
}
function analyzeAgents(inputs) {
  const result = emptyResult();
  const grants = [];
  if (inputs.mcpJson) {
    grants.push(...parseServers(".mcp.json", inputs.mcpJson, result));
  }
  if (inputs.cursorMcpJson) {
    grants.push(...parseServers(".cursor/mcp.json", inputs.cursorMcpJson, result));
  }
  if (inputs.claudeSettings) {
    grants.push(...parseSettings(inputs.claudeSettings, result));
  }
  grants.forEach((grant, index) => emitGrant(result, grant, index));
  return result;
}

// src/analyzers/ci/parse.ts
import { parse } from "yaml";
function parseWorkflow(yamlText) {
  return parse(yamlText) ?? {};
}
var UNTRUSTED_EVENTS = /* @__PURE__ */ new Set([
  "pull_request",
  "pull_request_target",
  "workflow_run",
  "issue_comment",
  "pull_request_review",
  "pull_request_review_comment"
]);
function normalizeTriggers(on) {
  if (typeof on === "string") {
    return [on];
  }
  if (Array.isArray(on)) {
    return on.filter((x) => typeof x === "string");
  }
  if (on && typeof on === "object") {
    return Object.keys(on);
  }
  return [];
}
function untrustedTriggers(triggers) {
  return triggers.filter((t) => UNTRUSTED_EVENTS.has(t));
}
function collectStrings(value, out) {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((v) => collectStrings(v, out));
  } else if (value && typeof value === "object") {
    Object.values(value).forEach((v) => collectStrings(v, out));
  }
}
var SECRET_RE = /\bsecrets\.([A-Za-z0-9_]+)/g;
var TOJSON_SECRETS_RE = /toJSON\(\s*secrets\s*\)/;
function findSecretRefs(job) {
  const strings = [];
  collectStrings(job, strings);
  const names = /* @__PURE__ */ new Set();
  let usesAllSecrets = false;
  for (const s of strings) {
    SECRET_RE.lastIndex = 0;
    let m;
    while ((m = SECRET_RE.exec(s)) !== null) {
      if (m[1] && m[1] !== "GITHUB_TOKEN") {
        names.add(m[1]);
      }
    }
    if (TOJSON_SECRETS_RE.test(s)) {
      usesAllSecrets = true;
    }
  }
  return { names: [...names], usesAllSecrets };
}
var INSTALL_RE = /\b(npm\s+(ci|install|i)|yarn(\s+install)?|pnpm\s+(install|i)|pip3?\s+install|python[\d.]*\s+-m\s+pip\s+install|python[\d.]*\s+setup\.py|uv\s+(pip\s+install|sync)|poetry\s+install|pipenv\s+install)\b/;
var TRUSTED_ROLE = /\b(OWNER|MEMBER|COLLABORATOR)\b/;
function hasActorGuard(job) {
  const cond = typeof job.if === "string" ? job.if : "";
  if (!cond) {
    return false;
  }
  if (/author_association/.test(cond) && TRUSTED_ROLE.test(cond)) {
    return true;
  }
  return /\bgithub\.(triggering_actor|actor)\b/.test(cond) && /(==|!=|fromJSON|contains)/.test(cond);
}
function hasInstallStep(job) {
  return (job.steps ?? []).some((step) => {
    if (typeof step.run === "string" && INSTALL_RE.test(step.run)) {
      return true;
    }
    return typeof step.uses === "string" && /^actions\/setup-node@/.test(step.uses);
  });
}
function isPinnedAction(uses) {
  if (uses.startsWith("./") || uses.startsWith("../")) {
    return true;
  }
  const at = uses.lastIndexOf("@");
  if (at === -1) {
    return false;
  }
  const ref = uses.slice(at + 1);
  return /^[0-9a-f]{40}$/i.test(ref) || /^sha256:[0-9a-f]{64}$/i.test(ref);
}
function unpinnedActions(job) {
  return (job.steps ?? []).map((s) => s.uses).filter((u) => typeof u === "string").filter((u) => !isPinnedAction(u));
}
function resolvePermissions(workflow, job) {
  const p = job.permissions ?? workflow.permissions;
  if (p === void 0) {
    return { raw: "inherited (repo default)", overBroad: false, known: false };
  }
  if (p === "write-all") {
    return { raw: "write-all", overBroad: true, known: true };
  }
  if (p === "read-all") {
    return { raw: "read-all", overBroad: false, known: true };
  }
  if (p && typeof p === "object") {
    const entries = Object.entries(p);
    const overBroad = entries.some(([, v]) => v === "write");
    const raw = entries.map(([k, v]) => `${k}:${String(v)}`).join(", ") || "{}";
    return { raw, overBroad, known: true };
  }
  return { raw: String(p), overBroad: false, known: true };
}

// src/analyzers/ci/injection.ts
var UNTRUSTED_TEXT_EVENTS = /* @__PURE__ */ new Set([
  "issues",
  "issue_comment",
  "pull_request_target",
  "pull_request",
  "pull_request_review",
  "pull_request_review_comment",
  "discussion",
  "discussion_comment"
]);
function untrustedTextTriggers(triggers) {
  return triggers.filter((t) => UNTRUSTED_TEXT_EVENTS.has(t));
}
var UNTRUSTED_TEXT_REF = /github\.event\.[\w.]*(?:body|title)\b/g;
var AGENT_ACTION_RE = /(?:anthropics\/claude|claude-code|opencode|aider|sweep-ai|gpt-engineer)/i;
function injectableTextRefs(job) {
  const strings = [];
  collectStrings(job, strings);
  const refs = /* @__PURE__ */ new Set();
  for (const s of strings) {
    for (const m of s.matchAll(UNTRUSTED_TEXT_REF)) {
      refs.add(m[0]);
    }
  }
  return [...refs];
}
function agentActionsUsed(job) {
  return (job.steps ?? []).map((s) => s.uses).filter((u) => typeof u === "string").filter((u) => AGENT_ACTION_RE.test(u));
}
function isInjectableAgentJob(job, triggers) {
  if (untrustedTextTriggers(triggers).length === 0) {
    return false;
  }
  return injectableTextRefs(job).length > 0 || agentActionsUsed(job).length > 0;
}

// src/analyzers/ci/index.ts
var CREDENTIAL_HINT = /(AWS|TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i;
function sinkKindFor(name) {
  return CREDENTIAL_HINT.test(name) ? "credential" : "secret";
}
function analyzeCi(inputs) {
  const result = emptyResult();
  for (const wf of inputs.workflows) {
    let spec;
    try {
      spec = parseWorkflow(wf.content);
    } catch (err) {
      result.diagnostics.push({
        level: "error",
        message: `failed to parse ${wf.path}: ${err.message}`
      });
      continue;
    }
    const triggers = normalizeTriggers(spec.on);
    const untrusted = untrustedTriggers(triggers);
    const forkTriggerable = untrusted.length > 0;
    const jobs = spec.jobs ?? {};
    for (const [jobId, job] of Object.entries(jobs)) {
      const { names: secretNames, usesAllSecrets } = findSecretRefs(job);
      const perms = resolvePermissions(spec, job);
      const jobNodeId = `job:${wf.path}#${jobId}`;
      const jobNode = {
        id: jobNodeId,
        kind: "ci-job",
        workflow: wf.path,
        job: jobId,
        triggers,
        secrets: secretNames,
        forkTriggerable,
        runsInstall: hasInstallStep(job)
      };
      result.nodes.push(jobNode);
      for (const name of secretNames) {
        const sinkId = `sink:secret:${name}`;
        result.nodes.push({
          id: sinkId,
          kind: "sink",
          sinkKind: sinkKindFor(name),
          identity: name
        });
        result.edges.push({ from: jobNodeId, to: sinkId, edge: { kind: "holds" } });
      }
      if (perms.overBroad) {
        const tokenSink = `sink:credential:GITHUB_TOKEN@${wf.path}#${jobId}`;
        result.nodes.push({
          id: tokenSink,
          kind: "sink",
          sinkKind: "credential",
          identity: `GITHUB_TOKEN (${perms.raw})`
        });
        result.edges.push({ from: jobNodeId, to: tokenSink, edge: { kind: "holds" } });
      }
      if (forkTriggerable) {
        const entryId = `entry:fork-pr:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: "entry",
          entryKind: "fork-pr",
          exposure: 3,
          label: `${untrusted.join("/")} reaches job ${jobId}`,
          guarded: hasActorGuard(job)
        });
        result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: "triggers" } });
      }
      if (isInjectableAgentJob(job, triggers) && !hasActorGuard(job)) {
        const refs = injectableTextRefs(job);
        const via = refs.length > 0 ? refs.join(", ") : agentActionsUsed(job).join(", ");
        const entryId = `entry:injection:${wf.path}#${jobId}`;
        result.nodes.push({
          id: entryId,
          kind: "entry",
          entryKind: "untrusted-text-injection",
          exposure: 3,
          label: `untrusted ${untrustedTextTriggers(triggers).join("/")} text reaches job ${jobId} (${via})`,
          guarded: false
        });
        result.edges.push({ from: entryId, to: jobNodeId, edge: { kind: "injects" } });
      }
      for (const u of unpinnedActions(job)) {
        result.diagnostics.push({
          level: "warn",
          message: `unpinned action \`${u}\` in ${wf.path}#${jobId} (pin to a full commit SHA)`
        });
      }
      if (perms.overBroad) {
        result.diagnostics.push({
          level: "warn",
          message: `over-broad GITHUB_TOKEN permissions (${perms.raw}) on ${wf.path}#${jobId}`
        });
      }
      if (usesAllSecrets || job.secrets === "inherit") {
        result.diagnostics.push({
          level: "warn",
          message: `${wf.path}#${jobId} exposes the full secret set (toJSON(secrets) or secrets: inherit)`
        });
      }
      if (hasInstallStep(job) && forkTriggerable && (secretNames.length > 0 || perms.overBroad)) {
        result.diagnostics.push({
          level: "warn",
          message: `pwn-request shape: ${wf.path}#${jobId} runs install on an untrusted trigger while holding secrets`
        });
      }
    }
  }
  return result;
}

// src/analyzers/deps/lockfile.ts
function packageName(nodeModulesPath) {
  return nodeModulesPath.replace(/^.*node_modules\//, "");
}
function isDirectDependency(nodeModulesPath) {
  return /^node_modules\/(@[^/]+\/)?[^/]+$/.test(nodeModulesPath);
}
function parsePackagesMap(json) {
  const data = JSON.parse(json);
  return data.packages ?? {};
}
function parseLockfile(json) {
  const packages = parsePackagesMap(json);
  const nodes = [];
  for (const [path, entry] of Object.entries(packages)) {
    if (path === "") {
      continue;
    }
    const pkg = packageName(path);
    const version = entry.version ?? "0.0.0";
    nodes.push({
      id: `dep:${pkg}@${version}`,
      kind: "dependency",
      pkg,
      version,
      isDirect: isDirectDependency(path),
      hasInstallScript: entry.hasInstallScript === true
    });
  }
  return nodes;
}

// src/analyzers/deps/diff.ts
function diffLockfiles(baseJson, headJson) {
  const head = parsePackagesMap(headJson);
  const base = baseJson ? parsePackagesMap(baseJson) : {};
  const changes = [];
  for (const [path, h] of Object.entries(head)) {
    if (path === "") {
      continue;
    }
    const pkg = packageName(path);
    const version = h.version ?? "0.0.0";
    const b = base[path];
    if (!b) {
      changes.push({ pkg, version, change: "added" });
    } else if (b.version !== h.version || b.resolved !== h.resolved || b.integrity !== h.integrity) {
      changes.push({ pkg, version, change: "changed" });
    }
  }
  return changes;
}

// src/analyzers/deps/npmrc.ts
var SECURITY_KEYS = /* @__PURE__ */ new Set([
  "registry",
  "ca",
  "cafile",
  "always-auth",
  "_auth",
  "proxy",
  "https-proxy"
]);
function isSecurityRelevant(key, value) {
  if (key === "strict-ssl") {
    return value === "false";
  }
  if (SECURITY_KEYS.has(key)) {
    return true;
  }
  return /:registry$/.test(key) || /_authToken$/.test(key);
}
function parseNpmrc(content) {
  const findings = [];
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }
    const eq = line.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (isSecurityRelevant(key, value)) {
      findings.push({ key, value });
    }
  }
  return findings;
}
function diffNpmrc(base, head) {
  if (!head) {
    return [];
  }
  const headFindings = parseNpmrc(head);
  if (base === null || base === void 0) {
    return headFindings;
  }
  const baseMap = new Map(parseNpmrc(base).map((f) => [f.key, f.value]));
  return headFindings.filter((f) => baseMap.get(f.key) !== f.value);
}

// src/analyzers/deps/index.ts
function analyzeDependencies(inputs) {
  const result = emptyResult();
  let deps;
  try {
    deps = parseLockfile(inputs.headLockfile);
  } catch (err) {
    result.diagnostics.push({
      level: "error",
      message: `failed to parse package-lock.json: ${err.message}`
    });
    return result;
  }
  result.nodes.push(...deps);
  if (inputs.baseLockfile !== void 0) {
    for (const change of diffLockfiles(inputs.baseLockfile, inputs.headLockfile)) {
      const depId = `dep:${change.pkg}@${change.version}`;
      const entryId = `entry:new-dep:${change.pkg}`;
      const entry = {
        id: entryId,
        kind: "entry",
        entryKind: "new-dependency",
        exposure: 1,
        label: `${change.change} dependency ${change.pkg}@${change.version}`
      };
      result.nodes.push(entry);
      result.edges.push({ from: entryId, to: depId, edge: { kind: "controls" } });
    }
  }
  for (const finding of diffNpmrc(inputs.baseNpmrc, inputs.npmrc)) {
    result.nodes.push({
      id: `entry:npmrc:${finding.key}`,
      kind: "entry",
      entryKind: "new-dependency",
      exposure: 2,
      label: `.npmrc ${finding.key} set or changed (supply-chain redirect signal)`
    });
  }
  return result;
}

// src/analyzers/exec/divergence.ts
var CI_MARKERS = [
  "CI",
  "CONTINUOUS_INTEGRATION",
  "GITHUB_ACTIONS",
  "GITLAB_CI",
  "TF_BUILD",
  "JENKINS_URL",
  "CIRCLECI",
  "TRAVIS",
  "BUILDKITE",
  "RUNNER_OS",
  "RUNNER_NAME"
];
var MARKER_ALT = CI_MARKERS.join("|");
var OPT_ENV_PREFIX = String.raw`(?:process\.env\.|env\.|\$\{?)?`;
var CI_BRANCH_PATTERNS = [
  new RegExp(String.raw`[!(]\s*${OPT_ENV_PREFIX}(?:${MARKER_ALT})\b`),
  new RegExp(String.raw`\b(?:${MARKER_ALT})\b\s*(?:===|!==|==|!=|&&|\|\||\?)`),
  new RegExp(String.raw`\[\s*-[znf]\s+"?\$\{?(?:${MARKER_ALT})\}?"?\s*\]`)
];
function firstCiMarker(source) {
  for (const m of CI_MARKERS) {
    if (new RegExp(String.raw`\b${m}\b`).test(source)) {
      return m;
    }
  }
  return void 0;
}
var CONTAINER_PATTERNS = [
  [/\/\.dockerenv/, "/.dockerenv"],
  [/\/proc\/(?:1|self)\/cgroup/, "/proc/1/cgroup"]
];
var TTY_PATTERNS = [
  [/\.isTTY\b/, "isTTY"],
  [/\bisatty\s*\(/, "isatty"],
  [/\[\s*-t\s+[012]\s*\]/, "test -t"],
  [/\btty\s+-s\b/, "tty -s"]
];
function detectDivergence(source) {
  const hits = [];
  const seen = /* @__PURE__ */ new Set();
  const add = (kind, marker) => {
    const key = `${kind}:${marker}`;
    if (!seen.has(key)) {
      seen.add(key);
      hits.push({ kind, marker });
    }
  };
  if (CI_BRANCH_PATTERNS.some((re) => re.test(source))) {
    add("ci", firstCiMarker(source) ?? "CI");
  }
  for (const [re, marker] of CONTAINER_PATTERNS) {
    if (re.test(source)) {
      add("container", marker);
    }
  }
  for (const [re, marker] of TTY_PATTERNS) {
    if (re.test(source)) {
      add("tty", marker);
    }
  }
  return hits;
}

// src/analyzers/exec/index.ts
var KIND_LABEL = {
  ci: "CI",
  container: "a container",
  tty: "an interactive terminal"
};
function analyzeExec(inputs) {
  const result = emptyResult();
  for (const script of inputs.scripts) {
    const hits = detectDivergence(script.source);
    if (hits.length === 0) {
      continue;
    }
    const environs = [...new Set(hits.map((h) => KIND_LABEL[h.kind]))].join(" / ");
    const markers = [...new Set(hits.map((h) => h.marker))].join(", ");
    const entryId = `entry:ci-divergent:${script.name}`;
    const sinkId = `sink:exec:${script.name}`;
    const entry = {
      id: entryId,
      kind: "entry",
      entryKind: "ci-divergent",
      exposure: 2,
      label: `install/build script ${script.name} runs differently under ${environs} (${markers})`
    };
    const sink = {
      id: sinkId,
      kind: "sink",
      sinkKind: "privileged-capability",
      identity: `install/build-time execution (${script.name})`
    };
    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: "reaches" } });
  }
  return result;
}

// src/analyzers/integrity/self-integrity.ts
var GATE_CONFIG_PATHS = ["plugin/hooks/hooks.json", ".mcp.json", ".claude/settings.json"];
var REFERENCES_GATE = /blastgate/i;
function gateEnforcementRemoved(f) {
  const wasWired = f.base !== null && REFERENCES_GATE.test(f.base);
  const stillWired = f.head !== null && REFERENCES_GATE.test(f.head);
  return wasWired && !stillWired;
}
function analyzeSelfIntegrity(inputs) {
  const result = emptyResult();
  for (const f of inputs.files) {
    if (!gateEnforcementRemoved(f)) {
      continue;
    }
    const entryId = `entry:gate-tamper:${f.path}`;
    const sinkId = `sink:gate-integrity:${f.path}`;
    const entry = {
      id: entryId,
      kind: "entry",
      entryKind: "gate-tamper",
      exposure: 3,
      label: `Blastgate enforcement removed from ${f.path}`
    };
    const sink = {
      id: sinkId,
      kind: "sink",
      sinkKind: "privileged-capability",
      identity: `gate enforcement (${f.path})`
    };
    result.nodes.push(entry, sink);
    result.edges.push({ from: entryId, to: sinkId, edge: { kind: "injects" } });
  }
  return result;
}

// src/analyzers/pydeps/index.ts
var PYTHON_INSTALL_MANIFESTS = ["setup.py"];
function analyzePyDeps(inputs) {
  const result = emptyResult();
  for (const m of inputs.manifests) {
    if (m.head === null) {
      continue;
    }
    const depId = `dep:python:${m.path}`;
    const dep = {
      id: depId,
      kind: "dependency",
      pkg: m.path,
      version: "install-time",
      isDirect: true,
      hasInstallScript: true,
      ecosystem: "python"
    };
    result.nodes.push(dep);
    const introduced = m.base === null || m.base !== m.head;
    if (introduced) {
      const entryId = `entry:new-dep:python:${m.path}`;
      result.nodes.push({
        id: entryId,
        kind: "entry",
        entryKind: "new-dependency",
        exposure: 1,
        label: `${m.path} (Python install-time code) added or changed`
      });
      result.edges.push({ from: entryId, to: depId, edge: { kind: "controls" } });
    }
  }
  return result;
}

// src/graph/graph.ts
import { DirectedGraph } from "graphology";
var AttackGraph = class {
  graph;
  constructor() {
    this.graph = new DirectedGraph({ allowSelfLoops: false });
  }
  /** Idempotent: adding a node with an existing id is a no-op. */
  addNode(node) {
    if (!this.graph.hasNode(node.id)) {
      this.graph.addNode(node.id, node);
    }
  }
  /** Idempotent on (from, to): merges rather than throwing on a repeat edge. */
  addEdge(from, to, edge) {
    this.graph.mergeDirectedEdge(from, to, edge);
  }
  node(id) {
    return this.graph.getNodeAttributes(id);
  }
  entryNodes() {
    return this.nodesOfKind("entry");
  }
  sinkNodes() {
    return this.nodesOfKind("sink");
  }
  nodesOfKind(kind) {
    const out = [];
    this.graph.forEachNode((_id, attrs) => {
      if (attrs.kind === kind) {
        out.push(attrs);
      }
    });
    return out;
  }
};

// src/engine/build.ts
function synthesizeCrossLayerEdges(ag) {
  const deps = [];
  const jobs = [];
  ag.graph.forEachNode((_id, n) => {
    if (n.kind === "dependency") {
      deps.push(n);
    } else if (n.kind === "ci-job") {
      jobs.push(n);
    }
  });
  for (const dep of deps) {
    if (!dep.hasInstallScript) {
      continue;
    }
    for (const job of jobs) {
      if (job.runsInstall && job.forkTriggerable) {
        ag.addEdge(dep.id, job.id, { kind: "runs-in" });
      }
    }
  }
}
function buildGraph(inputs) {
  const ag = new AttackGraph();
  const diagnostics = [];
  const results = [
    inputs.deps ? analyzeDependencies(inputs.deps) : void 0,
    inputs.pydeps ? analyzePyDeps(inputs.pydeps) : void 0,
    inputs.ci ? analyzeCi(inputs.ci) : void 0,
    inputs.agent ? analyzeAgents(inputs.agent) : void 0,
    inputs.exec ? analyzeExec(inputs.exec) : void 0,
    inputs.agentDiff ? analyzeAgentDiff(inputs.agentDiff) : void 0,
    inputs.selfIntegrity ? analyzeSelfIntegrity(inputs.selfIntegrity) : void 0,
    // Merged last: its entry→dep edge targets a dependency node the deps analyzer emits.
    inputs.provenance
  ];
  for (const result of results) {
    if (!result) {
      continue;
    }
    applyResult(ag, result);
    diagnostics.push(...result.diagnostics);
  }
  synthesizeCrossLayerEdges(ag);
  return { graph: ag, diagnostics };
}

// src/findings/finding.ts
function tierForSink(kind) {
  return kind === "privileged-capability" ? "warn" : "fail";
}

// src/taxonomy/label.ts
function labelPath(path) {
  const hasOverBaselineGrant = path.nodes.some(
    (n) => n.kind === "agent-grant" && n.exceedsBaseline
  );
  let agentic;
  let mcp;
  switch (path.entry.entryKind) {
    case "new-dependency":
      agentic = "ASI04";
      mcp = "MCP04";
      break;
    case "fork-pr":
      agentic = "ASI03";
      mcp = void 0;
      break;
    case "injectable-agent-surface":
      agentic = "ASI01";
      mcp = "MCP10";
      break;
    case "ci-divergent":
      agentic = "ASI04";
      mcp = void 0;
      break;
    case "privileged-hook":
      agentic = "ASI03";
      mcp = "MCP02";
      break;
    case "untrusted-text-injection":
      agentic = "ASI01";
      mcp = "MCP10";
      break;
    case "agent-config-change":
      agentic = "ASI01";
      mcp = "MCP10";
      break;
    case "gate-tamper":
      break;
  }
  if (hasOverBaselineGrant) {
    mcp = "MCP02";
    agentic ??= "ASI03";
  }
  return { agentic, mcp };
}

// src/graph/ranking.ts
var SINK_WEIGHT = {
  secret: 3,
  credential: 3,
  "privileged-capability": 1
};
var ENTRY_KIND_EXPOSURE = {
  // Untrusted public text (issue/PR body) reaching an agent is the most exposed entry.
  "untrusted-text-injection": 3,
  // Agent instructions introduced by an untrusted diff — a prompt injection at review time.
  "agent-config-change": 3,
  // A change that removes the gate's own enforcement — disabling the control itself.
  "gate-tamper": 3,
  "fork-pr": 3,
  "injectable-agent-surface": 2,
  "ci-divergent": 2,
  "new-dependency": 1,
  "privileged-hook": 1
};
function score(path) {
  return SINK_WEIGHT[path.sink.sinkKind] * 100 + ENTRY_KIND_EXPOSURE[path.entry.entryKind] * 10 + path.entry.exposure;
}
function rankFindings(paths) {
  return paths.map((path) => ({ path, labels: labelPath(path), score: score(path) })).sort((a, b) => b.score - a.score);
}

// src/graph/reachability.ts
import { bidirectional } from "graphology-shortest-path";
var byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
function reachablePaths(ag) {
  const entries = [...ag.entryNodes()].sort(byId);
  const sinks = [...ag.sinkNodes()].sort(byId);
  const paths = [];
  for (const entry of entries) {
    for (const sink of sinks) {
      const ids = bidirectional(ag.graph, entry.id, sink.id);
      if (!ids) {
        continue;
      }
      paths.push({
        entry,
        sink,
        nodes: ids.map((id) => ag.node(id)),
        hops: ids.length - 1
      });
    }
  }
  return paths;
}

// src/taxonomy/owasp.ts
var OWASP_AGENTIC_VERSION = "2026";
var OWASP_MCP_VERSION = "2025";
function agenticLabel(id) {
  return `${id}:${OWASP_AGENTIC_VERSION}`;
}
function mcpLabel(id) {
  return `${id}:${OWASP_MCP_VERSION}`;
}

// src/engine/checks.ts
function nodeLabel(n) {
  switch (n.kind) {
    case "entry":
      return n.label;
    case "dependency":
      return `${n.pkg}@${n.version}`;
    case "ci-job":
      return `${n.workflow}#${n.job}`;
    case "agent-grant":
      return `${n.source} (${n.capabilityClass}:${n.scope})`;
    case "sink":
      return n.identity;
  }
}
function find(path, kind) {
  return path.nodes.find((n) => n.kind === kind);
}
function isGuardedForkPr(path) {
  return path.entry.entryKind === "fork-pr" && path.entry.guarded === true;
}
function describe(path) {
  const dep = find(path, "dependency");
  const job = find(path, "ci-job");
  const grant = find(path, "agent-grant");
  const sink = path.sink;
  const isSecret = sink.sinkKind === "secret" || sink.sinkKind === "credential";
  if (path.entry.entryKind === "untrusted-text-injection") {
    const where = job ? `${job.workflow}#${job.job}` : "the workflow";
    return {
      reason: `${path.entry.label} \u2014 attacker-authored text from an untrusted event is read by job ${where}, which holds ${sink.sinkKind} ${sink.identity}. A prompt/command injection in that text (e.g. an HTML comment invisible on the rendered page but read via the API) can drive the job to exfiltrate it.`,
      remediation: `Do not pass untrusted event text (issue/PR/comment body) into a privileged step; restrict the workflow to trusted actors (author_association / github.actor) and remove ${sink.identity} from the untrusted-triggered job.`
    };
  }
  if (path.entry.entryKind === "agent-config-change") {
    return {
      reason: `${path.entry.label} \u2014 an untrusted change that adds or edits an agent instruction file is a prompt injection against any maintainer who reviews it with a coding agent (the same class as lockfile poisoning). Hidden content (HTML comments, zero-width/bidi text) makes it invisible on review.`,
      remediation: `Review ${sink.identity} as untrusted input before running any agent over the change; do not let a coding agent act on instruction files introduced by an external contributor.`
    };
  }
  if (path.entry.entryKind === "gate-tamper") {
    return {
      reason: `${path.entry.label} \u2014 this change removes Blastgate's own enforcement (${sink.identity}). Disabling the gate before making a change it would block is the obvious bypass, so a change that takes the gate out is itself flagged for review.`,
      remediation: `Restore the removed enforcement, or confirm the un-adoption is intentional and reviewed by a maintainer \u2014 do not let an automated change disable the gate.`
    };
  }
  if (path.entry.entryKind === "ci-divergent") {
    return {
      reason: `${path.entry.label} \u2014 an install/build script that changes behavior based on whether it runs in CI, a container, or an interactive terminal is the concealment technique used to keep a malicious lifecycle payload dormant exactly where it would be observed.`,
      remediation: `Remove the environment-conditional branch from the install/build script (or justify it in review); where lifecycle scripts are not required, install with \`npm ci --ignore-scripts\`.`
    };
  }
  if (path.entry.entryKind === "privileged-hook") {
    const location = path.entry.label.replace(/ \(committed hook\)$/, "");
    return {
      reason: `${path.entry.label} runs a shell command outside Claude Code's permission gate \u2014 a standing privileged capability (${sink.identity}). It fires deterministically, not via prompt injection, so it is not externally attacker-controllable; the risk is an over-scoped or untrusted hook command.`,
      remediation: `Review the hook command in ${location}, keep it minimal and repo-local, and remove the hook if it is not required.`
    };
  }
  if (dep && job && isSecret) {
    const untrusted = job.forkTriggerable ? ", which is triggered by untrusted input (fork PRs)" : "";
    if (dep.ecosystem === "python") {
      return {
        reason: `${dep.pkg} runs code at install time (\`pip install\` executes it), and it runs in job ${job.workflow}#${job.job}${untrusted}, which holds ${sink.sinkKind} ${sink.identity} \u2014 the shape of a malicious setup.py executed in CI / a Dependabot container.`,
        remediation: `Do not \`pip install\` untrusted code in that job (prefer \`--only-binary=:all:\` or a locked, hash-pinned install), or remove ${sink.identity} from ${job.workflow}#${job.job}.`
      };
    }
    return {
      reason: `New or changed dependency ${dep.pkg}@${dep.version} declares an install script that executes in job ${job.workflow}#${job.job}${untrusted} and holds ${sink.sinkKind} ${sink.identity}, which the script can exfiltrate.`,
      remediation: `Gate lifecycle scripts in that job (e.g. run \`npm ci --ignore-scripts\`) or remove ${sink.identity} from ${job.workflow}#${job.job}.`
    };
  }
  if (grant && isSecret) {
    return {
      reason: `Injectable agent surface ${grant.source} grants ${grant.capabilityClass} capability (${grant.scope}) that can read and exfiltrate ${sink.sinkKind} ${sink.identity}.`,
      remediation: `Scope the ${grant.capabilityClass} grant in ${grant.source} to the minimum required, or keep ${sink.identity} out of the agent's reach.`
    };
  }
  if (grant) {
    return {
      reason: `Injectable agent surface ${grant.source} grants ${grant.capabilityClass} capability (${grant.scope}) that exceeds the least-privilege baseline and reaches ${sink.identity}.`,
      remediation: `Scope the ${grant.capabilityClass} grant in ${grant.source} down to the minimum required path/host, or remove it.`
    };
  }
  if (job && isSecret) {
    if (isGuardedForkPr(path)) {
      return {
        reason: `Job ${job.workflow}#${job.job} triggers on untrusted events (${job.triggers.join(", ")}) and holds ${sink.sinkKind} ${sink.identity}, but its \`if:\` is actor-gated to trusted roles \u2014 so it is not externally triggerable, though the broad credential scope remains a least-privilege risk.`,
        remediation: `Scope ${sink.identity} down to least privilege for ${job.workflow}#${job.job}; the actor guard limits who can trigger the job but not its blast radius when it runs.`
      };
    }
    return {
      reason: `Job ${job.workflow}#${job.job} is triggered by untrusted input (${job.triggers.join(", ")}) and holds ${sink.sinkKind} ${sink.identity}, which is exfiltratable from an untrusted run.`,
      remediation: `Remove ${sink.identity} from the untrusted-triggerable job ${job.workflow}#${job.job}, or restrict its triggers to trusted events.`
    };
  }
  return {
    reason: `${path.entry.label} reaches ${sink.sinkKind} ${sink.identity} in ${path.hops} hop(s).`,
    remediation: `Break the path from ${path.entry.label} to ${sink.identity}.`
  };
}
function toFinding(ranked) {
  const { path, labels, score: score2 } = ranked;
  const { reason, remediation } = describe(path);
  const labelStrings = [
    labels.agentic ? agenticLabel(labels.agentic) : void 0,
    labels.mcp ? mcpLabel(labels.mcp) : void 0
  ].filter((s) => s !== void 0);
  return {
    id: `${path.entry.id}=>${path.sink.id}`,
    // An actor-gated fork-PR path is not externally attacker-controllable → warn, not
    // fail (U17); still reported because the broad credential scope is a real risk.
    tier: isGuardedForkPr(path) ? "warn" : tierForSink(path.sink.sinkKind),
    score: score2,
    path: path.nodes.map(nodeLabel),
    pathNodeIds: path.nodes.map((n) => n.id),
    hops: path.hops,
    entry: { kind: path.entry.entryKind, label: path.entry.label },
    sink: { kind: path.sink.sinkKind, identity: path.sink.identity },
    reason,
    remediation,
    owasp: labels,
    labels: labelStrings
  };
}
function compareFindings(a, b) {
  if (a.score !== b.score) {
    return b.score - a.score;
  }
  if (a.hops !== b.hops) {
    return a.hops - b.hops;
  }
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}
function assembleFindings(build) {
  return rankFindings(reachablePaths(build.graph)).map(toFinding).sort(compareFindings);
}

// src/graph/caps.ts
var MAX_REACHABILITY_PAIRS = 2e5;
function reachabilityCost(ag) {
  return ag.entryNodes().length * ag.sinkNodes().length;
}
function exceedsReachabilityCap(ag, cap = MAX_REACHABILITY_PAIRS) {
  return reachabilityCost(ag) > cap;
}

// src/engine/acknowledge.ts
function parseAcknowledgements(json) {
  if (!json) {
    return [];
  }
  try {
    const data = JSON.parse(json);
    const list = Array.isArray(data.acknowledged) ? data.acknowledged : [];
    const out = [];
    for (const item of list) {
      if (item && typeof item === "object" && typeof item.id === "string") {
        const record = item;
        out.push({ id: record.id, reason: typeof record.reason === "string" ? record.reason : "" });
      }
    }
    return out;
  } catch {
    return [];
  }
}
function applyAcknowledgements(findings, acks) {
  if (acks.length === 0) {
    return findings;
  }
  const reasonById = new Map(acks.map((a) => [a.id, a.reason]));
  return findings.map(
    (f) => f.tier === "fail" && reasonById.has(f.id) ? { ...f, tier: "warn", acknowledged: reasonById.get(f.id) ?? "" } : f
  );
}

// src/engine/gate.ts
function verdictOf(findings, diagnostics = []) {
  if (findings.some((f) => f.tier === "fail")) {
    return "fail";
  }
  if (diagnostics.some((d) => d.level === "error")) {
    return "unknown";
  }
  if (findings.some((f) => f.tier === "warn")) {
    return "warn";
  }
  return "pass";
}
function gateFails(verdict) {
  return verdict === "fail";
}
function gateBlocks(verdict) {
  return verdict === "fail" || verdict === "unknown";
}
function runEngine(inputs, opts = {}) {
  const build = buildGraph(inputs);
  const cap = opts.maxPairs ?? MAX_REACHABILITY_PAIRS;
  const diagnostics = [...build.diagnostics];
  if (inputs.acknowledgedIgnored && inputs.acknowledgedIgnored.length > 0) {
    diagnostics.push({
      level: "warn",
      message: `${inputs.acknowledgedIgnored.length} acknowledgement(s) introduced by this change were ignored \u2014 only acks already on the base ref are honored (0019): ` + inputs.acknowledgedIgnored.map((a) => a.id).join(", ")
    });
  }
  if (exceedsReachabilityCap(build.graph, cap)) {
    diagnostics.push({
      level: "error",
      message: `attack graph too large to evaluate safely (${reachabilityCost(build.graph)} entry\xD7sink pairs exceed the ${cap} cap); failing closed as UNKNOWN`
    });
    return { verdict: verdictOf([], diagnostics), findings: [], diagnostics };
  }
  const findings = applyAcknowledgements(assembleFindings(build), inputs.acknowledged ?? []);
  return { verdict: verdictOf(findings, diagnostics), findings, diagnostics };
}

export {
  emptyResult,
  AGENT_INSTRUCTION_PATHS,
  packageName,
  parsePackagesMap,
  GATE_CONFIG_PATHS,
  PYTHON_INSTALL_MANIFESTS,
  buildGraph,
  tierForSink,
  assembleFindings,
  parseAcknowledgements,
  verdictOf,
  gateFails,
  gateBlocks,
  runEngine
};
//# sourceMappingURL=chunk-76N57KBG.js.map