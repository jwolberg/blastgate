#!/usr/bin/env node
import {
  VERSION
} from "../chunk-MWBKKYRA.js";
import {
  collectInputs,
  nodeRepoFs,
  renderJson,
  renderMarkdown,
  renderText,
  scanExitCode
} from "../chunk-DLJ44CQU.js";
import {
  emptyResult,
  gateFails,
  packageName,
  parsePackagesMap,
  runEngine
} from "../chunk-76N57KBG.js";

// src/cli/index.ts
import { existsSync } from "fs";
import { pathToFileURL } from "url";

// src/analyzers/deps/provenance.ts
async function analyzeProvenance(baseLockfile, headLockfile, fetcher) {
  const result = emptyResult();
  if (!baseLockfile) {
    return result;
  }
  let base;
  let head;
  try {
    base = parsePackagesMap(baseLockfile);
    head = parsePackagesMap(headLockfile);
  } catch (err) {
    result.diagnostics.push({
      level: "error",
      message: `provenance: failed to parse a lockfile: ${err.message}`
    });
    return result;
  }
  for (const [path, headEntry] of Object.entries(head)) {
    if (path === "") {
      continue;
    }
    const baseEntry = base[path];
    const baseVersion = baseEntry?.version;
    const headVersion = headEntry.version;
    if (!baseVersion || !headVersion || baseVersion === headVersion) {
      continue;
    }
    const pkg = packageName(path);
    const baseProv = await fetcher.hasProvenance(pkg, baseVersion);
    const headProv = await fetcher.hasProvenance(pkg, headVersion);
    if (baseProv !== true || headProv !== false) {
      continue;
    }
    const entryId = `entry:provenance:${pkg}`;
    const depId = `dep:${pkg}@${headVersion}`;
    const entry = {
      id: entryId,
      kind: "entry",
      entryKind: "new-dependency",
      exposure: 2,
      label: `provenance regression: ${pkg} lost npm attestations (${baseVersion} \u2192 ${headVersion})`
    };
    result.nodes.push(entry);
    result.edges.push({ from: entryId, to: depId, edge: { kind: "controls" } });
    result.diagnostics.push({
      level: "warn",
      message: `provenance regression: ${pkg} had npm attestations at ${baseVersion} but not at ${headVersion} \u2014 a strong supply-chain compromise signal (cf. CVE-2025-54313).`
    });
  }
  return result;
}

// src/mcp/tools.ts
var CHANGE_KINDS = ["dependency", "install-script", "workflow", "mcp-config", "other"];
var CHECK_CHANGE_TOOL = {
  name: "blastgate_check_change",
  description: "Check whether the current repository state \u2014 including a change you just made \u2014 opens a reachable cross-layer attack path from an attacker-controllable entry point (a new/changed dependency, an untrusted CI trigger, or a prompt-injectable agent surface) to a sensitive sink (a secret, credential, or privileged capability). Advisory only: it returns a verdict and the ranked path, sink, reason, fix, and OWASP labels; it never blocks. Call it before committing a dependency/workflow/MCP-config change to see if it would fail the gate.",
  inputSchema: {
    type: "object",
    properties: {
      file_path: {
        type: "string",
        description: "The file you added or edited (a hint; the scan is repository-wide)."
      },
      change_kind: {
        type: "string",
        enum: [...CHANGE_KINDS],
        description: "The kind of change (a hint)."
      },
      base: {
        type: "string",
        description: "Git ref to diff against for change signals (defaults to HEAD)."
      }
    }
  }
};
var ADVISORY = "Advisory only \u2014 Blastgate does not block here; the pre-commit hook is the enforcement layer.";
function line(f) {
  const labels = f.labels.length > 0 ? ` [${f.labels.join(", ")}]` : "";
  return `- [${f.tier}] ${f.path.join(" \u2192 ")}
  sink: ${f.sink.kind} ${f.sink.identity}${labels}
  fix: ${f.remediation}`;
}
function summarize(result) {
  if (result.findings.length === 0) {
    return `OK \u2014 no reachable attacker\u2192sink path in the current repository state.

${ADVISORY}`;
  }
  const fails = result.findings.filter((f) => f.tier === "fail").length;
  const head = result.verdict === "fail" ? `REACHABLE PATH (fail) \u2014 ${fails} path(s) reach a secret/credential sink. This change would fail the gate.` : `WARNING (warn) \u2014 ${result.findings.length} lower-severity capability path(s); no secret/credential is reachable.`;
  return `${head}
${result.findings.map(line).join("\n")}

${ADVISORY}`;
}
function checkChange(fs, args, defaultBase = "HEAD") {
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    throw new Error("arguments must be an object");
  }
  const a = args;
  if (a.file_path !== void 0 && typeof a.file_path !== "string") {
    throw new Error("file_path must be a string");
  }
  if (a.change_kind !== void 0 && !CHANGE_KINDS.includes(a.change_kind)) {
    throw new Error(`change_kind must be one of: ${CHANGE_KINDS.join(", ")}`);
  }
  const base = typeof a.base === "string" ? a.base : defaultBase;
  const result = runEngine(collectInputs(fs, { base }));
  return {
    text: summarize(result),
    structured: { verdict: result.verdict, findings: result.findings }
  };
}

// src/mcp/server.ts
var PROTOCOL_VERSION = "2025-06-18";
function ok(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function fail(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}
function toolResult(text, isError, structured) {
  const result = { content: [{ type: "text", text }], isError };
  if (structured !== void 0) {
    result.structuredContent = structured;
  }
  return result;
}
function callTool(id, params, ctx) {
  const p = params ?? {};
  if (p.name !== CHECK_CHANGE_TOOL.name) {
    return ok(id, toolResult(`Unknown tool: ${String(p.name)}`, true));
  }
  try {
    const out = checkChange(ctx.fs, p.arguments ?? {}, ctx.base ?? "HEAD");
    return ok(id, toolResult(out.text, false, out.structured));
  } catch (err) {
    return ok(id, toolResult(`blastgate_check_change error: ${err.message}`, true));
  }
}
function handleRequest(request, ctx) {
  const req = request ?? {};
  const { id, method, params } = req;
  if (id === void 0 || id === null) {
    return null;
  }
  switch (method) {
    case "initialize": {
      const requested = params?.protocolVersion;
      return ok(id, {
        protocolVersion: requested ?? PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "blastgate", version: VERSION }
      });
    }
    case "tools/list":
      return ok(id, { tools: [CHECK_CHANGE_TOOL] });
    case "tools/call":
      return callTool(id, params, ctx);
    case "ping":
      return ok(id, {});
    default:
      return fail(id, -32601, `Method not found: ${String(method)}`);
  }
}
function runStdioServer(ctx) {
  return new Promise((resolve) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const raw = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!raw) {
          continue;
        }
        let request;
        try {
          request = JSON.parse(raw);
        } catch {
          continue;
        }
        const response = handleRequest(request, ctx);
        if (response) {
          process.stdout.write(`${JSON.stringify(response)}
`);
        }
      }
    });
    process.stdin.on("end", () => resolve());
  });
}

// src/registry/packument.ts
function readProvenance(packument, version) {
  if (!packument) {
    return null;
  }
  const entry = packument.versions?.[version];
  if (!entry) {
    return null;
  }
  return entry.dist?.attestations !== void 0;
}
function cachedFetcher(source) {
  const cache = /* @__PURE__ */ new Map();
  return {
    hasProvenance(pkg, version) {
      let pending = cache.get(pkg);
      if (!pending) {
        pending = source.fetch(pkg);
        cache.set(pkg, pending);
      }
      return pending.then((packument) => readProvenance(packument, version));
    }
  };
}
function httpSource() {
  return {
    async fetch(pkg) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${pkg.replace(/\//g, "%2F")}`, {
          redirect: "error"
        });
        if (!res.ok) {
          return null;
        }
        return await res.json();
      } catch {
        return null;
      }
    }
  };
}

// src/cli/gate.ts
var POST_PHASES = /* @__PURE__ */ new Set([
  "dependency-install",
  // 0025: a Bash command classified as an install verb.
  "shell-post"
]);
function bypassOutput(phase, command) {
  const reason = `Blastgate: this command disables commit/push verification (gate-bypass attempt) \u2014 "${command}". Run without \`--no-verify\` / \`core.hooksPath\` overrides.`;
  if (POST_PHASES.has(phase)) {
    return { stdout: "", stderr: `${reason}
`, exitCode: 0 };
  }
  const payload = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason
    }
  };
  return { stdout: `${JSON.stringify(payload)}
`, exitCode: 0 };
}
function reasonFrom(result) {
  const top = result.findings.find((f) => f.tier === "fail") ?? result.findings[0];
  if (!top) {
    return "";
  }
  const labels = top.labels.length > 0 ? ` [${top.labels.join(", ")}]` : "";
  return `Reachable path: ${top.path.join(" \u2192 ")}. ${top.reason} Fix: ${top.remediation}${labels}`;
}
function hookOutput(phase, result) {
  if (result.verdict === "unknown") {
    const n = result.diagnostics.filter((d) => d.level === "error").length;
    return {
      stdout: "",
      stderr: `blastgate: could not fully evaluate this change \u2014 UNKNOWN, not a pass (${n} evaluation error(s)). Allowing locally; re-run \`blastgate\` \u2014 CI blocks on UNKNOWN.
`,
      exitCode: 0
    };
  }
  if (!gateFails(result.verdict)) {
    return { stdout: "", exitCode: 0 };
  }
  if (POST_PHASES.has(phase)) {
    const payload2 = {
      decision: "block",
      reason: `Revert this install \u2014 it opens a reachable path. ${reasonFrom(result)}`
    };
    return { stdout: `${JSON.stringify(payload2)}
`, exitCode: 0 };
  }
  const payload = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reasonFrom(result)
    }
  };
  return { stdout: `${JSON.stringify(payload)}
`, exitCode: 0 };
}

// src/cli/shell-guard.ts
var GIT_COMMIT = /\bgit\b[^|;&\n]*\bcommit\b/;
var GIT_PUSH = /\bgit\b[^|;&\n]*\bpush\b/;
var NPM_INSTALL = /\bnpm\s+(?:install|i|ci|add)\b/;
var YARN_PNPM_INSTALL = /\b(?:yarn|pnpm)\s+(?:add|install)\b/;
var HOOKS_DISABLED = /core\.hooksPath\s*=/;
var NO_VERIFY = /--no-verify\b/;
var SHORT_NO_VERIFY = /(?:^|\s)-n(?=\s|$)/;
function classifyShellCommand(command) {
  const gitMutating = GIT_COMMIT.test(command) || GIT_PUSH.test(command);
  if (HOOKS_DISABLED.test(command)) {
    return "bypass";
  }
  if (gitMutating && (NO_VERIFY.test(command) || SHORT_NO_VERIFY.test(command))) {
    return "bypass";
  }
  if (gitMutating || NPM_INSTALL.test(command) || YARN_PNPM_INSTALL.test(command)) {
    return "gate";
  }
  return "ignore";
}

// src/cli/index.ts
var VALUE_FLAGS = /* @__PURE__ */ new Set(["--base", "--since", "--gate", "--format"]);
function baseRef(argv) {
  return flagValue(argv, "--base") ?? flagValue(argv, "--since");
}
function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : void 0;
}
function outputFormat(argv) {
  const fmt = flagValue(argv, "--format");
  if (argv.includes("--json") || fmt === "json") {
    return "json";
  }
  if (argv.includes("--md") || fmt === "md" || fmt === "markdown") {
    return "markdown";
  }
  return "text";
}
function renderResult(result, argv) {
  switch (outputFormat(argv)) {
    case "json":
      return renderJson(result);
    case "markdown":
      return renderMarkdown(result);
    default:
      return renderText(result);
  }
}
function usage() {
  return [
    `blastgate ${VERSION} \u2014 cross-layer attack-path gate`,
    "",
    "Usage:",
    "  blastgate [path] [--base <ref>] [--json]   scan a repo for reachable attacker\u2192sink paths",
    "  blastgate check --gate <phase>             plugin hook gate (reads hook JSON on stdin)",
    "  blastgate mcp                              stdio MCP self-check server",
    "",
    "Flags:",
    "  --base <ref>       diff against a git ref for change signals (new deps, .npmrc changes)",
    "  --format <fmt>     output format: text (default), json, or md (human-readable report)",
    "  --json / --md      shorthands for --format json / --format md",
    "  --provenance       opt-in npm provenance-regression check (network; needs --base)",
    "  --version          print version",
    ""
  ].join("\n");
}
async function provenanceResult(argv, env, base) {
  if (!argv.includes("--provenance")) {
    return void 0;
  }
  if (!base) {
    env.stderr("blastgate: --provenance needs --base <ref> for a version baseline; skipping.\n");
    return void 0;
  }
  const headLock = env.fs.read("package-lock.json");
  if (headLock === null) {
    return void 0;
  }
  const baseLock = env.fs.gitShow ? env.fs.gitShow(base, "package-lock.json") : null;
  return analyzeProvenance(baseLock, headLock, cachedFetcher(httpSource()));
}
async function scanMode(argv, env) {
  const base = baseRef(argv);
  const inputs = collectInputs(env.fs, base !== void 0 ? { base } : {});
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);
  env.stdout(renderResult(result, argv));
  return scanExitCode(result);
}
async function checkMode(argv, env) {
  const phase = flagValue(argv, "--gate");
  const raw = await env.stdin();
  let hook;
  if (raw) {
    try {
      hook = JSON.parse(raw);
    } catch {
    }
  }
  if (phase === "shell-pre" || phase === "shell-post") {
    const command = hook?.tool_input?.command;
    const cls = command ? classifyShellCommand(command) : "ignore";
    if (cls === "ignore") {
      return 0;
    }
    if (cls === "bypass") {
      const out = bypassOutput(phase, command ?? "");
      if (out.stdout) {
        env.stdout(out.stdout);
      }
      if (out.stderr) {
        env.stderr(out.stderr);
      }
      return out.exitCode;
    }
  }
  const base = baseRef(argv) ?? "HEAD";
  const inputs = collectInputs(env.fs, { base });
  inputs.provenance = await provenanceResult(argv, env, base);
  const result = runEngine(inputs);
  if (phase === void 0) {
    env.stdout(renderResult(result, argv));
    return scanExitCode(result);
  }
  const { stdout, stderr, exitCode } = hookOutput(phase, result);
  if (stdout) {
    env.stdout(stdout);
  }
  if (stderr) {
    env.stderr(stderr);
  }
  return exitCode;
}
async function runCli(argv, env) {
  if (argv.includes("--version") || argv.includes("-v")) {
    env.stdout(`blastgate ${VERSION}
`);
    return 0;
  }
  const cmd = argv[0];
  if (cmd === "--help" || cmd === "-h" || cmd === "help") {
    env.stdout(usage());
    return 0;
  }
  if (cmd === "check") {
    return checkMode(argv, env);
  }
  if (cmd === "mcp") {
    env.stderr("blastgate mcp: run via the bin (needs stdio streams).\n");
    return 0;
  }
  return scanMode(argv, env);
}
function firstPositional(argv) {
  const subcommands = /* @__PURE__ */ new Set(["check", "mcp", "help"]);
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok.startsWith("-")) {
      if (VALUE_FLAGS.has(tok)) {
        i++;
      }
      continue;
    }
    if (subcommands.has(tok)) {
      continue;
    }
    return tok;
  }
  return void 0;
}
function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => data += c);
    process.stdin.on("end", () => resolve(data));
    setTimeout(() => resolve(data), 250);
  });
}
async function main(argv) {
  const cmd = argv[0];
  if (cmd === "mcp") {
    const projectDir = process.env.BLASTGATE_PROJECT_DIR ?? process.env.CLAUDE_PROJECT_DIR ?? ".";
    await runStdioServer({ fs: nodeRepoFs(projectDir), base: "HEAD" });
    return 0;
  }
  const root = cmd === "check" ? "." : firstPositional(argv) ?? ".";
  if (!existsSync(root)) {
    process.stderr.write(`blastgate: path not found: ${root}
`);
    return 2;
  }
  return runCli(argv, {
    fs: nodeRepoFs(root),
    stdin: readStdin,
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s)
  });
}
var invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  void main(process.argv.slice(2)).then((code) => process.exit(code)).catch((err) => {
    process.stderr.write(`blastgate: ${err.message}
`);
    process.exit(1);
  });
}
export {
  runCli
};
//# sourceMappingURL=index.js.map