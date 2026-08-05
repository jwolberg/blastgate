import {
  AGENT_INSTRUCTION_PATHS,
  GATE_CONFIG_PATHS,
  PYTHON_INSTALL_MANIFESTS,
  gateBlocks,
  parseAcknowledgements
} from "./chunk-76N57KBG.js";

// src/cli/collect.ts
var LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublishOnly",
  "build"
];
function referencedLocalFiles(cmd) {
  const files = /* @__PURE__ */ new Set();
  const re = /(?:^|[\s'"=(])(\.{0,2}\/?[\w.\-/]+\.(?:js|cjs|mjs|ts|sh|py))\b/g;
  let m;
  while ((m = re.exec(cmd)) !== null) {
    files.add(m[1].replace(/^\.\//, ""));
  }
  return [...files];
}
function collectExec(fs) {
  const raw = fs.read("package.json");
  if (raw === null) {
    return void 0;
  }
  let scripts = {};
  try {
    scripts = JSON.parse(raw).scripts ?? {};
  } catch {
    return void 0;
  }
  const out = [];
  for (const name of LIFECYCLE_SCRIPTS) {
    const cmd = scripts[name];
    if (typeof cmd !== "string") {
      continue;
    }
    out.push({ name, source: cmd });
    for (const rel of referencedLocalFiles(cmd)) {
      const content = fs.read(rel);
      if (content !== null) {
        out.push({ name: `${name} \u2192 ${rel}`, source: content });
      }
    }
  }
  return out.length > 0 ? { scripts: out } : void 0;
}
function collectInputs(fs, opts = {}) {
  const inputs = {};
  const headLock = fs.read("package-lock.json");
  if (headLock !== null) {
    const deps = { headLockfile: headLock };
    const npmrc = fs.read(".npmrc");
    if (npmrc !== null) {
      deps.npmrc = npmrc;
    }
    if (opts.base && fs.gitShow) {
      deps.baseLockfile = fs.gitShow(opts.base, "package-lock.json");
      deps.baseNpmrc = fs.gitShow(opts.base, ".npmrc");
    }
    inputs.deps = deps;
  }
  if (opts.base && fs.gitShow) {
    const manifests = PYTHON_INSTALL_MANIFESTS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow(opts.base, path)
    }));
    if (manifests.some((m) => m.head !== null)) {
      inputs.pydeps = { manifests };
    }
  }
  const workflows = fs.listWorkflows().map((path) => ({ path, content: fs.read(path) ?? "" })).filter((w) => w.content !== "");
  if (workflows.length > 0) {
    inputs.ci = { workflows };
  }
  const mcpJson = fs.read(".mcp.json");
  const claudeSettings = fs.read(".claude/settings.json");
  const cursorMcpJson = fs.read(".cursor/mcp.json");
  if (mcpJson !== null || claudeSettings !== null || cursorMcpJson !== null) {
    inputs.agent = {
      mcpJson: mcpJson ?? void 0,
      claudeSettings: claudeSettings ?? void 0,
      cursorMcpJson: cursorMcpJson ?? void 0
    };
  }
  const exec = collectExec(fs);
  if (exec) {
    inputs.exec = exec;
  }
  if (opts.base && fs.gitShow) {
    const files = AGENT_INSTRUCTION_PATHS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow(opts.base, path)
    }));
    const agentDiff = { files };
    if (files.some((f) => f.head !== null)) {
      inputs.agentDiff = agentDiff;
    }
  }
  if (opts.base && fs.gitShow) {
    const files = GATE_CONFIG_PATHS.map((path) => ({
      path,
      head: fs.read(path),
      base: fs.gitShow(opts.base, path)
    }));
    if (files.some((f) => f.base !== null)) {
      inputs.selfIntegrity = { files };
    }
  }
  const headAcks = parseAcknowledgements(fs.read(".blastgate/acknowledged.json"));
  if (opts.base && fs.gitShow) {
    const baseAcks = parseAcknowledgements(fs.gitShow(opts.base, ".blastgate/acknowledged.json"));
    const baseIds = new Set(baseAcks.map((a) => a.id));
    const ignored = headAcks.filter((a) => !baseIds.has(a.id));
    if (baseAcks.length > 0) {
      inputs.acknowledged = baseAcks;
    }
    if (ignored.length > 0) {
      inputs.acknowledgedIgnored = ignored;
    }
  } else if (headAcks.length > 0) {
    inputs.acknowledged = headAcks;
  }
  return inputs;
}

// src/cli/node-fs.ts
import { execFileSync } from "child_process";
import { readdirSync, readFileSync, realpathSync } from "fs";
import { join, resolve, sep } from "path";
function safeRealpath(p) {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}
function isInside(root, p) {
  return p === root || p.startsWith(root + sep);
}
function isGitWorkTree(root) {
  try {
    execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: root,
      stdio: ["ignore", "pipe", "ignore"]
    });
    return true;
  } catch {
    return false;
  }
}
function nodeRepoFs(root) {
  const gitAware = isGitWorkTree(root);
  const realRoot = safeRealpath(root) ?? resolve(root);
  const ignoreCache = /* @__PURE__ */ new Map();
  const isIgnored = (rel) => {
    if (!gitAware) {
      return false;
    }
    let hit = ignoreCache.get(rel);
    if (hit === void 0) {
      try {
        execFileSync("git", ["check-ignore", "-q", "--", rel], { cwd: root, stdio: "ignore" });
        hit = true;
      } catch {
        hit = false;
      }
      ignoreCache.set(rel, hit);
    }
    return hit;
  };
  return {
    read(rel) {
      if (isIgnored(rel)) {
        return null;
      }
      const real = safeRealpath(join(root, rel));
      if (real === null || !isInside(realRoot, real)) {
        return null;
      }
      try {
        return readFileSync(real, "utf8");
      } catch {
        return null;
      }
    },
    listWorkflows() {
      const dir = join(root, ".github", "workflows");
      try {
        return readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).map((f) => `.github/workflows/${f}`).filter((rel) => !isIgnored(rel));
      } catch {
        return [];
      }
    },
    gitShow(ref, rel) {
      try {
        return execFileSync("git", ["show", "--end-of-options", `${ref}:${rel}`], {
          cwd: root,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"]
        });
      } catch {
        return null;
      }
    }
  };
}

// src/cli/render.ts
var WORKFLOW_GUIDANCE = {
  /** The three moments the same engine runs, earliest to latest. */
  stages: "local commit/install hook \u2192 CI pull-request gate \u2192 pre-merge review",
  /** The gate policy in one line, so a reader knows what a verdict means. */
  policy: "Blastgate fails only on a reachable path to a secret or credential sink; lower-severity capability paths are reported as warnings without failing.",
  /** Where to read the full adoption + response walkthrough. */
  runbook: "docs/runbooks/adopt-blastgate.md"
};
function renderText(result) {
  const lines = [];
  if (result.verdict === "unknown") {
    lines.push(
      "blastgate: could not fully evaluate the change \u2014 UNKNOWN (blocking in CI, not a pass)"
    );
    for (const e of result.diagnostics.filter((d) => d.level === "error")) {
      lines.push(`      error: ${e.message}`);
    }
    if (result.findings.length === 0) {
      lines.push("");
      lines.push(workflowFooterText());
      lines.push("");
      return lines.join("\n");
    }
    lines.push("");
  } else if (result.findings.length === 0) {
    return `blastgate: no reachable attacker\u2192sink path. PASS

${workflowFooterText()}
`;
  } else {
    const header = result.verdict === "fail" ? "FAIL" : "WARN";
    lines.push(`blastgate: ${result.findings.length} reachable path(s) \u2014 ${header}`);
  }
  for (const f of result.findings) {
    const tag = f.tier === "fail" ? "\u2717 FAIL" : "! WARN";
    const labels = f.labels.length > 0 ? `  [${f.labels.join(", ")}]` : "";
    lines.push("");
    lines.push(`${tag}  ${f.path.join(" \u2192 ")}`);
    lines.push(`      sink: ${f.sink.kind} ${f.sink.identity}${labels}`);
    if (f.acknowledged) {
      lines.push(`      accepted: ${f.acknowledged}`);
    }
    lines.push(`      why:  ${f.reason}`);
    lines.push(`      fix:  ${f.remediation}`);
  }
  lines.push("");
  lines.push(workflowFooterText());
  lines.push("");
  return lines.join("\n");
}
function workflowFooterText() {
  return `Runs at: ${WORKFLOW_GUIDANCE.stages}  \xB7  docs: ${WORKFLOW_GUIDANCE.runbook}`;
}
function renderJson(result) {
  return `${JSON.stringify(result.findings, null, 2)}
`;
}
function renderMarkdown(result) {
  const lines = [];
  lines.push(...markdownHeader(result));
  lines.push("");
  lines.push(`**Where this runs:** ${WORKFLOW_GUIDANCE.stages}  `);
  lines.push(`_${WORKFLOW_GUIDANCE.policy}_`);
  for (const f of result.findings) {
    lines.push("", "---", "", ...markdownFinding(f));
  }
  lines.push("", "---", "", markdownNextSteps(result), "");
  return lines.join("\n");
}
function markdownHeader(result) {
  const n = result.findings.length;
  if (result.verdict === "pass") {
    return [
      "## \u{1F6E1} Blastgate \u2014 \u2705 PASS",
      "",
      "No reachable path connects an attacker-controllable entry point to a secret, credential, or privileged capability."
    ];
  }
  if (result.verdict === "unknown") {
    const out = [
      "## \u{1F6E1} Blastgate \u2014 \u26A0\uFE0F UNKNOWN",
      "",
      "Blastgate could not fully evaluate the change, so the run **blocks in CI** rather than passing (fail-closed)."
    ];
    const errors = result.diagnostics.filter((d) => d.level === "error");
    if (errors.length > 0) {
      out.push("");
      for (const e of errors) {
        out.push(`- error: ${inlineText(e.message)}`);
      }
    }
    return out;
  }
  const badge = result.verdict === "fail" ? "\u274C FAIL" : "\u26A0\uFE0F WARN";
  const meaning = result.verdict === "fail" ? "A reachable path connects an attacker-controllable entry point to a secret or credential. This **blocks the gate** until the path is broken or the finding is acknowledged." : "A reachable path reaches a privileged capability. This is **reported, not blocking**.";
  return [`## \u{1F6E1} Blastgate \u2014 ${badge} (${n} reachable path${n === 1 ? "" : "s"})`, "", meaning];
}
function markdownFinding(f) {
  const mark = f.tier === "fail" ? "\u274C" : "\u26A0\uFE0F";
  const chain = f.path.map((n) => `\`${n.replace(/`/g, "")}\``).join(" \u2192 ");
  const out = [
    `### ${mark} ${inlineText(f.path[0] ?? f.entry.label)} \u2192 \u2026 \u2192 ${sinkIcon(f)} ${inlineText(f.sink.identity)}`,
    "",
    chain,
    ""
  ];
  if (f.acknowledged) {
    out.push(`- **accepted:** ${inlineText(f.acknowledged)} _(downgraded fail \u2192 warn)_`);
  }
  out.push(`- **why:** ${inlineText(f.reason)}`);
  out.push(`- **fix:** ${inlineText(f.remediation)}`);
  out.push(`- **sink:** ${f.sink.kind} \`${f.sink.identity}\``);
  if (f.labels.length > 0) {
    out.push(`- **OWASP:** ${f.labels.map((l) => `\`${l}\``).join(", ")}`);
  }
  return out;
}
function markdownNextSteps(result) {
  if (result.verdict === "fail" || result.verdict === "warn") {
    return `**Next:** break any edge on the path (preferred \u2014 the fixes above), or record a reviewed exception in \`.blastgate/acknowledged.json\` by finding id (\`blastgate --json\` prints the \`id\`). See [${WORKFLOW_GUIDANCE.runbook}](${WORKFLOW_GUIDANCE.runbook}).`;
  }
  return `**Where to add it:** run Blastgate on every \`pull_request\` (the Action) and as a local commit/install hook (the plugin), so a reachable path is caught before it lands. See [${WORKFLOW_GUIDANCE.runbook}](${WORKFLOW_GUIDANCE.runbook}).`;
}
function sinkIcon(f) {
  return f.sink.kind === "privileged-capability" ? "\u{1F6E0}" : "\u{1F511}";
}
function inlineText(s) {
  return s.replace(/\r?\n/g, " ").replace(/\|/g, "\\|").trim();
}
function scanExitCode(result) {
  return gateBlocks(result.verdict) ? 1 : 0;
}

export {
  collectInputs,
  nodeRepoFs,
  renderText,
  renderJson,
  renderMarkdown,
  scanExitCode
};
//# sourceMappingURL=chunk-DLJ44CQU.js.map