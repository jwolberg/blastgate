import {
  collectInputs,
  nodeRepoFs,
  renderMarkdown,
  scanExitCode
} from "../chunk-DLJ44CQU.js";
import {
  runEngine
} from "../chunk-76N57KBG.js";

// src/action/index.ts
import { appendFileSync } from "fs";
import { pathToFileURL } from "url";
function runActionCore(fs, opts = {}) {
  return runEngine(collectInputs(fs, opts));
}
function annotationMessage(f) {
  const labels = f.labels.length > 0 ? ` [${f.labels.join(", ")}]` : "";
  return `${f.path.join(" \u2192 ")} \u2014 ${f.reason} Fix: ${f.remediation}${labels}`;
}
function runAction(env) {
  const result = runActionCore(env.fs, env.base !== void 0 ? { base: env.base } : {});
  for (const f of result.findings) {
    env.annotate(f.tier === "fail" ? "error" : "warning", annotationMessage(f));
  }
  env.summary(renderMarkdown(result));
  return scanExitCode(result);
}
function input(name) {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v && v.length > 0 ? v : void 0;
}
function emitAnnotation(level, message) {
  const escaped = message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  process.stdout.write(`::${level} title=Blastgate::${escaped}
`);
}
function writeSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) {
    try {
      appendFileSync(file, `${markdown}
`);
      return;
    } catch {
    }
  }
  process.stdout.write(`${markdown}
`);
}
function main() {
  const path = input("path") ?? ".";
  const base = input("base") ?? process.env.GITHUB_BASE_REF ?? void 0;
  const provenance = input("provenance") === "true";
  if (provenance) {
    emitAnnotation(
      "warning",
      "provenance check requested but not available yet (U8, network-gated); running offline."
    );
  }
  return runAction({
    fs: nodeRepoFs(path),
    base,
    provenance,
    annotate: emitAnnotation,
    summary: writeSummary
  });
}
var invokedDirectly = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.exit(main());
}
export {
  runAction,
  runActionCore
};
//# sourceMappingURL=index.js.map