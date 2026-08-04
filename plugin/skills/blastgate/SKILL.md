---
name: blastgate
description: Run a Blastgate reachability scan (entry points to secret sinks) against the working tree or a diff, and report any blocking attack paths.
argument-hint: "[--since <ref>] [--fix]"
disable-model-invocation: true
allowed-tools: Bash(${CLAUDE_PLUGIN_ROOT}/bin/blastgate *), mcp__plugin_blastgate_checker__blastgate_check_change
---

Run the Blastgate reachability scanner and summarize findings.

1. Execute `${CLAUDE_PLUGIN_ROOT}/bin/blastgate check --since "${1:-HEAD}" $ARGUMENTS`.
2. If it exits non-zero, report the entry point, the reachable path, and the secret
   sink it reaches, plus the OWASP Agentic / MCP category label.
3. If `--fix` was passed, propose the smallest change that breaks the path (pin the
   dependency, drop the install-script capability, remove the secret from the
   untrusted job) instead of suppressing the finding.
