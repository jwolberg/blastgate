---
title: A shell-parsing allowlist cannot be made sound in a review loop
date: 2026-10-01
tags: [ci, precision, gh-aw, review]
anchor: LRN-shell-parsing
---

# A shell-parsing allowlist cannot be made sound in a review loop

## [1] What happened

Ticket 0062 tried to exempt GitHub Agentic Workflows (gh-aw) runtime steps from the 0048
"any `run:` after an untrusted checkout runs PR code" rule by classifying each `run:`
script. Four review rounds on PR #39:

1. A path-mention regex — exempted user steps that merely *mentioned* a gh-aw path.
2. A denylist of workspace commands — `node x.js`, `docker build .`, `eval` slipped through.
3. An allowlist over a hand-rolled tokenizer — fooled by quoted command words, `$((…))` /
   `<<<` / comments misread as heredocs, backticks, `<(…)`, `command`/`trap`, `awk system()`.
4. A fail-closed tokenizer — still fooled by a lone `&`, `#` inside quotes, one-line `case`,
   `<<` in double quotes; and gh-aw's real agent launch embeds a ~1KB `bash -c` script that a
   sound rule would have to parse too.

Each round closed every reported hole and the next found new ones. The exemption was dropped;
the 2 false fails it was meant to clear stand as a documented exception.

## [2] The lesson

- Bash is not a language you can soundly classify with regexes and a line tokenizer. Every
  fix moves the boundary; reviewers (correctly) find the next gap.
- When a precision exemption needs to *prove a negative* about shell ("this step runs no PR
  code"), prefer a **structural signal** (who emitted the step — e.g. gh-aw's compiler step
  names) or **accept a documented exception**. Decide after round 2, not round 4.
- Separately: the bypasses were shapes a *trusted workflow author* would have to write, not
  something a PR attacker controls — worth weighing before treating each as a blocker.
