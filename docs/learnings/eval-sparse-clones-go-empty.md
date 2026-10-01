---
title: Eval-scan sparse clones can be silently empty and scan clean
date: 2026-10-01
tags: [evaluation, eval-scan, measurement]
anchor: LRN-empty-clones
---

# Eval-scan sparse clones can be silently empty and scan clean

## [1] What happened

During the 2026-10-01 agent re-scan, `scripts/eval-scan.sh` reported 6 repos as 0 fail /
0 warn that were not clean: network timeouts ("could not fetch … from promisor remote")
left blobless sparse clones with no checked-out `.github/`, and Blastgate correctly reported
nothing for an empty tree. The tell was free-programming-books dropping from 1 warn to 0 at
the **same SHA** as the previous scan. Five other repos failed loudly (exit 2, no SHA) on the
same run; these six failed silently.

## [2] The lesson

- An empty scan result is indistinguishable from a clean repo. Before trusting a re-scan,
  check every clone has its sparse paths:
  `for d in <workdir>/*/; do [ -d "$d/.github" ] || echo "broken $d"; done`
- Compare against the previous scan: a count change at an unchanged SHA is a measurement
  fault, not a finding.
- Ticket 0066 makes the script fail such a repo instead of scanning it.
