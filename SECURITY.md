# Security Policy

Blastgate is a security tool, so we hold its own surface to the standard it
enforces on others. Thank you for helping keep it trustworthy.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use a private channel:

1. **Preferred — GitHub private vulnerability reporting.** Go to the repo's
   **Security → Report a vulnerability** tab (GitHub Security Advisories). This
   opens a private thread with the maintainers.
2. **Fallback — email** `jmwolberg@gmail.com` with the details below. Use the
   subject line `blastgate security`.

Please include:

- What the issue is and the impact you believe it has.
- A minimal reproduction (a repo, workflow, or config snippet) if you have one.
- Affected version / commit SHA.

We aim to acknowledge a report within **3 business days** and to share a
remediation plan or a request for more information within **10 business days**.
Once a fix ships we'll credit you in the advisory unless you'd rather stay
anonymous.

## What counts as a vulnerability here

Because Blastgate is a **detector**, security bugs come in two flavors — both are
in scope:

- **False negative (a missed path).** A reachable attacker-controllable →
  sensitive-sink path that Blastgate should have failed on but did not
  (e.g. an untrusted trigger, a fork-reachable secret, or an over-privileged
  agent grant it fails to flag). A missed real path is a security bug, not just a
  feature gap.
- **Tool-integrity issue.** Anything that lets an untrusted input subvert
  Blastgate as it runs — crafted repo/config content that causes it to crash,
  hang, mis-label, or execute unintended code during a scan; a way to silently
  suppress findings; or a weakness in how the Action/plugin handles credentials.

False **positives** (over-flagging) are correctness bugs — please file those as
normal public issues, not security reports.

## Out of scope

- Findings that require the reporter to already have push/admin access to the
  target repository.
- Weaknesses in third-party tools Blastgate integrates with, unless Blastgate's
  handling of them is the flaw. Report those upstream.
- Anything requiring social engineering of a maintainer.

## Supported versions

Blastgate is pre-1.0 (`0.x`). Security fixes are applied to `main` and the latest
released `0.x`. Please test against `main` before reporting.

## Safe harbor

We consider good-faith security research that follows this policy to be
authorized. We will not pursue action against you for accidental,
good-faith violations discovered and reported through the channels above. Do not
access, modify, or exfiltrate data that isn't yours, and don't run tests against
repositories or infrastructure you don't own.
