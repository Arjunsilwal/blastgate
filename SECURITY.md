# Security policy

## Reporting a vulnerability

Please report privately, through GitHub's
[private vulnerability reporting](https://github.com/Arjunsilwal/blastgate/security/advisories/new),
rather than in a public issue.

Include what you did, what happened, and what you expected. A failing test or a
scenario file is ideal — the attack corpus in `tests/attacks/` exists exactly
for this, and a reproduction in that form goes straight into the suite.

This is a single-maintainer, pre-alpha project. There is no response-time
commitment. If you need one, do not depend on this yet.

## What counts as a vulnerability

A finding is a vulnerability if it defeats a control that
[docs/threat-model.md](docs/threat-model.md) **section 6** claims. Those are the
claims; everything there names the test that demonstrates it.

A finding is **not** a vulnerability if section 8 already discloses it. That
section is longer than section 6 on purpose, and it includes things that would
otherwise look alarming:

- A payload can exfiltrate through the registry itself, which has to stay
  reachable during an install.
- The audit log detects truncation but not an attacker who rewrites both the
  log and its anchor.
- Container escape defeats everything here; the isolation is the runtime's.
- Credential brokering stops the token being *stolen*, not authenticated reads
  being *made* from inside the sandbox during the install.

If you find one of these, it is not a bug — but if the *disclosure* is wrong,
incomplete, or reads as less serious than it is, that is worth reporting and
will be fixed. A threat model that undersells a gap is a defect.

Two scenarios in the corpus are marked `expect: not_prevented` and are expected
to succeed for the attacker. They are counted as failures in the published
score deliberately.

## Scope

In scope: the policy engine, the proxy, the sandbox topology, the resolve phase,
the audit log and its anchoring, and the credential broker.

Out of scope: the container runtime itself, the registries, and anything a
package does after installation. Blastgate constrains an install. It does not
protect the application that install produces.
