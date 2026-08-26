# Contributing

## The one thing to read first

Most contributions to a project like this are requests to allow a host. Adding a
host to an allowlist widens what every install in that ecosystem can reach,
including code from a package nobody read. Allowlist changes are the highest-risk
patch this repository accepts, and they are reviewed as such.

If you only need a host for your own project, you do not need a pull request:

```yaml
# .blastgate.yaml in your project
version: 1
allow:
  - host: artifacts.internal.example.com
    reason: "internal mirror for @acme packages"
```

Open a PR only for hosts every user of that ecosystem needs.

## Adding a host to a shipped allowlist

Every entry carries a `reason`, and the reason is the point. It should say what
breaks without the host, in words a reviewer can disagree with. "Needed for
installs" is not a reason. "Yarn resolves its own binary from here during
`corepack` bootstrap" is.

A PR adding a host should say:

- **What fails without it.** Ideally the error, verbatim.
- **Why it belongs to every user of the ecosystem**, not just your setup.
- **Which tier**, and why. An exact host is a smaller grant than a wildcard.
  Prefer exact. A wildcard should look like a bigger request, because it is.
- **Whether it accepts writes.** A host that accepts uploads is an exfiltration
  channel that happens to be useful. It may still be right to add — the registry
  itself is one — but it must be stated, not discovered later.

Conditional entries exist for hosts that are commonly needed and double as
exfiltration channels. If a host is only sometimes required, it probably belongs
there rather than in `exact`.

## Adding an attack scenario

The most valuable contribution, and the one this project is weakest on. Ten of
sixteen scenarios still say `source: constructed`, meaning they were written
from the threat model rather than from something that happened.

A scenario derived from a real, documented incident is worth more than several
invented ones. `tests/attacks/SCHEMA.md` has the format. Two rules:

- **Cite the write-up in `source`.** A scenario that merely resembles an
  incident does not get to borrow its citation. If you cannot verify it, mark it
  `constructed` — that is honest, and a fabricated citation is much worse than
  an admission.
- **A scenario may assert that an attack succeeds.** `expect: not_prevented` is
  for gaps this design does not close. Those count as failures in the published
  score, which is why it is 14 of 16. Do not delete a scenario to improve the
  number.

## Changing a control

Every claim in threat model section 6 names the test that demonstrates it. If
you change a control, change that row, and if a control stops being true, move
it to section 8 rather than deleting it. A gap that is disclosed is a known
limitation; a gap that quietly disappears from the document is a lie.

Two tests exist to catch this drift: one fails if the README's published score
stops matching what the corpus actually computes, and one fails loudly if a
scenario marked `not_prevented` stops reproducing — because that means the
threat model is stale, not that things silently improved.

## Running the tests

```bash
pip install -e ".[test]"
pytest -q
```

Tests that need a container runtime skip themselves without one, which means a
green run on a machine with no Docker has not exercised the sandbox at all. CI
fails if the topology tests skip, for that reason. If you are changing anything
about isolation, run them somewhere with a runtime.

`scripts/compat_check.py` measures the false-positive rate by installing real
projects twice, with and without blastgate. It is slow and needs the network.

## Commit messages

Say what changed and why it was wrong before. The git log here is meant to be
readable as a record of reasoning, including the mistakes — several commits
document bugs the author shipped and then found.

## Scope

Blastgate constrains an install. It does not detect malicious packages, and it
does not protect the application after installation. Proposals that move it
toward detection are probably a different project.
