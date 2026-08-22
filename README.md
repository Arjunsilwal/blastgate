# bulkhead

> **Status: pre-alpha, Phase 1 of 4. Do not rely on this for protection yet.**
> The policy engine works. Isolation and egress enforcement are not built.
> `bh run` refuses to execute rather than running without an enforcement point.
> See [docs/threat-model.md](docs/threat-model.md) for what this will and will
> not defend against.

Run package installs with no credentials available and no network egress except
an explicit allowlist.

## The problem

Registry supply chain worms follow one structure: a maintainer's token is
stolen, trojanized versions are published across every package that account
controls, install-time code execution harvests credentials from the machine, and
the stolen tokens publish the next wave. Existing tooling is good at identifying
which versions were malicious, after the fact. That is incident response, not
prevention.

## The thesis

There is no bounded list of ways to obtain code execution during an install, so
that link cannot be reliably cut. The two links after it are structurally narrow:

- Credential theft requires **reading files an install has no business reading**.
- Exfiltration requires **reaching a destination an install has no business
  reaching**.

Two controls, no detection. **Isolation:** the install sees the project
directory and nothing else. **Egress control:** the install reaches a short
allowlist; everything else is denied and logged.

It should not matter how the code got execution, because there is nothing to
steal and nowhere to send it.

Bulkhead does not tell you whether a package is malicious. It assumes the answer
is yes and constrains what that can accomplish.

## What works today

| Phase | Component | Status |
|---|---|---|
| 0 | Threat model | [Written](docs/threat-model.md) |
| 1 | Policy engine — allowlist load, host matching, allow/deny | Working |
| 2 | Isolation — container topology, credential stripping | Not built |
| 3 | Enforcement — egress proxy, hash-chained audit log | Not built |
| 4 | Executable attack corpus | Not built |

Phases 2 and 3 are the controls the thesis actually depends on. Until they
exist, bulkhead protects no install. What you can do today is inspect the policy.

## Try the policy engine

Requires Python 3.10+. No Docker, no containers, nothing to configure.

```bash
pip install -e .
```

```bash
bh check npm registry.npmjs.org
```

```
ALLOW registry.npmjs.org (matched: exact:registry.npmjs.org) - Primary package registry metadata and tarball host
```

Default is deny, and every allow path is explicit:

```
$ bh check npm evil.example.com
DENY evil.example.com - default deny: host not in allowlist

$ bh check npm cdn.npmjs.org
ALLOW cdn.npmjs.org (matched: wildcard:*.npmjs.org) - Registry CDN edge nodes and asset endpoints

$ bh check npm registry.npmjs.org.evil.com
DENY registry.npmjs.org.evil.com - default deny: host not in allowlist

$ bh check npm 127.0.0.1
DENY 127.0.0.1 - invalid hostname: Raw IP addresses are not allowed: 127.0.0.1
```

Hosts that are commonly needed but double as exfiltration channels are denied
unless you opt in by name:

```
$ bh check npm github.com
DENY github.com - conditional host requires condition 'git-dependencies': Direct git repository dependencies and GitHub release assets

$ bh check npm github.com --allow git-dependencies
ALLOW github.com (matched: conditional:github.com) - Direct git repository dependencies and GitHub release assets
```

Exit code is 0 for allow, 1 for deny, 2 for an error. Allowlists ship in-repo
under [`allowlists/`](allowlists/) — a remote fetch would itself be a supply
chain dependency — and every entry carries a reason or it is rejected at load.

## What it does not defend against

The full list is [section 8 of the threat model](docs/threat-model.md), which is
deliberately longer than the list of things it does defend against. The ones
most likely to matter to you:

- **Container escape.** Isolation will depend on the container runtime. A
  payload with a working escape reaches the host.
- **Exfiltration to an allowlisted host.** No TLS interception, so a payload
  writing to an attacker's repository on an allowlisted forge is not blocked.
  This gap is real and was used in the 2026 campaigns.
- **DNS-based exfiltration.** Not detected.
- **Post-install runtime.** Protects the install, not the application later.
- **Compromised base image or package manager.** Enforces nothing useful.
- **Ports are not policy.** `registry.npmjs.org:8443` normalises to the host and
  is allowed; policy makes no port distinction.

## The rule

Every protection claim maps to a test that fails when the control is removed. A
control with no test is a claim, not a protection, and stays in the gaps list
until it has one. If a change alters what bulkhead protects against, the threat
model changes in the same commit.

That is also why the threat model is the first commit in this repository and the
code is the third.

## Tests

```bash
pip install -e ".[test]" && pytest
```

The evasion cases in `tests/test_policy.py` are the highest-value tests here and
back every claim in section 6 of the threat model.

## License

Apache 2.0. See [LICENSE](LICENSE).
