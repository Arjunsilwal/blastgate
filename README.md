# bulkhead

> **Status: pre-alpha. Every control in the design is built and demonstrated
> against running containers, and the known gaps have not shrunk.** A real
> `npm install` completes inside the sandbox with one allowed route out. It has
> not been run against a live worm, and it does not stop a payload that exfils
> through a host you allowlisted — read
> [docs/threat-model.md](docs/threat-model.md) section 8 before relying on it.

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
| 2 | Isolation — container topology, credential stripping | Working |
| 3 | Enforcement — egress proxy, hash-chained audit log | Working |
| 4 | Executable attack corpus | Scenarios written, no executor |

Phase 4 is the honest remainder. `tests/attacks/` holds the scenario format and
eight scenarios, one of which asserts a *disclosed gap is not prevented*. There
is no executor yet, so there is no published pass rate, and a pass rate nobody
has computed is not a claim worth making.

## What actually stops a payload

The proxy environment variables are configuration, and a payload has no reason
to honour configuration. They are not the control.

The control is that the install container is joined to a network with no
gateway. The only host it can open a socket to is the proxy, and the proxy is
the only container joined to both networks. A payload that ignores
`HTTPS_PROXY` entirely and dials `registry.npmjs.org:443` directly finds no
route to it. That difference — a setting versus a topology — is the one the
tests are built around:

```
tests/test_end_to_end.py::TestTheWholeThing::test_a_payload_that_ignores_the_proxy_is_still_blocked
```

The audit log is written to a directory mounted into the proxy container and
nowhere else, so the sandbox cannot read or delete it. Pointing `--audit` inside
the project directory is refused, because the project is mounted writable and a
log the payload can rewrite is not evidence.

## Run an install

Requires Docker or Podman.

```bash
bh run npm -- npm ci
```

The install command goes after `--`. Bulkhead's own options go before it:

```bash
bh run npm --project ./app --allow git-dependencies -- npm install
```

Then review what it tried to reach:

```bash
bh audit ~/.bulkhead/audit/<project>-<hash>.log
```

Every failure path refuses rather than falling back. A missing runtime, a
network that is not actually internal, or a sidecar that does not come up all
produce a refusal, never an unsandboxed install.

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
- **Ports are not policy.** `bh check npm registry.npmjs.org:8443` reports ALLOW
  because policy decides on hostname alone. The proxy restricts tunnelling to
  443, so the two disagree when inspected separately.
- **Your project must live where the runtime can see it.** On macOS the runtime
  runs in a VM sharing only part of the filesystem; a project outside a shared
  path cannot be mounted.

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
