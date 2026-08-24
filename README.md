# bulkhead

> **Status: pre-alpha. Every control in the design is built and demonstrated
> against running containers.** A real `npm install` completes inside the
> sandbox with one allowed route out, including projects with git dependencies,
> which are fetched before any package code runs. It has not been run against a
> live worm, and a payload can still use the registry itself as a channel — read
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
| 4 | Executable attack corpus | Working |

## Does it break real installs?

The corpus measures what bulkhead stops. This measures what it breaks, which is
the number that decides whether anyone keeps it switched on.

Every project is installed twice: once in a plain container with full network
access, and once under bulkhead. Without that control a failure means nothing —
the project might simply be broken, and counting that as a false positive would
hide real breakage in noise.

```bash
python scripts/compat_check.py
```

**15 of 15 projects install unchanged under bulkhead. No false positives found.**

| Project | Ecosystem | Why it is here | Verdict |
| --- | --- | --- | --- |
| `express` `axios` `got` `prettier` | npm | real repos, pinned to release tags | compatible |
| `esbuild` | npm | postinstall downloads a platform binary | compatible |
| `sharp` | npm | native module, prebuilt binaries | compatible |
| `is-odd#3.0.1` | npm | git dependency via the resolve phase | compatible |
| webpack + eslint | npm | wide, deep transitive graph | compatible |
| `requests` `click` | pypi | pure-python wheels | compatible |
| `cryptography` | pypi | compiled wheel | compatible |
| `pendulum` | pypi | build isolation fetches its own backend | compatible |
| `fastapi` `uvicorn` | pypi | wide transitive graph | compatible |
| `serde` | cargo | sparse index plus crate downloads | compatible |
| `tokio` `clap` | cargo | hundreds of transitive crates | compatible |
| `anyhow` (git) | cargo | git dependency, no resolve phase | compatible |
| `date-fns` | npm | — | **excluded** |

`date-fns` is excluded because its *control* install fails too: `oxlint@^1.65.0`
floats forward into a peer conflict with its own pinned sibling, so the tag does
not install today under any sandbox. That is upstream's conflict, not
bulkhead's. The report prints the `ERESOLVE` output so the exclusion can be
checked rather than taken on trust.

Both runs are retried the same number of times. An unretried control silently
excludes a project on a transient failure, which makes the rate look better by
measuring less — `got` did exactly that on one run and installed fine on the
next two. Deterministic failures skip the retries.

### Why this number is weaker than it looks

Read it as "no false positives found in fifteen projects", not as a rate.

- **The two hardest npm cases passed for reasons unrelated to this design.**
  esbuild and sharp were included because they historically downloaded binaries
  from GitHub releases at postinstall, which bulkhead denies. Both now ship
  platform binaries as npm optional dependencies served from the registry. The
  ecosystem moved somewhere convenient; that is luck, and it can move back.
- **The pypi and cargo cases are synthetic manifests**, not cloned projects.
  They exercise real packages and real transitive graphs, but not real
  repository layouts.
- **Untested entirely:** private registries, authenticated `.npmrc`, workspace
  monorepos, yarn, and pnpm.

## What the attack corpus scores

`tests/attacks/` holds executable scenarios. Each one is run against the real
sandbox and scored, and the number below is regenerated from that run rather
than written by hand:

```bash
python scripts/attack_report.py --write
```

<!-- corpus:begin -->
**11 of 13 scenarios prevented (85%).**

| Scenario | Link | Expected | Result |
| --- | --- | --- | --- |
| `audit-replacement-is-detected` | 6 | not_prevented | known-gap ⚠ |
| `audit-truncation-is-detected` | 6 | denied | prevented |
| `egress-forge-without-opt-in` | 5 | denied | prevented |
| `egress-lookalike-registry` | 5 | denied | prevented |
| `egress-nonstandard-port` | 5 | denied | prevented |
| `egress-raw-ip` | 5 | denied | prevented |
| `egress-unlisted-host` | 5 | denied | prevented |
| `exfil-over-tls-to-allowlisted-host` | 5 | denied | prevented |
| `exfil-via-registry-during-install` | 5 | not_prevented | known-gap ⚠ |
| `fetch-phase-runs-no-lifecycle-scripts` | 3 | denied | prevented |
| `git-dependency-still-installs` | 0 | allowed | allowed |
| `harvest-host-credential-files` | 4 | denied | prevented |
| `registry-traffic-still-works` | 0 | allowed | allowed |

Counted as failures because they are:
- `audit-replacement-is-detected` — Attacker replaces the log and re-anchors it with a chain of their own
- `exfil-via-registry-during-install` — Payload uses the package registry itself as the exfiltration channel
<!-- corpus:end -->

The rate counts a disclosed gap as a failure, because it is one. It counts a
scenario that could not run as a failure too. A corpus that only tallies the
cases it wins produces a nicer number and a worse tool. A test in
`tests/test_attacks.py` fails if this README stops matching what the corpus
actually scores.

This number went **down** when the corpus grew, from 88% to 85%. Nothing
regressed; two disclosed gaps are now counted against a larger set. A rate that
can only rise is a curated one, and there is a test asserting that adding an
honest gap lowers it.

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

### Git dependencies never open a forge (npm)

A dependency like `"is-odd": "github:jonschlinkert/is-odd"` used to require
putting `github.com` in the allowlist for the whole install — and a proxy that
does not intercept TLS cannot tell a clone of that repository from a push of
your stolen token to an attacker's.

So the forge is not in the install's allowlist at all. Declared git dependencies
are fetched first, by a separate phase running under
[`allowlists/npm-resolve.yaml`](allowlists/npm-resolve.yaml), where forges are
reachable, the registry is not, and no package lifecycle script executes. The
install then reads them from a read-only local mirror.

```bash
bh run npm --allow git-dependencies -- npm install
```

`--allow git-dependencies` no longer opens a host to the install. It permits the
resolve phase to run. The audit log from a real run shows the difference:

```
npm-resolve  ALLOW  github.com            ← fetched, before any package code ran
npm          ALLOW  registry.npmjs.org
npm          DENY   codeload.github.com   ← the install tried; it was refused
```

The install succeeds anyway, from the mirror. There is no read to distinguish
from a write because there is no connection.

This is a narrowing, not a solution, in two ways. The registry has to stay
reachable during an install, and a registry accepts writes — that residual is
the corpus scenario `exfil-via-registry-during-install`, counted as a failure
below.

And it is **npm only**. Reading declared git dependencies is manifest-specific,
so pypi and cargo have no resolve phase and `--allow git-dependencies` keeps its
original meaning there: the forge stays reachable for the whole install. `bh run`
warns when that happens. Removing the grant instead would not close the gap for
them, it would only break every project with a git dependency.

The audit log is written to a directory mounted into the proxy container and
nowhere else, so the sandbox cannot read or delete it. Pointing `--audit` inside
the project directory is refused, because the project is mounted writable and a
log the payload can rewrite is not evidence.

After each run the *host-side runner* — a different process, which the sandbox
cannot reach and which the proxy has never had mounted — records the log's head
hash and entry count in a separate anchor store. Truncating a log no longer
passes verification, and anchors are chained across runs so deleting a whole run
is equally visible.

`bh audit` distinguishes two verdicts that a hash chain alone conflates:

```
OK: chain verified against anchor, 12 entries (anchored at 12 by run 4f2a91c0)
UNANCHORED: chain is internally consistent, 12 entries.
    No anchor found, so truncation cannot be detected.
```

Anchoring is not provenance. It raises the bar from writing one file to writing
two consistently. An attacker with write access to both stores forges both, and
that limit is asserted by a test so it cannot be quietly assumed closed.

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
