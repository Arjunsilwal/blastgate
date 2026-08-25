# blastgate

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

Blastgate does not tell you whether a package is malicious. It assumes the answer
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

The corpus measures what blastgate stops. This measures what it breaks, which is
the number that decides whether anyone keeps it switched on.

Every project is installed twice: once in a plain container with full network
access, and once under blastgate. Without that control a failure means nothing —
the project might simply be broken, and counting that as a false positive would
hide real breakage in noise.

```bash
python scripts/compat_check.py
```

**16 of 16 projects install unchanged under blastgate. No false positives found.**

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
| `requests` (git) | pypi | git dependency via the resolve phase | compatible |
| `serde` | cargo | sparse index plus crate downloads | compatible |
| `tokio` `clap` | cargo | hundreds of transitive crates | compatible |
| `anyhow` (git) | cargo | git dependency via the resolve phase | compatible |
| `date-fns` | npm | — | **excluded** |

`date-fns` is excluded because its *control* install fails too: `oxlint@^1.65.0`
floats forward into a peer conflict with its own pinned sibling, so the tag does
not install today under any sandbox. That is upstream's conflict, not
blastgate's. The report prints the `ERESOLVE` output so the exclusion can be
checked rather than taken on trust.

Both runs are retried the same number of times. An unretried control silently
excludes a project on a transient failure, which makes the rate look better by
measuring less — `got` did exactly that on one run and installed fine on the
next two. Deterministic failures skip the retries.

### Why this number is weaker than it looks

Read it as "no false positives found in sixteen projects", not as a rate.

- **The two hardest npm cases passed for reasons unrelated to this design.**
  esbuild and sharp were included because they historically downloaded binaries
  from GitHub releases at postinstall, which blastgate denies. Both now ship
  platform binaries as npm optional dependencies served from the registry. The
  ecosystem moved somewhere convenient; that is luck, and it can move back.
- **The pypi and cargo cases are synthetic manifests**, not cloned projects.
  They exercise real packages, real transitive graphs and real git
  dependencies, but not real repository layouts.
- **Untested entirely:** private registries, authenticated `.npmrc`, workspace
  monorepos, yarn, and pnpm.

## When something is denied

A refusal tells you what to do about it:

```
blast: 1 request(s) reached for host(s) the allowlist does not name: artifacts.internal.test
    if these are legitimate, add them to /path/to/project/.blastgate.yaml:

      version: 1
      allow:
        - host: artifacts.internal.test
          reason: "why this install needs it"

    a host added there is reachable by every install in this project,
    including one running code from a package you did not write.
```

`.blastgate.yaml` can **only add hosts**. Any key that could disable the proxy,
open a port, or turn off anchoring is refused rather than ignored, and every
entry needs a reason — adding a host widens egress, and the diff should say why.
Hosts added this way appear as `[project]` in the audit log.

## In CI

```yaml
- uses: Arjunsilwal/blastgate@v0.1.0
  with:
    ecosystem: npm
    command: npm ci
```

Exit code 3 is the one worth gating on: **the install succeeded, and something
reached for a host the allowlist does not name.** Without a distinct code that
is invisible to a pipeline, because nothing failed.

Denials are not all equal, and treating them as if they were is how a gate gets
switched off. An npm install with a git dependency reaches for
`codeload.github.com`, is refused because the forge is deliberately unreachable
during the install phase, and finishes from the local mirror. That is correct
behaviour, not an incident:

```
denied: [('codeload.github.com', 'known')]     -> exit 0
denied: [('exfil.attacker.test', 'UNKNOWN')]   -> exit 3
```

`--json PATH` writes a machine-readable summary. Full details in
[docs/ci.md](docs/ci.md).

## What the attack corpus scores

`tests/attacks/` holds executable scenarios. Each one is run against the real
sandbox and scored, and the number below is regenerated from that run rather
than written by hand:

```bash
python scripts/attack_report.py --write
```

<!-- corpus:begin -->
**14 of 16 scenarios prevented (88%).**

| Scenario | Link | Expected | Result |
| --- | --- | --- | --- |
| `audit-replacement-is-detected` | 6 | not_prevented | known-gap ⚠ |
| `audit-truncation-is-detected` | 6 | denied | prevented |
| `dns-tunnelled-exfiltration` | 5 | denied | prevented |
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
| `registry-token-theft-from-the-sandbox` | 4 | denied | prevented |
| `registry-traffic-still-works` | 0 | allowed | allowed |
| `shai-hulud-webhook-exfiltration` | 5 | denied | prevented |

Counted as failures because they are:
- `audit-replacement-is-detected` — Attacker replaces the log and re-anchors it with a chain of their own
- `exfil-via-registry-during-install` — Payload uses the package registry itself as the exfiltration channel
<!-- corpus:end -->

The rate counts a disclosed gap as a failure, because it is one. It counts a
scenario that could not run as a failure too. A corpus that only tallies the
cases it wins produces a nicer number and a worse tool. A test in
`tests/test_attacks.py` fails if this README stops matching what the corpus
actually scores.

This number moves when the corpus grows, in both directions, and neither
direction means what it looks like. It fell from 88% to 85% when two disclosed
gaps started being counted against a larger set, and rose again when scenarios
were added that blastgate prevents. A rate that can only rise is a curated one,
and there is a test asserting that adding an honest gap lowers it.

Scenarios are drawn from documented incidents where one exists. The
`source:` field carries the write-up, and scenarios with no verifiable source
say `constructed` rather than borrowing a citation from an incident they only
resemble.

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

### Git dependencies never open a forge

A dependency like `"is-odd": "github:jonschlinkert/is-odd"` used to require
putting `github.com` in the allowlist for the whole install — and a proxy that
does not intercept TLS cannot tell a clone of that repository from a push of
your stolen token to an attacker's.

So the forge is not in the install's allowlist at all. Declared git dependencies
are fetched first, by a separate phase running under
[`blastgate/allowlists/npm-resolve.yaml`](blastgate/allowlists/npm-resolve.yaml), where forges are
reachable, the registry is not, and no package lifecycle script executes. The
install then reads them from a read-only local mirror.

```bash
blast run npm --allow git-dependencies -- npm install
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

This works the same way for all three ecosystems. npm, pip and cargo all shell
out to git, so the same mirror and the same rewriting serve all of them; only
the spelling of a dependency differs between manifests. cargo needs one extra
push, because it fetches with libgit2 which ignores `url.insteadOf` —
`CARGO_NET_GIT_FETCH_WITH_CLI` makes it use the git CLI so the redirection
applies.

It is a narrowing, not a solution. The registry has to stay reachable during an
install, and a registry accepts writes — that residual is the corpus scenario
`exfil-via-registry-during-install`, counted as a failure below. And an
ecosystem added later has no parser until one is written, so it keeps the older
arrangement and `blast run` warns when that path is taken.

### Private registries: the token never enters the sandbox

Installing from a private registry normally means a token in `~/.npmrc`,
readable by every postinstall script that runs. That is not a hypothetical
weakness — it is what the Shai-Hulud worm harvested, from that exact file,
across several hundred packages.

```bash
echo -n "$NPM_TOKEN" | blast creds add registry.internal.example.com
blast run npm -- npm ci
```

The credential stays on the host. The sandbox talks plain HTTP to the broker
over a network with no gateway, and the broker attaches the `Authorization`
header on the upstream leg. A payload that reads every environment variable and
every readable file inside the sandbox finds nothing — which is the corpus
scenario `registry-token-theft-from-the-sandbox`, not a claim.

The secret is read from **stdin, never an argument**, because arguments are
visible in `ps`. `blast creds list` prints hosts and withholds secrets. The
store is mode 0600 and is refused outright if anything wider.

**The broker forwards reads only.** It is authenticated, so without that a
payload could publish through it — which is precisely how Shai-Hulud spread,
republishing every package the stolen token could reach. `PUT`, `POST`,
`DELETE` and `PATCH` get 405.

This is not TLS interception. There is no CA, nothing to distribute or expire,
and no TLS parser in the path of attacker-controlled bytes. What a payload
retains is the ability to *make* authenticated reads during the install; what
it cannot do is take the token anywhere.

The audit log is written to a directory mounted into the proxy container and
nowhere else, so the sandbox cannot read or delete it. Pointing `--audit` inside
the project directory is refused, because the project is mounted writable and a
log the payload can rewrite is not evidence.

After each run the *host-side runner* — a different process, which the sandbox
cannot reach and which the proxy has never had mounted — records the log's head
hash and entry count in a separate anchor store. Truncating a log no longer
passes verification, and anchors are chained across runs so deleting a whole run
is equally visible.

`blast audit` distinguishes two verdicts that a hash chain alone conflates:

```
OK: chain verified against anchor, 12 entries (anchored at 12 by run 4f2a91c0)
UNANCHORED: chain is internally consistent, 12 entries.
    No anchor found, so truncation cannot be detected.
```

Anchoring is not provenance. It raises the bar from writing one file to writing
two consistently. An attacker with write access to both stores forges both, and
that limit is asserted by a test so it cannot be quietly assumed closed.

## Install

```bash
pip install blastgate
```

Requires Docker or Podman, and Python 3.10+.

## Run an install

```bash
blast run npm -- npm ci
```

The install command goes after `--`. Blastgate's own options go before it:

```bash
blast run npm --project ./app --allow git-dependencies -- npm install
```

Then review what it tried to reach:

```bash
blast audit ~/.blastgate/audit/<project>-<hash>.log
```

Every failure path refuses rather than falling back. A missing runtime, a
network that is not actually internal, or a sidecar that does not come up all
produce a refusal, never an unsandboxed install.

## Try the policy engine

No Docker, no containers, nothing to configure.

```bash
blast check npm registry.npmjs.org
```

```
ALLOW registry.npmjs.org (matched: exact:registry.npmjs.org) - Primary package registry metadata and tarball host
```

Default is deny, and every allow path is explicit:

```
$ blast check npm evil.example.com
DENY evil.example.com - default deny: host not in allowlist

$ blast check npm cdn.npmjs.org
ALLOW cdn.npmjs.org (matched: wildcard:*.npmjs.org) - Registry CDN edge nodes and asset endpoints

$ blast check npm registry.npmjs.org.evil.com
DENY registry.npmjs.org.evil.com - default deny: host not in allowlist

$ blast check npm 127.0.0.1
DENY 127.0.0.1 - invalid hostname: Raw IP addresses are not allowed: 127.0.0.1
```

Hosts that are commonly needed but double as exfiltration channels are denied
unless you opt in by name:

```
$ blast check npm github.com
DENY github.com - conditional host requires condition 'git-dependencies': Direct git repository dependencies and GitHub release assets

$ blast check npm github.com --allow git-dependencies
ALLOW github.com (matched: conditional:github.com) - Direct git repository dependencies and GitHub release assets
```

Exit code is 0 for allow, 1 for deny, 2 for an error. Allowlists ship in-repo
under [`blastgate/allowlists/`](blastgate/allowlists/) — a remote fetch would itself be a supply
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
- **Ports are not policy.** `blast check npm registry.npmjs.org:8443` reports ALLOW
  because policy decides on hostname alone. The proxy restricts tunnelling to
  443, so the two disagree when inspected separately.
- **Your project must live where the runtime can see it.** On macOS the runtime
  runs in a VM sharing only part of the filesystem; a project outside a shared
  path cannot be mounted.

## The rule

Every protection claim maps to a test that fails when the control is removed. A
control with no test is a claim, not a protection, and stays in the gaps list
until it has one. If a change alters what blastgate protects against, the threat
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
