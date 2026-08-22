# Threat model

**Status: pre-alpha. Bulkhead currently enforces nothing.**

This document is the specification for what bulkhead is meant to prevent, written
before the code that would prevent it. Every later design decision resolves back
to this file. If a change alters what the tool protects against, this file changes
in the same commit.

At the time of writing, the only implemented component is the policy engine
(`bulkhead/policy.py`), which answers "is this host on the allowlist?" as a pure
function. It does not isolate anything, does not intercept traffic, and is not
wired to any package manager. **Nothing in section 6 constitutes protection of a
real install today.** See section 7 for the precise gap between design and
implementation.

Document version: 1. Last reviewed: 2026-08-22.

---

## 1. What is being defended

A developer or CI runner installing third-party packages from a public registry
(`npm install`, `pip install`, `cargo build`).

The assets at risk, in priority order:

1. **Long-lived credentials on the host** — registry publish tokens, SSH private
   keys, cloud credential files (`~/.aws`, `~/.config/gcloud`), kubeconfigs, CI
   secrets in environment variables, browser and keychain material.
2. **Source code and proprietary data** in and around the project directory.
3. **The integrity of the developer's own published packages**, which a stolen
   publish token converts into the next stage of the worm.

Asset 1 is first because it is what makes these campaigns self-propagating.

## 2. The attack chain

The registry supply chain worms observed through 2026 share one structure:

| # | Link | Description |
|---|---|---|
| 1 | Account takeover | Attacker steals a maintainer's registry token or forge credentials. |
| 2 | Automated republishing | Trojanized patch versions are pushed across every package the account controls, faster than human review. |
| 3 | Silent execution | A lifecycle hook, or a less obvious path, runs attacker code during install with the full permissions of the invoking user. |
| 4 | Credential harvest | The payload reads tokens, keys, cloud credential files, environment variables. |
| 5 | Exfiltration | Harvested material leaves over the network. |
| 6 | Propagation | Stolen publish tokens republish more packages, returning to link 2. |

> **Citation needed before publication.** The V0 plan references specific 2026
> campaigns — a June campaign using a weaponized `binding.gyp` to obtain execution
> via `node-gyp`, and August guidance that affected machines be treated as
> compromised. Those references are load-bearing for section 3 and must carry
> links to primary write-ups before this repository is promoted. Unsourced
> specifics in a security document are a defect.

## 3. Which link is cut, and why

**Link 3 cannot be reliably prevented. Links 4 and 5 can be constrained.**

There is no bounded list of ways to obtain code execution during an install.
Lifecycle hooks are the well-known path; build-time native compilation, plugin
resolution, and interpreted configuration files are others, and the set grows
whenever someone looks. Any defense that enumerates known execution paths is
playing a game in which the attacker chooses the next move.

Links 4 and 5 are structurally narrow:

- Credential theft requires **reading files an install has no business reading**.
- Exfiltration requires **reaching a network destination an install has no
  business reaching**.

Both are chokepoints. Neither depends on knowing how execution was obtained.

Two controls, no detection:

- **Isolation** — the install sees the project directory and nothing else.
- **Egress control** — the install reaches a short allowlist; everything else is
  denied and logged.

The design principle: *it should not matter how the code got execution, because
there is nothing to steal and nowhere to send it.*

This is a containment argument, not a detection argument. Bulkhead does not try to
decide whether a package is malicious. It assumes every package is malicious and
constrains what that can accomplish.

## 4. Trust boundary

```
  HOST (trusted)
  credentials, SSH keys, cloud config, shell and IDE config, other projects
        |
        |  crosses inward: nothing
        |  crosses outward: the project directory, mounted
        v
  INSTALL CONTAINER (untrusted)      joined ONLY to the internal network
  project dir, package manager, arbitrary third-party package code
        |
        |  no alternative route exists
        v
  PROXY CONTAINER (enforcement point)   joined to internal AND external networks
        |
        |  allowlist decision, logged
        v
  INTERNET
```

Stated explicitly:

- **Untrusted:** all package code, all registry content, all package metadata,
  every byte inside the install container, and every string the proxy parses.
- **Trusted:** the host, the container runtime, the base images, bulkhead's own
  code, and the allowlist files in this repository.
- **The boundary** is the install container's network namespace and mount
  namespace. The security property is intended to be *topological* — the install
  container has no route to the internet, and the only reachable host on its
  network is the proxy. A payload cannot opt out of policy because there is
  nothing to opt out to.

The proxy parses hostile input by design and therefore holds no credentials of its
own. Compromising the proxy yields egress, not secrets.

## 5. Adversary

Assumed capabilities:

- Arbitrary code execution inside the install container, as the install user, at
  install time.
- Full knowledge of bulkhead's source, allowlists, and this document.
- Ability to publish arbitrary package content to a public registry, including
  content targeting bulkhead specifically.
- Ability to control DNS responses for hosts they own, and to operate services on
  arbitrary ports at hosts they control.

Assumed *not* available:

- A working container-runtime escape (see section 8).
- Compromise of the host before the install begins.
- Compromise of the registries themselves, or of the base images.

## 6. What is defended against

Every row maps to a test that fails when the control is removed. **A control with
no test is a claim, not a protection, and belongs in section 8 until it has one.**

All rows below are properties of the policy engine, tested in
`tests/test_policy.py`. They describe what the *decision function* does, not what
is enforced against a running install — see section 7.

| Claim | Control | Test |
|---|---|---|
| An unlisted host is denied | Default deny; no implicit allow path | `TestDefaultDeny::test_unlisted_domain_denied` |
| An allowlist for one ecosystem does not grant another ecosystem's hosts | Per-ecosystem policy files | `TestDefaultDeny::test_cross_ecosystem_denied` |
| Case variation does not evade a rule | Hostname lowercased during normalization | `TestEvasion::test_case_variation_exact`, `::test_case_variation_wildcard` |
| A trailing DNS root dot does not evade a rule | Single trailing dot stripped | `TestEvasion::test_trailing_dot_exact`, `::test_trailing_dot_wildcard` |
| Malformed dot placement is denied | Empty labels and leading dots rejected | `TestEvasion::test_multiple_trailing_dots_denied`, `::test_leading_dot_denied` |
| A lookalike domain does not match an allowlisted host | Exact match on the full normalized hostname | `TestEvasion::test_lookalike_domains_denied` |
| A suffix wildcard cannot be defeated by prefixing the domain | Wildcard requires a true label boundary | `TestEvasion::test_prefix_spoofing_suffix_wildcard_denied` |
| A raw IP address is never a valid target | IPv4 and IPv6 literals rejected | `TestEvasion::test_raw_ipv4_denied`, `::test_raw_ipv6_denied` |
| Alternate IP encodings do not bypass the IP rejection | Integer and hex forms rejected | `TestEvasion::test_alternate_ip_encodings_denied` |
| URI and shell metacharacters in a host are rejected, not parsed | Character allowlist plus RFC 1123 label validation | `TestEvasion::test_uri_injection_and_malformed_hosts` |
| A host commonly needed but usable for exfiltration is denied unless opted into | Conditional tier, off by default | `TestConditionalRules::test_conditional_denied_by_default` |
| Enabling one condition does not enable another | Conditions matched by name | `TestConditionalRules::test_conditional_denied_when_different_condition_enabled` |
| An allowlist entry without a stated reason is rejected at load | Schema validation | `TestPolicySchemaAndLoading::test_rule_without_reason_raises` |

Two deliberate properties worth stating because they surprise people:

- A suffix wildcard does **not** cover the apex. `*.npmjs.org` allows
  `registry.npmjs.org` but not `npmjs.org`; the apex must be listed explicitly.
- The policy engine is pure. No network, no subprocess, no filesystem access
  beyond reading the allowlist, no model calls, ever. Purity is what makes it
  exhaustively testable, and exhaustive testing is the product.

## 7. Designed but not implemented

These are the controls the argument in section 3 actually depends on. **None of
them exist yet.** Until each ships with a test in `tests/attacks/` that fails when
the control is removed, bulkhead prevents nothing about a real install.

| Control | Module | Status |
|---|---|---|
| Isolation: project directory is the only mount | `runner.py` | Not written |
| Credential-shaped environment stripping | `runner.py` | Not written |
| Network topology: install container has no route out | `runner.py` | Not written |
| Egress enforcement at the proxy | `proxy.py` | Not written |
| Hash-chained audit log | `audit.py` | Not written |
| Executable attack scenario corpus | `tests/attacks/` | Not written |

Until then the policy engine is a correct answer to a question nothing is asking.

## 8. What is NOT defended against

This section is longer than section 6 on purpose. Someone hostile should be able
to read it and not find a gap that was left undisclosed.

### 8.1 Structural limits of the design

- **Container escape.** Isolation depends entirely on the container runtime. A
  payload with a working escape reaches the host and every credential on it.
  Bulkhead adds a layer; it does not add a guarantee.
- **Exfiltration to an allowlisted host.** There is no TLS interception in v0, so
  a payload that writes stolen material to an attacker-controlled repository on an
  allowlisted forge is not blocked. This gap is real and was used in the 2026
  campaigns. Closing it requires distinguishing reads from writes at allowlisted
  hosts, which is not in v0. The conditional tier reduces the exposure by denying
  forge hosts unless the user opts in; it does not remove it.
- **DNS-based exfiltration.** Data encoded in DNS queries is not detected or
  blocked.
- **Compromised base image or package manager.** If the sandbox interior is
  already hostile, bulkhead enforces nothing useful.
- **Post-install runtime.** Bulkhead protects the install. It does not protect the
  application when it later runs.
- **Anything outside an install.** A malicious package that does nothing at
  install time and attacks in production is entirely out of scope.

### 8.2 Limits of the policy engine as written

- **Ports are stripped and ignored.** `registry.npmjs.org:8443` normalizes to
  `registry.npmjs.org` and is allowed. Policy makes no port distinction, so a
  service on a non-standard port at an allowlisted host is permitted.
- **No IP or certificate pinning.** Policy operates on hostname strings. Whatever
  resolves the name decides the address. An attacker who controls DNS for an
  allowlisted name, or who can rebind it, is not stopped by policy.
- **The proxy will see hostnames, not content.** Without TLS interception the
  enforcement point knows the destination and nothing else. Volume, timing, and
  payload are invisible.
- **Nothing binds an install to its declared ecosystem.** Running an `npm` install
  under the `pypi` allowlist is a user error the tool does not currently catch.
- **Unicode and IDN hostnames are rejected outright**, not punycode-normalized.
  This is fail-closed and may produce false negatives on legitimate
  internationalized hosts.
- **Allowlist trust.** The shipped allowlists are trusted input. A bad entry
  merged into this repository is a direct compromise of the control, which is why
  every entry carries a reason and allowlist changes are reviewed as security
  changes.

### 8.3 Explicit non-goals

- Bulkhead does not detect malicious packages, score them, or tell you whether a
  version is safe. Other tools do that well. This one assumes the answer is "no"
  and contains the consequences.
- Bulkhead does not intercept TLS by default and will not in v0. If interception
  is ever added it will be opt-in. A tool that decrypts a developer's traffic by
  default does not deserve trust.
- Bulkhead never falls back to unsandboxed execution. If the container runtime is
  unavailable, it fails closed and refuses to run.

## 9. Residual risk if every phase ships as designed

Assuming all of section 7 is built and tested, a payload with install-time
execution can still:

- exfiltrate to an allowlisted host over TLS, if the user has opted into a
  conditional forge host;
- exfiltrate over DNS;
- read and corrupt everything in the project directory, which is mounted writable
  and includes any secrets the developer keeps there;
- persist inside the project directory — a poisoned lockfile, a modified build
  script — and attack later, outside the sandbox;
- attempt a container escape.

Bulkhead's claim at v1 is narrow and should be stated narrowly: **an install-time
payload cannot read host credentials it was never given, and cannot reach a
network destination that is not on a short reviewed list.** Everything above
remains true at the same time.

## 10. How to invalidate a claim in this document

- A protection claim without a passing test that fails when the control is removed
  must be moved to section 8.
- Any change to `bulkhead/` that alters what the tool protects against updates this
  file in the same commit, or the change is refused.
- If a gap in section 8 is closed, it moves to section 6 with its test, and the
  README's status language is re-checked in the same commit.
