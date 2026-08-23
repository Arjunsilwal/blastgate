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

Document version: 6. Last reviewed: 2026-08-22.

**Design note, recorded because it departs from the v0 plan.** The plan specified
environment variables "filtered by shape (prefix, and any name containing TOKEN,
SECRET, PASSWORD, KEY)". That is a denylist, and it has to anticipate every
credential variable that will ever exist. As implemented, the primary control is
instead a default-deny allowlist of names an install legitimately needs, with the
shape check retained as a second layer over variables the user forwards
explicitly. This is strictly more restrictive than the plan and consistent with
the default-deny principle used everywhere else, but it is a trust-boundary
change and belongs in the record rather than in a commit message.

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

Most rows below are properties of *pure functions* — they say the decision is
correct, not that an install is constrained. The rows marked *(runtime)* are
different: they are demonstrated against a real container runtime in
`tests/test_topology.py` and do constrain a running process. Rows marked
*(constrains bulkhead)* limit this tool's own behaviour rather than an
attacker's.

The runtime rows depend on a control test asserting that a container on the
default bridge *does* reach the network. Without it, a runtime with no
connectivity would satisfy every isolation assertion while proving nothing.

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
| `bh run` never falls back to an unsandboxed install *(constrains bulkhead)* | Every error path refuses; no fallback branch in the CLI | `TestCliRun::test_run_refuses_when_no_runtime_is_available`, `::test_run_refuses_an_audit_log_inside_the_project` |
| Bulkhead's own options are not swallowed into the install command *(constrains bulkhead)* | `--` split before argparse; REMAINDER would silently drop `--audit` | `TestCliRun::test_bulkhead_options_are_not_swallowed_into_the_command` |
| A host environment variable does not reach the sandbox unless it was named | Default-deny allowlist over variable names | `test_runner.py::TestDefaultDeny::test_unknown_variable_is_withheld`, `::test_variable_invented_tomorrow_is_withheld` |
| A credential variable from a real registry campaign does not reach the sandbox | Same allowlist; 24 real names asserted | `TestDefaultDeny::test_real_credential_names_are_withheld` |
| Host proxy settings are not inherited into the sandbox | Withheld by default; bulkhead sets its own | `TestDefaultDeny::test_proxy_settings_are_not_inherited` |
| Registry-redirection variables are not inherited into the sandbox | Withheld by default | `TestDefaultDeny::test_registry_redirection_is_not_inherited` |
| A user cannot forward a credential-shaped variable into the sandbox *(constrains bulkhead)* | Second-layer shape check; fails closed on explicit request | `TestExplicitForwarding::test_forwarding_a_credential_fails_closed` |
| An absent container runtime is a refusal, not a degraded mode *(constrains bulkhead)* | `detect_runtime` raises rather than returning a falsy value | `TestRuntimeDetection::test_missing_runtime_raises_rather_than_returning_none` |
| A denial cannot be edited into an allow without detection | Hash-chained audit entries | `test_audit.py::TestTamperDetection::test_flipping_a_denial_to_an_allow_is_detected` |
| An audit entry cannot be removed, reordered, or forged into the middle without detection | Each entry commits to its predecessor's hash | `TestTamperDetection::test_removing_a_middle_entry_is_detected`, `::test_reordering_entries_is_detected`, `::test_splicing_a_forged_entry_is_detected` |
| Fixing an edited entry's own hash does not repair the chain | Later entries still commit to the original hash | `TestTamperDetection::test_recomputing_the_hash_after_editing_is_still_detected` |
| Appending to an already-broken log is refused | Tail is verified before extension | `TestTamperDetection::test_appending_to_a_tampered_log_is_refused` |
| A denied host is refused at the enforcement point, not merely judged | Proxy returns 403 and never opens the upstream connection | `test_proxy.py::TestEnforcement::test_denied_host_is_refused` |
| A `Host:` header cannot launder a denied CONNECT target | Decision uses the CONNECT target only; headers are drained and ignored | `TestEnforcement::test_host_header_cannot_override_connect_target` |
| An allowlisted host is not reachable on an arbitrary port | Proxy restricts tunnelling to port 443 | `TestEnforcement::test_non_standard_port_refused_on_allowlisted_host` |
| Plain HTTP through the proxy is refused rather than forwarded | Only CONNECT is accepted; absolute-URI requests are rejected | `TestRequestParsing::test_non_connect_methods_refused` |
| Every egress decision reaches the log | Proxy records before responding | `TestEnforcement::test_every_decision_is_recorded` |
| An install in the sandbox has no route to the internet *(runtime)* | Internal network with no gateway | `test_topology.py::TestNoRouteOut::test_sandbox_cannot_reach_the_internet` |
| Skipping DNS and dialling an address directly does not help *(runtime)* | Same; there is no route regardless of name resolution | `TestNoRouteOut::test_sandbox_cannot_reach_a_raw_address` |
| The sandbox has no default route at all *(runtime)* | Same | `TestNoRouteOut::test_sandbox_has_no_default_route` |
| Public DNS does not resolve inside the sandbox *(runtime)* | Same | `TestNoRouteOut::test_sandbox_cannot_resolve_public_dns` |
| The project directory is the only host mount *(runtime)* | Single bind mount; host home is absent | `TestMountBoundary::test_host_home_is_not_mounted`, `::test_only_one_host_mount_exists` |
| The container runtime's socket is not exposed to the install *(runtime)* | Not mounted | `TestMountBoundary::test_docker_socket_is_not_mounted` |
| Host credentials do not appear in the sandbox environment *(runtime)* | Filtered environment passed explicitly | `TestEnvironmentAtTheBoundary::test_host_credentials_do_not_appear_in_the_sandbox` |
| A network that is not actually internal is refused *(constrains bulkhead)* | Internality is inspected, not inferred from the name | `TestNetworkIntegrity::test_non_internal_network_is_refused` |
| An allowlisted host is reachable through the proxy *(runtime)* | Sidecar joined to both networks | `test_end_to_end.py::TestTheWholeThing::test_an_allowlisted_host_is_reachable_through_the_proxy` |
| A denied host is not reachable from a real install *(runtime)* | Policy enforced at the proxy | `TestTheWholeThing::test_a_denied_host_is_not_reachable` |
| A payload that ignores the proxy variables is still blocked *(runtime)* | Topology, not configuration: there is no route to find | `TestTheWholeThing::test_a_payload_that_ignores_the_proxy_is_still_blocked` |
| The proxy is the only host the sandbox can open a socket to *(runtime)* | Internal network membership | `TestTheWholeThing::test_the_proxy_is_the_only_host_reachable` |
| The audit log is not visible from inside the sandbox *(runtime)* | Audit directory mounted into the proxy container only | `TestTheAuditLog::test_the_sandbox_cannot_see_the_log` |
| An audit log inside the project directory is refused *(constrains bulkhead)* | The project is mounted writable; a log there is one the payload can rewrite | `TestTheAuditLog::test_a_log_inside_the_project_is_refused` |
| A real `npm install` completes inside the sandbox *(runtime)* | Whole path end to end | `TestARealInstall::test_npm_install_succeeds_inside_the_sandbox` |
| Every corpus scenario runs; none is silently skipped *(constrains bulkhead)* | Unrunnable scenarios are counted as failures | `test_attacks.py::TestCorpusResults::test_no_scenario_failed_to_run` |
| No denied scenario gets through *(runtime)* | Corpus executed against the real sandbox | `TestCorpusResults::test_no_regressions` |
| No legitimate scenario is broken *(runtime)* | Same | `TestCorpusResults::test_no_false_positives` |
| A disclosed gap is counted as a failure, not omitted *(constrains bulkhead)* | Scoring treats `not_prevented` as failing | `TestScoring::test_a_disclosed_gap_that_still_reproduces_counts_against_the_rate` |
| A gap that stops reproducing fails loudly rather than passing quietly *(constrains bulkhead)* | Closing a gap means the threat model is stale | `TestCorpusResults::test_disclosed_gaps_still_reproduce` |
| A malformed scenario is refused rather than skipped *(constrains bulkhead)* | Dropping one would inflate the rate | `TestSchema::test_a_malformed_scenario_is_loud_not_skipped` |
| The published pass rate matches what the corpus scores *(constrains bulkhead)* | README is generated, and a test fails if it drifts | `TestCorpusResults::test_the_published_number_matches_the_corpus` |

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
| Isolation: project directory is the only mount | `runner.py` | **Written and demonstrated** (section 6) |
| Environment filtering: deciding what may cross | `runner.py` | **Written and tested** (section 6) |
| Environment filtering: applying that decision to a real container | `runner.py` | **Written and demonstrated** (section 6) |
| Network topology: install container has no route out | `runner.py` | **Written and demonstrated** (section 6) |
| Egress enforcement: CONNECT handling and the allow/deny response | `proxy.py` | **Written and tested** (section 6) |
| Egress enforcement: the proxy running as a sidecar on both networks | `runner.py` | **Written and demonstrated** (section 6) |
| Hash-chained audit log: tamper-evident structure | `audit.py` | **Written and tested** (section 6) |
| Hash-chained audit log: written where the payload cannot reach it | `runner.py` | **Written and demonstrated** (section 6) |
| Executable attack scenario corpus | `tests/attacks/` | **Written and running** (section 6) |

Every control in the design is built and demonstrated against a running
install, and the attack corpus executes against the real sandbox. `bh run`
works; a real `npm install` completes inside it with one allowed route out.

The corpus currently scores **7 of 8 (88%)**. The single failure is
`exfil-over-tls-to-allowlisted-host`, which is section 8.1's first gap written
as an executable scenario. It is expected to succeed for the attacker, and it is
counted as a failure anyway. Scenarios that cannot run are counted as failures
too. The number is regenerated by `scripts/attack_report.py` and a test fails if
the README stops matching it, so it is not a number anyone here chose.

Section 8 has not shrunk. What is built works; what is listed there is a limit
on what this design attempts, and a corpus of eight scenarios is a small corpus.
The next honest step is more scenarios drawn from real write-ups rather than
constructed ones — every current scenario is marked `source: constructed`, and
that is a real weakness in the evidence.

Because none of the above exists, `bh run` refuses to execute rather than running
an install without an enforcement point. This is the fail-closed default from
section 8.3, applied to the tool's own incompleteness: a sandbox that is not
built and a container runtime that is unavailable are the same condition, and
both must refuse rather than degrade. The refusal is a property of bulkhead, not
a protection against an attacker — it prevents a user from being misled into
relying on an enforcement point that does not exist. It stops nothing that a
malicious package does.

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

- **The policy engine still ignores ports.** `bh check npm registry.npmjs.org:8443`
  reports ALLOW, because normalization strips the port and the decision is made
  on hostname alone. The restriction to port 443 lives in the proxy, not in
  policy, so the two disagree when inspected separately. Treat `bh check` as
  answering "is this host allowed", never "is this destination reachable".
- **The project must live somewhere the runtime can see.** On macOS the
  container runtime runs inside a VM that shares only part of the host
  filesystem. A project outside a shared path cannot be mounted and the run
  fails. This is a usability constraint rather than a weakness, but it means the
  set of directories bulkhead can protect is smaller than "any directory".
- **Refusing plain HTTP may break real installs.** The proxy accepts only
  CONNECT. A package manager or mirror that falls back to unencrypted HTTP will
  fail rather than be forwarded. This is fail-closed and deliberate, and it is a
  false-positive risk against a stated budget of near zero.
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
- **Audit truncation is not detected.** Removing the most recent entries leaves
  a shorter chain that still verifies. Detecting this requires anchoring the head
  somewhere the writer cannot reach, which bulkhead does not do. Asserted
  explicitly in `TestDisclosedLimits::test_truncating_the_tail_is_NOT_detected`
  so the limit cannot be quietly assumed closed.
- **The audit log proves consistency, not provenance.** An attacker who can write
  the file can replace it wholesale with a valid chain of their own. The chain is
  only meaningful while the log lives somewhere the install container cannot
  reach, which depends on the topology and is not built.
- **The environment filter is blind to values.** It decides by variable *name*
  only. A secret stored under a name like `BUILD_NUMBER` is not recognised as a
  secret, and would be forwarded if the user asked for it by name. Shape
  checking cannot close this and is not claimed to.
- **The environment is not the only route to a credential.** Filtering variables
  does nothing about credentials on disk — `~/.npmrc`, `~/.aws`, SSH keys. Those
  are addressed by the mount boundary, which is not built. Until it is, the
  environment filter protects against one of the two harvest routes and the more
  valuable one remains open.
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
  unavailable, if the network is not actually internal, or if the sidecar does
  not come up, it fails closed
  and refuses to run. This is enforced in code and tested, not merely intended.

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
