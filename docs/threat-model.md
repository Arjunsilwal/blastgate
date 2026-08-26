# Threat model

**Status: pre-alpha. Blastgate currently enforces nothing.**

This document is the specification for what blastgate is meant to prevent, written
before the code that would prevent it. Every later design decision resolves back
to this file. If a change alters what the tool protects against, this file changes
in the same commit.

At the time of writing, the only implemented component is the policy engine
(`blastgate/policy.py`), which answers "is this host on the allowlist?" as a pure
function. It does not isolate anything, does not intercept traffic, and is not
wired to any package manager. **Nothing in section 6 constitutes protection of a
real install today.** See section 7 for the precise gap between design and
implementation.

Document version: 19. Last reviewed: 2026-08-22.

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

This is a containment argument, not a detection argument. Blastgate does not try to
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
- **Trusted:** the host, the container runtime, the base images, blastgate's own
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
- Full knowledge of blastgate's source, allowlists, and this document.
- Ability to publish arbitrary package content to a public registry, including
  content targeting blastgate specifically.
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
*(constrains blastgate)* limit this tool's own behaviour rather than an
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
| `blast run` never falls back to an unsandboxed install *(constrains blastgate)* | Every error path refuses; no fallback branch in the CLI | `TestCliRun::test_run_refuses_when_no_runtime_is_available`, `::test_run_refuses_an_audit_log_inside_the_project` |
| Blastgate's own options are not swallowed into the install command *(constrains blastgate)* | `--` split before argparse; REMAINDER would silently drop `--audit` | `TestCliRun::test_blastgate_options_are_not_swallowed_into_the_command` |
| A host environment variable does not reach the sandbox unless it was named | Default-deny allowlist over variable names | `test_runner.py::TestDefaultDeny::test_unknown_variable_is_withheld`, `::test_variable_invented_tomorrow_is_withheld` |
| A credential variable from a real registry campaign does not reach the sandbox | Same allowlist; 24 real names asserted | `TestDefaultDeny::test_real_credential_names_are_withheld` |
| Host proxy settings are not inherited into the sandbox | Withheld by default; blastgate sets its own | `TestDefaultDeny::test_proxy_settings_are_not_inherited` |
| Registry-redirection variables are not inherited into the sandbox | Withheld by default | `TestDefaultDeny::test_registry_redirection_is_not_inherited` |
| A user cannot forward a credential-shaped variable into the sandbox *(constrains blastgate)* | Second-layer shape check; fails closed on explicit request | `TestExplicitForwarding::test_forwarding_a_credential_fails_closed` |
| An absent container runtime is a refusal, not a degraded mode *(constrains blastgate)* | `detect_runtime` raises rather than returning a falsy value | `TestRuntimeDetection::test_missing_runtime_raises_rather_than_returning_none` |
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
| A network that is not actually internal is refused *(constrains blastgate)* | Internality is inspected, not inferred from the name | `TestNetworkIntegrity::test_non_internal_network_is_refused` |
| An allowlisted host is reachable through the proxy *(runtime)* | Sidecar joined to both networks | `test_end_to_end.py::TestTheWholeThing::test_an_allowlisted_host_is_reachable_through_the_proxy` |
| A denied host is not reachable from a real install *(runtime)* | Policy enforced at the proxy | `TestTheWholeThing::test_a_denied_host_is_not_reachable` |
| A payload that ignores the proxy variables is still blocked *(runtime)* | Topology, not configuration: there is no route to find | `TestTheWholeThing::test_a_payload_that_ignores_the_proxy_is_still_blocked` |
| The proxy is the only host the sandbox can open a socket to *(runtime)* | Internal network membership | `TestTheWholeThing::test_the_proxy_is_the_only_host_reachable` |
| The audit log is not visible from inside the sandbox *(runtime)* | Audit directory mounted into the proxy container only | `TestTheAuditLog::test_the_sandbox_cannot_see_the_log` |
| An audit log inside the project directory is refused *(constrains blastgate)* | The project is mounted writable; a log there is one the payload can rewrite | `TestTheAuditLog::test_a_log_inside_the_project_is_refused` |
| A real `npm install` completes inside the sandbox *(runtime)* | Whole path end to end | `TestARealInstall::test_npm_install_succeeds_inside_the_sandbox` |
| Every corpus scenario runs; none is silently skipped *(constrains blastgate)* | Unrunnable scenarios are counted as failures | `test_attacks.py::TestCorpusResults::test_no_scenario_failed_to_run` |
| No denied scenario gets through *(runtime)* | Corpus executed against the real sandbox | `TestCorpusResults::test_no_regressions` |
| No legitimate scenario is broken *(runtime)* | Same | `TestCorpusResults::test_no_false_positives` |
| A disclosed gap is counted as a failure, not omitted *(constrains blastgate)* | Scoring treats `not_prevented` as failing | `TestScoring::test_a_disclosed_gap_that_still_reproduces_counts_against_the_rate` |
| A gap that stops reproducing fails loudly rather than passing quietly *(constrains blastgate)* | Closing a gap means the threat model is stale | `TestCorpusResults::test_disclosed_gaps_still_reproduce` |
| A malformed scenario is refused rather than skipped *(constrains blastgate)* | Dropping one would inflate the rate | `TestSchema::test_a_malformed_scenario_is_loud_not_skipped` |
| Deleting denials from the end of the audit log is caught | Corpus tampers with a real log and checks it against its anchor | `audit-truncation-is-detected` |
| A project with a git dependency installs with every forge denied *(runtime)* | Corpus runs a real install end to end | `git-dependency-still-installs` |
| Nothing in the resolve image can run a package lifecycle script *(runtime)* | No package manager and no interpreter present | `fetch-phase-runs-no-lifecycle-scripts` |
| The corpus can score the tool worse than before *(constrains blastgate)* | An added gap lowers the published rate | `TestScoring::test_adding_an_honest_gap_lowers_the_rate` |
| The published pass rate matches what the corpus scores *(constrains blastgate)* | README is generated, and a test fails if it drifts | `TestCorpusResults::test_the_published_number_matches_the_corpus` |
| A denied hostname is never resolved | Policy is evaluated and refused before `open_connection` | `test_proxy.py::TestResolutionOrder::test_a_denied_host_is_never_resolved` |
| DNS-tunnelled exfiltration does not leave the sandbox *(runtime)* | No resolver inside; the proxy resolves only allowed names | `dns-tunnelled-exfiltration` |
| A registry credential is never present in the sandbox *(runtime)* | The proxy attaches it upstream; the install holds nothing | `registry-token-theft-from-the-sandbox`, `TestCredentialBrokering::test_the_secret_is_nowhere_in_the_sandbox` |
| The broker refuses writes | Only GET and HEAD are forwarded | `test_credentials.py::TestBroker::test_writes_are_refused` |
| The credential store is refused if others can read it *(constrains blastgate)* | Mode is checked before the file is read | `TestStore::test_a_readable_store_is_refused_not_read` |
| A secret is never taken from the command line *(constrains blastgate)* | `blast creds add` reads stdin, because argv is visible in ps | `blastgate/cli.py` |
| Truncating an audit log is detected | Anchor records head hash and entry count | `test_audit.py::TestDisclosedLimits::test_truncating_the_tail_IS_detected_against_an_anchor` |
| Truncating a log written by a real run is detected *(runtime)* | Anchor written by the host runner after the sidecar stops | `test_end_to_end.py::TestAnchoring::test_truncating_the_log_after_a_run_is_detected` |
| Removing a whole run's anchor is detected | Anchors are chained across runs | `TestAnchorStore::test_removing_a_whole_run_breaks_the_anchor_chain` |
| The sandbox cannot see the anchor store *(runtime)* | Separate directory, mounted nowhere | `TestAnchoring::test_the_sandbox_cannot_see_the_anchor_store` |
| An anchor beside the audit log is refused *(constrains blastgate)* | That directory is mounted into the proxy, so the log's writer could forge its own anchor | `TestAnchoring::test_an_anchor_beside_the_audit_log_is_refused` |
| An unanchored log is not reported as verified *(constrains blastgate)* | `UNANCHORED` is a distinct verdict | `TestCliAudit::test_an_unanchored_log_does_not_report_as_verified` |
| The install phase never reaches a code forge *(runtime)* | Forge is absent from the install allowlist; deps come from a local mirror | `test_end_to_end.py::TestTwoPhaseResolution::test_the_install_phase_never_reaches_a_forge` |
| A forge request during install is denied and logged *(runtime)* | npm does try; the denial is recorded rather than absent | `TestTwoPhaseResolution::test_a_forge_request_during_install_is_denied_and_logged` |
| A project with a git dependency still installs *(runtime)* | Resolve phase plus local mirror | `TestTwoPhaseResolution::test_a_git_dependency_installs` |
| The resolve phase cannot reach the registry | Separate allowlist naming forges only | `TestTwoPhaseResolution::test_the_resolve_policy_cannot_reach_the_registry` |
| The git cache is read-only during install *(runtime)* | A writable cache would be a channel back into the phase with forge access | `TestTwoPhaseResolution::test_the_git_cache_is_read_only_in_the_install` |
| Git dependencies without the resolve flag refuse the run *(constrains blastgate)* | Fail closed rather than reach a forge | `TestTwoPhaseResolution::test_git_dependencies_without_the_flag_are_refused` |
| The crates.io registry source is not mistaken for a git dependency | Cargo.lock spells it as a GitHub URL | `test_resolve.py::TestCargoSources::test_the_crates_registry_is_not_a_git_dependency` |
| A pypi or cargo install reaches a forge only during resolution *(runtime)* | Same two-phase split as npm | `test_end_to_end.py::TestResolveAcrossEcosystems::test_cargo_reaches_the_forge_only_in_the_resolve_phase` |
| Every resolve-capable ecosystem has a parser, an allowlist and an image *(constrains blastgate)* | Listing one without them removes the grant and breaks installs | `TestEveryCapableEcosystemHasAParser` |
| A registry tarball URL is not mistaken for a git dependency | https URLs need `git+` or `.git` | `test_resolve.py::TestGitSpecParsing::test_dependencies_come_from_the_lockfile_too` |
| An unparseable manifest refuses the run *(constrains blastgate)* | Guessing the dependency set is worse than stopping | `test_resolve.py::TestGitSpecParsing::test_an_unparseable_manifest_refuses_rather_than_guesses` |
| A shell metacharacter in a manifest cannot escape the clone script | Arguments are shell-quoted independently of the parser's charset | `test_resolve.py::TestCloneScript::test_shell_metacharacters_cannot_escape_the_script` |
| A sidecar left by a killed run cannot serve the next one *(runtime)* | Networks are per-run, so a leftover is not on anyone else's | `TestStaleSidecar::test_a_stale_proxy_cannot_reach_another_runs_network` |
| Two projects install concurrently without interfering *(runtime)* | One internal network per run | `test_end_to_end.py::TestConcurrency::test_two_projects_install_at_the_same_time` |
| Concurrent runs against one project are refused *(constrains blastgate)* | Interleaved appends would break the audit chain | `TestConcurrency::test_the_same_project_twice_at_once_is_refused` |
| A killed run's sidecar is removed by the next run *(constrains blastgate)* | Containers carry the supervising pid | `TestRunLifecycle::test_a_sidecar_with_a_dead_supervisor_is_reaped` |
| A running install's sidecar is never reaped *(constrains blastgate)* | Liveness is checked before removal | `TestRunLifecycle::test_a_live_sidecar_is_never_reaped` |
| Run networks do not leak *(runtime)* | Removed in a finally block | `TestConcurrency::test_the_run_network_is_removed_afterwards` |
| The proxy image cannot enforce a stale allowlist *(constrains blastgate)* | Image tag is derived from the source and allowlist contents, so a policy change forces a rebuild | `TestProxyImageFreshness::test_changing_an_allowlist_changes_the_image_tag` |

Two deliberate properties worth stating because they surprise people:

- A suffix wildcard does **not** cover the apex. `*.npmjs.org` allows
  `registry.npmjs.org` but not `npmjs.org`; the apex must be listed explicitly.
- The policy engine is pure. No network, no subprocess, no filesystem access
  beyond reading the allowlist, no model calls, ever. Purity is what makes it
  exhaustively testable, and exhaustive testing is the product.

## 7. Designed but not implemented

These are the controls the argument in section 3 actually depends on. **None of
them exist yet.** Until each ships with a test in `tests/attacks/` that fails when
the control is removed, blastgate prevents nothing about a real install.

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
install, and the attack corpus executes against the real sandbox. `blast run`
works; a real `npm install` completes inside it with one allowed route out.

The corpus scores **11 of 13 (85%)**, across five kinds of check: egress through
the proxy, filesystem visibility inside the sandbox, a real install, the contents
of the resolve image, and host-side tampering with the audit log.

That number went *down* when the corpus grew, from 88% to 85%, and the drop is
the point. Nothing regressed. Two disclosed gaps are now counted against a
larger set: `exfil-via-registry-during-install`, because the registry must stay
reachable during an install and a registry accepts writes, and
`audit-replacement-is-detected`, because anchoring is not provenance. Both are
expected to succeed for the attacker and both are counted as failures.

Scenarios that cannot run are counted as failures too, and a malformed scenario
file is refused rather than skipped. The number is regenerated by
`scripts/attack_report.py`, and a test fails if the README stops matching it, so
it is not a number anyone here chose.

One scenario is weaker evidence than the rest and is marked as such:
`fetch-phase-runs-no-lifecycle-scripts` checks a precondition - that no package
manager or interpreter exists in the resolve image - rather than observing an
attack fail.

Section 8 has not shrunk. What is built works; what is listed there is a limit
on what this design attempts, and a corpus of eight scenarios is a small corpus.
The next honest step is more scenarios drawn from real write-ups rather than
constructed ones — every current scenario is marked `source: constructed`, and
that is a real weakness in the evidence.

Because none of the above exists, `blast run` refuses to execute rather than running
an install without an enforcement point. This is the fail-closed default from
section 8.3, applied to the tool's own incompleteness: a sandbox that is not
built and a container runtime that is unavailable are the same condition, and
both must refuse rather than degrade. The refusal is a property of blastgate, not
a protection against an attacker — it prevents a user from being misled into
relying on an enforcement point that does not exist. It stops nothing that a
malicious package does.

### 7.1 Where the controls live

Six modules, which is one more than the original plan allowed. The rule it
broke was "five source modules; if a sixth appears, something grew that should
not have", and something had grown: `runner.py` had reached 1,100 lines and was
doing two unrelated jobs.

The split follows purity, the same line that makes `policy.py` worth trusting.

| Module | Owns | Pure |
| --- | --- | --- |
| `policy.py` | The allow/deny decision | yes |
| `resolve.py` | What a project declares, and where fetched copies go | yes |
| `audit.py` | The decision log and its anchors | filesystem only |
| `proxy.py` | The enforcement point | network only |
| `runner.py` | Topology, containers, and what crosses the boundary | no |
| `cli.py` | Argument handling and exit codes | no |

`resolve.py` executes nothing and starts no process, so it is exhaustively
testable without a runtime — which matters because its mistakes are quiet ones.
A version range misread as a repository sends the resolve phase to a forge for
something that was never there. A repository misread as a version leaves the
install to find a forge that is deliberately unreachable, failing late and
confusingly. Neither shows up as a crash.

Fetching stays in `runner.py`, because fetching is topology.

## 8. What is NOT defended against

This section is longer than section 6 on purpose. Someone hostile should be able
to read it and not find a gap that was left undisclosed.

### 8.1 Structural limits of the design

- **Container escape.** Isolation depends entirely on the container runtime. A
  payload with a working escape reaches the host and every credential on it.
  Blastgate adds a layer; it does not add a guarantee.
- **Exfiltration through the registry.** Narrowed, not closed. The forge case is
  gone — see below — but the registry has to be reachable during an install,
  because that is what an install is, and any allowlisted host that accepts
  writes is a channel. Credential stripping is what reduces this: an anonymous
  payload has no publish token, and the environment filter is why. That is a
  mitigation. `exfil-via-registry-during-install` reproduces it and is counted
  as a failure in the published rate.
- **Exfiltration to a code forge is closed, and not by inspecting traffic.**
  There is still no TLS interception. The forge is simply not in the install
  phase's allowlist for any supported ecosystem: declared git dependencies are
  fetched by a separate resolve phase, while no package code is running, and
  served during the install from a read-only local mirror. There is no read to
  distinguish from a write because there is no connection. This introduces its
  own surface, listed in 8.3.
- **An ecosystem without a manifest parser would still be exposed.** Closing the
  gap requires reading what a project declares, which is manifest-specific. npm,
  pypi and cargo have parsers; anything added later does not until one is
  written for it. Such an ecosystem keeps the older, weaker arrangement — the
  forge reachable for the whole install — and `blast run` warns when that path is
  taken. Removing the grant without adding a parser does not close the gap, it
  only breaks every project with a git dependency, which is what it did briefly
  for pypi and cargo before the compatibility check caught it.
- **DNS-based exfiltration is closed, by ordering rather than by inspection.**
  This entry used to say the opposite. It was wrong, and writing a scenario from
  a real incident is what surfaced it. The install container has no resolver and
  no route to one, so nothing resolves inside the sandbox - not even the
  registry it is allowed to reach. Names are resolved by the proxy, taken from
  the CONNECT request, and only after policy has allowed the host: a denial is
  written and returned before `open_connection` is ever called. So no query for
  a denied name leaves the machine, which matters because a DNS tunnel needs no
  reply - the query itself carries the data. Asserted in
  `TestResolutionOrder::test_a_denied_host_is_never_resolved` and reproduced end
  to end by `dns-tunnelled-exfiltration`.
- **Compromised base image or package manager.** If the sandbox interior is
  already hostile, blastgate enforces nothing useful.
- **Post-install runtime, and build output.** Blastgate protects the install. It
  does not protect the application the install produces, and it does not notice
  a package that tampers with a build rather than exfiltrating from it.
  event-stream in 2018 is the documented example: the payload did not steal
  anything from the machine that installed it, it injected a wallet-stealing
  script into Copay's release build, and the theft happened later on end users'
  devices. Nothing in this design would have stopped that. The install was, from
  an egress point of view, entirely well-behaved.
- **Anything outside an install.** A malicious package that does nothing at
  install time and attacks in production is entirely out of scope.

### 8.4 Surface introduced by credential brokering

- **The proxy now holds a secret.** It was a chokepoint; it is now also a target
  worth attacking. The credential reaches it through a file mounted only into
  that container, because `docker inspect` prints both arguments and
  environment variables.
- **A payload can still make authenticated requests through the broker.** It
  cannot steal the token, use it elsewhere, or keep it after the run. It can
  fetch private packages during the install. Reads only: the broker refuses
  PUT, POST, DELETE and PATCH, so it cannot publish - which is the step that
  turned Shai-Hulud from a theft into a worm.
- **The sandbox talks plain HTTP to the broker.** That network has two members
  and no gateway, and the payload already sees the package bodies. What it must
  not see is the credential, and that is added on the upstream leg. No TLS is
  intercepted anywhere; the v1 rejection of interception stands.
- **Registry metadata is rewritten in flight.** Absolute URLs pointing at the
  upstream host are replaced so the client comes back to the broker. That is a
  transformation applied to a response body, and a registry that encodes URLs
  in some other form would not be rewritten and would fail rather than leak.
- **The store is a file, not an OS keychain.** Mode 0600, and refused if it is
  wider. That defends against the install, which is this project's threat. It
  does not defend against another process running as the same user on the host.
- **Only npm and pypi are wired for brokering.** cargo needs registry source
  replacement rather than an index URL, and is not done. An ecosystem with no
  entry gets no brokering rather than a setting that silently does nothing.
- **Untested against a real private registry.** The end-to-end test uses the
  public registry, which accepts any bearer token on a public read. It proves
  the credential never enters the sandbox; it does not prove Artifactory or
  Nexus accept the header shape.

### 8.3 Surface introduced by two-phase resolution

Closing the forge gap added components. They are smaller than what they replace,
and they are not nothing.

- **The resolve phase still touches a forge.** It runs `git` against an
  attacker-influenceable repository. No project code executes there, no
  credentials are present, and its egress is allowlisted and logged under the
  ecosystem's `*-resolve.yaml` — but git has had its own CVEs and this is a
  real, if much smaller, exposure.
- **cargo needs the git CLI to be enforced at all.** cargo fetches with libgit2,
  which ignores `url.insteadOf`. `CARGO_NET_GIT_FETCH_WITH_CLI` makes it shell
  out to git so the redirection applies. If that variable were ever dropped,
  cargo would quietly ignore the local mirror and dial the forge — where it
  would be denied, so the failure is loud rather than silent, but the dependency
  is worth naming.
- **Fetched repositories are untrusted data.** The cache holds bytes an attacker
  chose. It is mounted read-only into the install and must never be executed
  from.
- **A git dependency discovered only at install time fails the install.** The
  resolve phase fetches what the manifest and lockfile declare. Anything
  appearing later rewrites to a local path that does not exist and git fails
  locally rather than reaching out. Fail-closed, and a real false-positive risk
  against a near-zero budget.
- **Manifest parsing is new attack surface.** `package.json` and
  `package-lock.json` are parsed before any sandbox exists. An unparseable file
  refuses the run rather than being skipped, but the parser itself runs on the
  host.
- **ssh-form dependencies are fetched over https.** npm writes ssh URLs into
  lockfiles routinely. Blastgate rewrites them to https to fetch, because it has
  no key to authenticate with and https is the transport the proxy can enforce.
  A genuinely private repository therefore fails rather than being fetched.
- **Projects with git dependencies get a git binary in the install image.** A
  slightly larger interior than a project without them, added only when needed.

### 8.2 Limits of the policy engine as written

- **The policy engine still ignores ports.** `blast check npm registry.npmjs.org:8443`
  reports ALLOW, because normalization strips the port and the decision is made
  on hostname alone. The restriction to port 443 lives in the proxy, not in
  policy, so the two disagree when inspected separately. Treat `blast check` as
  answering "is this host allowed", never "is this destination reachable".
- **The project must live somewhere the runtime can see.** On macOS the
  container runtime runs inside a VM that shares only part of the host
  filesystem. A project outside a shared path cannot be mounted and the run
  fails. This is a usability constraint rather than a weakness, but it means the
  set of directories blastgate can protect is smaller than "any directory".
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
- **The false-positive budget is verified against a small sample.**
  `scripts/compat_check.py` installs each project twice, with and without
  blastgate, across npm, pypi and cargo, and currently finds no false positives.
  Read that as "none found", not as a rate. Both runs are retried the same
  number of times, because an unretried control silently excludes a project on a
  transient failure and makes the number look better by measuring less.
- **Compatibility currently depends on an ecosystem convention that could
  change.** The two hardest cases in that check, esbuild and sharp, were chosen
  because they historically downloaded binaries from GitHub releases during
  postinstall — traffic blastgate denies. Both now ship platform binaries as npm
  optional dependencies served from the registry, so they pass for reasons that
  have nothing to do with this design. If packages move back toward fetching
  binaries from arbitrary hosts at install time, the false-positive rate rises
  sharply and no code change here caused it.
- **Two installs against the same project cannot run at once.** Different
  projects run in parallel freely, each on its own internal network. The same
  project is refused, and the reason is the audit log rather than the network:
  appending reads and verifies the whole chain before writing a tail, so two
  writers interleave into a log that no longer verifies. The lock is `flock`, so
  a killed run releases it rather than wedging the next one.
- **An orphaned sidecar is reaped, not merely refused.** `--rm` does not fire
  when the supervising process is killed rather than allowed to exit, so
  containers record the pid that started them and a later run removes the ones
  whose supervisor is gone. A reused pid can leave a dead sidecar looking alive,
  which leaks a container; it cannot make a live one look dead, so reaping never
  drops another install's enforcement mid-flight.
- **Nothing binds an install to its declared ecosystem.** Running an `npm` install
  under the `pypi` allowlist is a user error the tool does not currently catch.
- **Unicode and IDN hostnames are rejected outright**, not punycode-normalized.
  This is fail-closed and may produce false negatives on legitimate
  internationalized hosts.
- **Audit truncation is detected only where an anchor exists.** The hash chain
  alone still cannot see it — a shorter chain verifies fine, asserted in
  `test_truncating_the_tail_is_not_detected_by_the_chain_alone`. What closes it
  is the anchor store, written after each run by the host-side runner rather
  than by the proxy that writes the log. A log with no anchor reports
  `UNANCHORED`, never `OK`, because "internally consistent" and "complete" are
  different claims and printing them identically would hide this limit.
- **The audit log proves consistency, not provenance.** Anchoring raises the bar
  from writing one file to writing two, in two directories, the second of which
  is chained across runs. It is not provenance. An attacker with write access to
  both stores forges both, asserted in
  `test_replacement_is_NOT_detected_if_both_stores_are_rewritten`. Closing this
  needs an anchor this machine cannot alter — an external service, a key held in
  an OS keychain, or an offline record — none of which blastgate has.
- **The environment filter is blind to values.** It decides by variable *name*
  only. A secret stored under a name like `BUILD_NUMBER` is not recognised as a
  secret, and would be forwarded if the user asked for it by name. Shape
  checking cannot close this and is not claimed to.
- **The environment is not the only route to a credential.** Filtering variables
  does nothing about credentials on disk — `~/.npmrc`, `~/.aws`, SSH keys. Those
  are addressed by the mount boundary, which is not built. Until it is, the
  environment filter protects against one of the two harvest routes and the more
  valuable one remains open.
- **`.blastgate.yaml` is trusted input, and it lives in the repository.** A
  project can add hosts to its own allowlist. It cannot disable the proxy, open
  a port, turn off anchoring, or override a denial made on other grounds -
  every unrecognised key is refused rather than ignored, and every added host
  needs a written reason. But a pull request that adds a host is a pull request
  that widens what every install in that repository can reach, including code
  from a package nobody read. It deserves the same review as a change to the
  shipped allowlists. Hosts added this way are tagged `[project]` in the audit
  log so their origin is never in doubt.
- **Allowlist trust.** The shipped allowlists are trusted input. A bad entry
  merged into this repository is a direct compromise of the control, which is why
  every entry carries a reason and allowlist changes are reviewed as security
  changes.

### 8.3 Explicit non-goals

- Blastgate does not detect malicious packages, score them, or tell you whether a
  version is safe. Other tools do that well. This one assumes the answer is "no"
  and contains the consequences.
- Blastgate does not intercept TLS by default and will not in v0. If interception
  is ever added it will be opt-in. A tool that decrypts a developer's traffic by
  default does not deserve trust.
- Blastgate never falls back to unsandboxed execution. If the container runtime is
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

Blastgate's claim at v1 is narrow and should be stated narrowly: **an install-time
payload cannot read host credentials it was never given, and cannot reach a
network destination that is not on a short reviewed list.** Everything above
remains true at the same time.

## 10. How to invalidate a claim in this document

- A protection claim without a passing test that fails when the control is removed
  must be moved to section 8.
- Any change to `blastgate/` that alters what the tool protects against updates this
  file in the same commit, or the change is refused.
- If a gap in section 8 is closed, it moves to section 6 with its test, and the
  README's status language is re-checked in the same commit.
