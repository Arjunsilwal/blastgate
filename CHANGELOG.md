# Changelog

Notable changes per release. Security-relevant entries say what they change
about the threat model, because that is the part worth reading.

## Unreleased

## 0.1.0 — 2026-08-26

First tagged version. Pre-alpha: every control is built and demonstrated
against running containers, and section 8 of the threat model is longer than
section 6 on purpose.

### Added
- **Credential brokering.** `blast creds` stores a registry credential on the
  host; the proxy attaches it to upstream requests so the install never holds
  it. Reads only, so a payload cannot publish through the broker. npm and pypi.
- **Project configuration and a shim.** `blast npm ci` as shorthand, and a
  `.blastgate.yaml` that can add hosts to a project's allowlist and nothing
  else. A denial now prints the exact entry to add, and what adding it costs.
- **CI integration.** A composite GitHub Action, a JSON run summary, and exit
  code 3 for "the install succeeded but reached for a host nobody listed".
  Denials of hosts the allowlist names are recorded rather than escalated, so
  the gate does not fire on ordinary install behaviour.
- Concurrent runs. Each run gets its own internal network, so installs against
  different projects no longer collide. Previously the second run was refused.
- Orphaned sidecars are reaped. Containers record the pid that started them, so
  a run cancelled with Ctrl-C no longer leaves a container behind.
- Per-project lock. Two runs against one project are refused, because both
  would append to a single audit log and interleave its hash chain.
- Attack corpus sourced from documented incidents (Shai-Hulud, torchtriton),
  and a `dns` check type that reproduces DNS tunnelling.
- Resolve phase for pypi and cargo, closing the code-forge exfiltration gap for
  those ecosystems as it was already closed for npm.
- `scripts/compat_check.py`, which measures the false-positive rate against
  real projects by installing each one with and without blastgate.

### Fixed
- **Wheels were unusable.** The built distribution contained the Python modules
  and none of the allowlists or Dockerfiles, so an installed copy imported
  cleanly and failed on the first command. Both now ship inside the package.
- The proxy image had a fixed tag and went stale, which meant the sidecar could
  keep enforcing an allowlist that no longer matched the files on disk.
- Registry tarball URLs in lockfiles were parsed as git dependencies, which
  would have broken every project with a lockfile.
- `--allow git-dependencies` silently granted nothing for pypi and cargo.

### Changed
- Renamed from `bulkhead` to `blastgate`. The CLI is `blast`.
- Threat model 8.1 no longer claims DNS-based exfiltration is unblocked. It is
  blocked, by the proxy resolving only after policy allows a host.
