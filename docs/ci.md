# Running blastgate in CI

CI is where an install-time compromise does the most damage, and the one place
where nobody objects to a slow, isolated build step.

## The short version

```yaml
- uses: Arjunsilwal/blastgate@v0.1.0
  with:
    ecosystem: npm
    command: npm ci
```

That installs blastgate, runs `npm ci` in a sandbox with no credentials and no
egress except the npm allowlist, writes a JSON summary, and fails the step if
anything reached for a host the allowlist does not name.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The install succeeded and nothing unexpected was attempted |
| 1 | The install itself failed, as it would have anyway |
| 2 | Blastgate refused to run: no runtime, a bad audit path, a sidecar that would not start |
| 3 | The install **succeeded**, and something reached for a host the allowlist does not name |

Code 3 is the one worth wiring a gate to. An install can complete perfectly
while a payload tries to exfiltrate and is refused, and without a distinct code
that is invisible to a pipeline.

## Why not fail on every denial

Because a gate that cries wolf gets switched off.

Installs probe hosts routinely and carry on when refused. An npm install with a
git dependency reaches for `codeload.github.com`, is denied because the forge is
deliberately unreachable during the install phase, and completes from the local
mirror. That denial is correct behaviour, and failing a build on it would train
everyone to pass `--no-verify` at the first opportunity.

So denials are split by whether the allowlist names the host at all:

- **Named and refused** — a normal part of how that ecosystem behaves. Recorded,
  not escalated.
- **Not named anywhere** — nobody has ever listed this host for this ecosystem.
  That is the signal.

```
denied: [('codeload.github.com', 'known')]     -> exit 0
denied: [('exfil.attacker.test', 'UNKNOWN')]   -> exit 3
```

## The summary

`--json PATH` writes a machine-readable record. `-` writes to stdout, but a file
is the default so the install's own output stays usable.

```json
{
  "schema": "blastgate.run/1",
  "ecosystem": "npm",
  "install_ok": true,
  "decisions": {"total": 14, "allowed": 13, "denied": 1},
  "denied": [
    {"host": "codeload.github.com", "known_to_allowlist": true, "reason": "..."}
  ],
  "unexpected_egress": []
}
```

## Keeping the audit log

The log is the record of what the install tried to reach. It is worth keeping
as a build artefact, especially for the runs that did not fail.

```yaml
- uses: Arjunsilwal/blastgate@v0.1.0
  id: install
  with:
    ecosystem: npm
    command: npm ci

- name: Keep the egress record
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: blastgate-audit
    path: |
      blastgate-summary.json
      ${{ steps.install.outputs.audit-log }}
```

`if: always()` matters. The run you most want the log from is the one that
failed.

Verify a stored log later with `blast audit <path>`. Note that the anchor
lives on the machine that ran the install, so a log pulled from an artefact
verifies as `UNANCHORED`: its chain is intact, but truncation cannot be ruled
out. Treat an artefact as a record of what happened, not as proof that nothing
was removed from it.

## Private registries

The token never enters the sandbox.

```yaml
- name: Store the registry credential
  shell: bash
  env:
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
  run: echo -n "$NPM_TOKEN" | blast creds add registry.internal.example.com

- uses: Arjunsilwal/blastgate@v0.1.0
  with:
    ecosystem: npm
    command: npm ci
```

The secret is read from stdin rather than an argument, because arguments are
visible in `ps` and in some CI logs. See the credential brokering section of the
README for what this does and does not protect.

## What this does not do

- It does not tell you whether a package is malicious. It constrains what one
  can reach if it is.
- It does not protect the application after install. See threat model section 8.
- Concurrent jobs are fine; two jobs installing the **same project directory**
  at once are refused, because they would interleave one audit log.
