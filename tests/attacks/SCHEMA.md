# Attack scenario format

One scenario per file. A scenario is a claim about what bulkhead does when a
payload tries something specific, written so it can be executed rather than
asserted.

```yaml
id: short-kebab-case-identifier
title: One line, what the payload is attempting
chain_link: 4              # which link of the attack chain (threat model §2)
ecosystem: npm             # npm | pypi | cargo
source: https://...        # public write-up, or "constructed" if synthetic

expect: denied             # denied | allowed | not_prevented
requires: policy           # policy | proxy | sandbox

target:                    # for egress scenarios
  host: exfil.attacker.test
  port: 443

note: >
  Why this scenario exists and what it proves.
```

## `expect`

- **`denied`** — bulkhead must refuse this. A scenario that stops being denied is
  a regression.
- **`allowed`** — legitimate traffic that must keep working. These guard the
  false-positive budget, which is near zero.
- **`not_prevented`** — a disclosed gap from threat model §8, written down as an
  executable fact. These are expected to succeed for the attacker. They exist so
  a gap cannot be quietly believed closed, and so the published pass rate counts
  them honestly instead of omitting them.

## `requires`

What has to exist for the scenario to run. Scenarios requiring a component that
is not built are reported as *not yet runnable* and counted against the pass
rate rather than skipped silently. The number in the README is meant to be one
nobody chose.
