"""Runs the attack corpus against the real sandbox and scores it.

Scoring is deliberately unflattering. Three of the six outcomes count against
the published number, including the one for a gap this project disclosed itself.
A corpus that only counts the scenarios it wins is a press release.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence
import json
import shutil
import tempfile

from bulkhead.policy import load_policy
from bulkhead.runner import (
    PROXY_ALIAS,
    PROXY_PORT,
    RunnerError,
    default_audit_path,
    detect_runtime,
    run_install,
)

from .corpus import Scenario, load_corpus

PROBE_IMAGE = "python:3.12-alpine"
MARKER = "BULKHEAD_RESULT "

# Outcomes. Only PREVENTED and EXPECTED_ALLOWED count as passes.
PREVENTED = "prevented"           # denied scenario was blocked
EXPECTED_ALLOWED = "allowed"      # allowed scenario worked
REGRESSION = "regression"         # denied scenario got through
FALSE_POSITIVE = "false-positive" # allowed scenario was blocked
KNOWN_GAP = "known-gap"           # disclosed gap, still open, still counted
GAP_CLOSED = "gap-closed"         # disclosed gap no longer reproduces
NOT_RUNNABLE = "not-runnable"     # a component the scenario needs is missing
ERROR = "error"

PASSING = frozenset({PREVENTED, EXPECTED_ALLOWED, GAP_CLOSED})


@dataclass(frozen=True)
class Outcome:
    scenario: Scenario
    status: str
    detail: str

    @property
    def passed(self) -> bool:
        return self.status in PASSING


EGRESS_PROBE = r"""
import json, socket, sys
targets = json.loads(sys.argv[1])
out = {}
for t in targets:
    try:
        s = socket.create_connection((%(alias)r, %(port)d), timeout=10)
        req = "CONNECT %%s:%%d HTTP/1.1\r\nHost: %%s\r\n\r\n" %% (t["host"], t["port"], t["host"])
        s.sendall(req.encode())
        line = b""
        while not line.endswith(b"\r\n") and len(line) < 200:
            ch = s.recv(1)
            if not ch:
                break
            line += ch
        out[t["id"]] = line.decode("latin-1").strip() or "NO RESPONSE"
        s.close()
    except Exception as e:
        out[t["id"]] = "ERROR " + type(e).__name__
print(%(marker)r + json.dumps(out))
""" % {"alias": PROXY_ALIAS, "port": PROXY_PORT, "marker": MARKER}

FILESYSTEM_PROBE = r"""
import json, os, sys
paths = json.loads(sys.argv[1])
print(%(marker)r + json.dumps({p: os.path.exists(p) for p in paths}))
""" % {"marker": MARKER}


def _parse_marker(stdout: str) -> Optional[dict]:
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER):])
    return None


def _run_probe(script: str, argument: str, ecosystem: str, enable: Sequence[str]) -> dict:
    runtime = detect_runtime()
    base = Path.home() / ".bulkhead-tests"
    base.mkdir(parents=True, exist_ok=True)
    project = Path(tempfile.mkdtemp(dir=base))
    audit = default_audit_path(project)
    try:
        result = run_install(
            policy=load_policy(ecosystem),
            command=["python", "-c", script, argument],
            project_dir=project,
            image=PROBE_IMAGE,
            audit_path=audit,
            enabled_conditions=set(enable),
            runtime=runtime,
            host_env={},
            timeout=180,
        )
        parsed = _parse_marker(result.stdout)
        if parsed is None:
            raise RunnerError(
                f"probe produced no result. stdout={result.stdout[-400:]!r} "
                f"stderr={result.stderr[-400:]!r}"
            )
        return parsed
    finally:
        shutil.rmtree(project, ignore_errors=True)
        if audit.exists():
            audit.unlink()


def _classify(scenario: Scenario, reached: bool, detail: str) -> Outcome:
    if scenario.expect == "denied":
        status = REGRESSION if reached else PREVENTED
    elif scenario.expect == "allowed":
        status = EXPECTED_ALLOWED if reached else FALSE_POSITIVE
    else:  # not_prevented
        # Reaching the target is what this scenario asserts. It is not a
        # surprise and it is not a pass.
        status = KNOWN_GAP if reached else GAP_CLOSED
    return Outcome(scenario, status, detail)


def run_corpus(scenarios: Optional[List[Scenario]] = None) -> List[Outcome]:
    scenarios = scenarios if scenarios is not None else load_corpus()
    outcomes: List[Outcome] = []

    egress = [s for s in scenarios if s.check == "egress"]
    filesystem = [s for s in scenarios if s.check == "filesystem"]

    # Group by the policy configuration they need, so scenarios sharing one
    # configuration share a single sandbox rather than paying for their own.
    groups: Dict[tuple, List[Scenario]] = {}
    for scenario in egress:
        groups.setdefault((scenario.ecosystem, tuple(sorted(scenario.enable))), []).append(scenario)

    for (ecosystem, enable), group in groups.items():
        targets = [
            {"id": s.id, "host": s.target.host, "port": s.target.port} for s in group
        ]
        try:
            results = _run_probe(EGRESS_PROBE, json.dumps(targets), ecosystem, enable)
        except (RunnerError, Exception) as e:
            for scenario in group:
                outcomes.append(Outcome(scenario, NOT_RUNNABLE, str(e)))
            continue

        for scenario in group:
            line = results.get(scenario.id, "MISSING")
            reached = line.startswith("HTTP/1.1 200")
            outcomes.append(_classify(scenario, reached, line))

    for scenario in filesystem:
        try:
            results = _run_probe(
                FILESYSTEM_PROBE, json.dumps(list(scenario.paths)),
                scenario.ecosystem, scenario.enable,
            )
        except Exception as e:
            outcomes.append(Outcome(scenario, NOT_RUNNABLE, str(e)))
            continue
        visible = sorted(p for p, exists in results.items() if exists)
        detail = "none of the paths resolve" if not visible else f"visible: {', '.join(visible)}"
        outcomes.append(_classify(scenario, bool(visible), detail))

    order = {s.id: i for i, s in enumerate(scenarios)}
    return sorted(outcomes, key=lambda o: order[o.scenario.id])


@dataclass(frozen=True)
class Report:
    outcomes: List[Outcome]

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0

    def by_status(self, status: str) -> List[Outcome]:
        return [o for o in self.outcomes if o.status == status]

    def to_markdown(self) -> str:
        lines = [
            f"**{self.passed} of {self.total} scenarios prevented "
            f"({self.rate:.0f}%).**",
            "",
            "| Scenario | Link | Expected | Result |",
            "| --- | --- | --- | --- |",
        ]
        for o in self.outcomes:
            mark = "" if o.passed else " ⚠"
            lines.append(
                f"| `{o.scenario.id}` | {o.scenario.chain_link} | "
                f"{o.scenario.expect} | {o.status}{mark} |"
            )
        gaps = self.by_status(KNOWN_GAP)
        if gaps:
            lines += ["", "Counted as failures because they are:"]
            for o in gaps:
                lines.append(f"- `{o.scenario.id}` — {o.scenario.title}")
        return "\n".join(lines)
