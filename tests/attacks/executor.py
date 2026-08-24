"""Runs the attack corpus against the real sandbox and scores it.

Scoring is deliberately unflattering. Three of the six outcomes count against
the published number, including the one for a gap this project disclosed itself.
A corpus that only counts the scenarios it wins is a press release.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence
import json
import shlex
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


def _scratch_project() -> Path:
    base = Path.home() / ".bulkhead-tests"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(dir=base))


def _run_install_scenario(scenario: Scenario) -> Outcome:
    """Run a real install and see whether it worked.

    The false-positive guard. Closing a gap by breaking the feature it belonged
    to is not closing it, and this is the scenario most likely to catch that.
    """
    from bulkhead.runner import default_anchor_path

    project = _scratch_project()
    manifest = {"name": "corpus-demo", "version": "1.0.0"}
    manifest.update(scenario.manifest or {})
    (project / "package.json").write_text(json.dumps(manifest) + "\n")

    audit = default_audit_path(project)
    anchors = default_anchor_path(project)
    try:
        result = run_install(
            policy=load_policy(scenario.ecosystem),
            command=list(scenario.command),
            project_dir=project,
            audit_path=audit,
            enabled_conditions=set(scenario.enable),
            host_env={},
            timeout=900,
        )
        missing = [p for p in scenario.expect_present if not (project / p).exists()]
        worked = result.exit_code == 0 and not missing
        if worked:
            detail = "install succeeded"
        elif missing:
            detail = f"exit {result.exit_code}, missing: {', '.join(missing)}"
        else:
            detail = f"exit {result.exit_code}: {result.stderr.strip()[-200:]}"
        return _classify(scenario, worked, detail)
    except Exception as e:
        return _classify(scenario, False, f"{type(e).__name__}: {e}")
    finally:
        shutil.rmtree(project, ignore_errors=True)
        for artefact in (audit, anchors):
            if artefact.exists():
                artefact.unlink()


def _run_image_scenario(scenario: Scenario) -> Outcome:
    """Check what is present inside an image.

    Weaker evidence than observing an attack fail, and honest about that: it
    tests a precondition rather than an outcome. A lifecycle script cannot run
    where nothing exists to run it.
    """
    from bulkhead.runner import INTERNAL_NETWORK, ensure_networks, run_sandboxed

    runtime = detect_runtime()
    ensure_networks(runtime)
    project = _scratch_project()
    checks = " ".join(
        f'[ -e {shlex.quote(p)} ] && echo PRESENT {shlex.quote(p)};' for p in scenario.absent
    )
    try:
        result = run_sandboxed(
            ["-c", f"{checks} echo PROBE_DONE"],
            project, scenario.image, runtime=runtime,
            network=INTERNAL_NETWORK, entrypoint="sh", timeout=180,
        )
        if "PROBE_DONE" not in result.stdout:
            return Outcome(scenario, NOT_RUNNABLE, result.stderr.strip()[-200:] or "probe did not run")
        present = [
            line.split(" ", 1)[1] for line in result.stdout.splitlines()
            if line.startswith("PRESENT ")
        ]
        detail = "none present" if not present else f"present: {', '.join(present)}"
        return _classify(scenario, bool(present), detail)
    finally:
        shutil.rmtree(project, ignore_errors=True)


def _run_audit_scenario(scenario: Scenario) -> Outcome:
    """Tamper with an audit log on the host and see whether it is caught.

    No container involved. The attacker here is someone with write access to
    the log after a run, which is what the anchor store exists to detect.
    """
    from bulkhead.audit import AnchorStore, AuditLog, TamperError

    directory = Path(tempfile.mkdtemp())
    try:
        log = AuditLog(directory / "audit.log")
        for host in ("registry.npmjs.org", "a.attacker.test", "b.attacker.test"):
            log.append(scenario.ecosystem, host, host.endswith("npmjs.org"), None, "corpus")
        store = AnchorStore(directory / "anchors")

        if scenario.tamper == "truncate":
            anchor = store.append("run-1", log.path, log.read_all())
            lines = log.path.read_text().splitlines()
            log.path.write_text("\n".join(lines[:-1]) + "\n")
        elif scenario.tamper == "replace-both-stores":
            # The attacker rewrites the log AND anchors it themselves, which is
            # what anchoring does not defend against.
            forged = AuditLog(directory / "forged.log")
            for _ in range(3):
                forged.append(scenario.ecosystem, "registry.npmjs.org", True, "exact", "innocent")
            log.path.write_text(forged.path.read_text())
            anchor = store.append("run-1", log.path, log.read_all())
        else:
            return Outcome(scenario, NOT_RUNNABLE, f"unknown tamper {scenario.tamper!r}")

        try:
            AuditLog(log.path).verify_against_anchor(anchor)
            return _classify(scenario, True, "tampering was NOT detected")
        except TamperError as e:
            return _classify(scenario, False, f"detected: {str(e)[:90]}")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


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

    runners = {
        "install": _run_install_scenario,
        "image": _run_image_scenario,
        "audit": _run_audit_scenario,
    }
    for scenario in scenarios:
        if scenario.check in runners:
            try:
                outcomes.append(runners[scenario.check](scenario))
            except Exception as e:
                outcomes.append(Outcome(scenario, NOT_RUNNABLE, f"{type(e).__name__}: {e}"))

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
