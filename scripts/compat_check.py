#!/usr/bin/env python3
"""Measure the false-positive rate against real projects.

This is v1's kill criterion, made measurable. The plan says: if two-phase
resolution cannot handle common real projects without frequent false positives,
stop. A tool that breaks legitimate installs is uninstalled within the hour.

Every project is installed twice. Once in a plain container with full network
access, which is the control, and once under bulkhead. Without the control a
failure means nothing: the project might simply be broken, or the network flaky,
and counting that against bulkhead would flatter it by hiding real breakage in
noise, or damn it for someone else's bug.

    control ok, bulkhead ok    -> compatible
    control ok, bulkhead fail  -> FALSE POSITIVE, the number that matters
    control fail               -> excluded, not bulkhead's failure to own

Denied hosts are reported for every run, because which host broke an install is
the thing that tells you whether the allowlist is wrong or the design is.

    python scripts/compat_check.py                 # everything
    python scripts/compat_check.py --only express  # one case
"""

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bulkhead.audit import AuditLog  # noqa: E402
from bulkhead.policy import load_policy  # noqa: E402
from bulkhead.resolve import parse_git_dependencies  # noqa: E402
from bulkhead.runner import (  # noqa: E402
    default_anchor_path,
    default_audit_path,
    detect_runtime,
    ensure_install_image,
    run_install,
)

NPM_IMAGE = "node:20-alpine"
INSTALL_CMD = ["npm", "install", "--no-audit", "--no-fund"]


@dataclass
class Case:
    name: str
    kind: str                      # "repo" or "manifest"
    repo: Optional[str] = None
    ref: Optional[str] = None      # release tag, never a moving branch
    manifest: Optional[dict] = None
    why: str = ""


# Real repositories, for messiness we did not design for, and synthetic
# manifests aimed at categories known to be hard. The synthetic ones are
# expected to fail; they are here to find where the boundary actually is
# rather than to pad the pass rate.
# Pinned to release tags, never to a branch. An earlier version cloned HEAD,
# which meant testing whatever state main happened to be in that morning:
# date-fns/main was mid-ERESOLVE-conflict and excluded itself from the
# measurement. A release tag is also what a developer actually installs.
CASES: List[Case] = [
    Case("express", "repo", repo="https://github.com/expressjs/express",
         ref="v5.2.1", why="classic mid-sized tree, pure JS"),
    Case("axios", "repo", repo="https://github.com/axios/axios",
         ref="v1.19.0", why="heavy devDependencies, build tooling"),
    Case("got", "repo", repo="https://github.com/sindresorhus/got",
         ref="v15.1.0", why="deep transitive tree"),
    Case("date-fns", "repo", repo="https://github.com/date-fns/date-fns",
         ref="v4.4.0", why="large package, many dev tools"),
    Case("prettier", "repo", repo="https://github.com/prettier/prettier",
         ref="3.9.6", why="large monorepo-ish build"),
    Case("binary-postinstall", "manifest",
         manifest={"dependencies": {"esbuild": "0.24.0"}},
         why="postinstall downloads a platform binary"),
    Case("native-build", "manifest",
         manifest={"dependencies": {"sharp": "0.33.5"}},
         why="native module, fetches prebuilt binaries"),
    Case("git-dependency", "manifest",
         manifest={"dependencies": {"is-odd": "github:jonschlinkert/is-odd#3.0.1"}},
         why="exercises two-phase resolution"),
    Case("deep-tree", "manifest",
         manifest={"dependencies": {"webpack": "5.95.0", "eslint": "9.13.0"}},
         why="wide and deep transitive graph"),
]


@dataclass
class Result:
    case: Case
    control_ok: bool = False
    control_detail: str = ""
    bulkhead_ok: bool = False
    bulkhead_detail: str = ""
    denied_hosts: List[str] = field(default_factory=list)
    commit: str = ""
    seconds: float = 0.0

    @property
    def verdict(self) -> str:
        if not self.control_ok:
            return "excluded"
        return "compatible" if self.bulkhead_ok else "FALSE POSITIVE"


def _run(argv, timeout):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def prepare(case: Case, workdir: Path) -> tuple:
    """Materialise the project. Returns (path, commit) or (None, reason)."""
    source = workdir / "source"
    source.mkdir(parents=True)
    if case.kind == "manifest":
        manifest = {"name": f"compat-{case.name}", "version": "1.0.0"}
        manifest.update(case.manifest or {})
        (source / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return source, "pinned in manifest"

    if not case.ref:
        return None, "no ref pinned; refusing to test a moving branch"
    result = _run(
        ["git", "clone", "--depth", "1", "--branch", case.ref, "--quiet",
         case.repo, str(source)],
        300,
    )
    if result.returncode != 0:
        return None, f"clone of {case.ref} failed: {result.stderr.strip()[-160:]}"
    revision = _run(["git", "-C", str(source), "rev-parse", "HEAD"], 60)
    commit = revision.stdout.strip()[:12] if revision.returncode == 0 else "?"
    shutil.rmtree(source / ".git", ignore_errors=True)
    return source, commit


def image_for(project: Path, runtime: str) -> str:
    """The image bulkhead would choose, used for the control too.

    The control has to differ from the test in exactly one variable: whether
    egress is restricted. An earlier version ran the control in plain
    node:20-alpine, which has no git, so every git-dependency project failed
    its control for a reason that had nothing to do with network policy and
    got excluded from the measurement it existed to provide.
    """
    if parse_git_dependencies(project):
        return ensure_install_image(runtime)
    return NPM_IMAGE


def control_install(project: Path, runtime: str, image: str, timeout: int = 900):
    """The same container with full network. What "working" looks like."""
    argv = [
        runtime, "run", "--rm", "--network", "bridge",
        "--mount", f"type=bind,source={project},target=/workspace",
        "-w", "/workspace", "--entrypoint", "npm",
        image, *INSTALL_CMD[1:],
    ]
    result = _run(argv, timeout)
    return result.returncode == 0, (result.stderr or result.stdout).strip()[-300:]


def bulkhead_install(project: Path, timeout: int = 900):
    audit = default_audit_path(project)
    anchors = default_anchor_path(project)
    for artefact in (audit, anchors):
        if artefact.exists():
            artefact.unlink()

    conditions = set()
    if parse_git_dependencies(project):
        conditions.add("git-dependencies")

    denied: List[str] = []
    try:
        result = run_install(
            policy=load_policy("npm"), command=INSTALL_CMD, project_dir=project,
            audit_path=audit, enabled_conditions=conditions, host_env={},
            timeout=timeout,
        )
        ok = result.exit_code == 0
        detail = (result.stderr or result.stdout).strip()[-300:]
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"[-300:]

    if audit.exists():
        seen = []
        for entry in AuditLog(audit).read_all():
            if not entry.allowed and entry.host not in seen:
                seen.append(entry.host)
        denied = seen
    return ok, detail, denied


def run_case(case: Case, runtime: str) -> Result:
    result = Result(case=case)
    started = time.time()
    workdir = Path(tempfile.mkdtemp(dir=Path.home() / ".bulkhead-tests"))
    try:
        source, commit = prepare(case, workdir)
        if source is None:
            result.control_detail = commit
            return result
        result.commit = commit

        control_dir = workdir / "control"
        shutil.copytree(source, control_dir)
        image = image_for(control_dir, runtime)
        result.control_ok, result.control_detail = control_install(control_dir, runtime, image)
        shutil.rmtree(control_dir, ignore_errors=True)
        if not result.control_ok:
            return result

        test_dir = workdir / "bulkhead"
        shutil.copytree(source, test_dir)
        result.bulkhead_ok, result.bulkhead_detail, result.denied_hosts = bulkhead_install(test_dir)
        return result
    finally:
        result.seconds = time.time() - started
        shutil.rmtree(workdir, ignore_errors=True)


def render(results: List[Result]) -> str:
    considered = [r for r in results if r.control_ok]
    failures = [r for r in considered if not r.bulkhead_ok]
    excluded = [r for r in results if not r.control_ok]

    rate = (len(failures) / len(considered) * 100) if considered else 0.0
    lines = [
        f"**{len(considered) - len(failures)} of {len(considered)} real projects "
        f"install unchanged under bulkhead. False positive rate: {rate:.0f}%.**",
        "",
        "| Project | Pinned at | Why it is here | Verdict | Denied hosts |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in results:
        hosts = ", ".join(f"`{h}`" for h in r.denied_hosts[:4]) or "—"
        pin = f"`{r.case.ref}`" if r.case.ref else "version-pinned"
        lines.append(
            f"| `{r.case.name}` | {pin} | {r.case.why} | {r.verdict} | {hosts} |"
        )
    if excluded:
        lines += ["", "Excluded because the control install also failed, so the"
                  " failure is not bulkhead's:"]
        for r in excluded:
            lines.append(f"- `{r.case.name}`: {r.control_detail[-160:]}")
    if failures:
        lines += ["", "False positives, in full:"]
        for r in failures:
            lines.append(f"- `{r.case.name}`: {r.bulkhead_detail[-300:]}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    runtime = detect_runtime()
    (Path.home() / ".bulkhead-tests").mkdir(parents=True, exist_ok=True)
    cases = [c for c in CASES if not args.only or c.name in args.only]

    results = []
    for case in cases:
        print(f"[{case.name}] running...", flush=True)
        result = run_case(case, runtime)
        print(f"[{case.name}] {result.verdict} ({result.seconds:.0f}s)", flush=True)
        results.append(result)

    report = render(results)
    print("\n" + report)
    if args.out:
        args.out.write_text(report + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
