#!/usr/bin/env python3
"""Measure the false-positive rate against real projects.

This is v1's kill criterion, made measurable. The plan says: if two-phase
resolution cannot handle common real projects without frequent false positives,
stop. A tool that breaks legitimate installs is uninstalled within the hour.

Every project is installed twice. Once in a plain container with full network
access, which is the control, and once under blastgate. Without the control a
failure means nothing: the project might simply be broken, or the network flaky,
and counting that against blastgate would flatter it by hiding real breakage in
noise, or damn it for someone else's bug.

    control ok, blastgate ok    -> compatible
    control ok, blastgate fail  -> FALSE POSITIVE, the number that matters
    control fail               -> excluded, not blastgate's failure to own

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

from blastgate.audit import AuditLog  # noqa: E402
from blastgate.policy import load_policy  # noqa: E402
from blastgate.resolve import parse_git_dependencies  # noqa: E402
from blastgate.runner import (  # noqa: E402
    default_anchor_path,
    default_audit_path,
    detect_runtime,
    ensure_install_image,
    run_install,
)

NPM_IMAGE = "node:20-alpine"

# One entry per ecosystem: the image blastgate would pick, and the command that
# means "fetch this project's dependencies". For cargo that is `fetch` rather
# than `build`: compiling is not what egress policy governs, and building would
# measure the compiler instead.
ECOSYSTEMS = {
    "npm": {
        "image": "node:20-alpine",
        "command": ["npm", "install", "--no-audit", "--no-fund"],
        "manifest_name": "package.json",
    },
    "pypi": {
        "image": "python:3.12-alpine",
        "command": ["pip", "install", "--no-cache-dir", "--root-user-action=ignore",
                    "-r", "requirements.txt"],
        "manifest_name": "requirements.txt",
    },
    "cargo": {
        "image": "rust:1-alpine",
        "command": ["cargo", "fetch"],
        "manifest_name": "Cargo.toml",
    },
}


@dataclass
class Case:
    name: str
    kind: str                      # "repo" or "manifest"
    ecosystem: str = "npm"
    repo: Optional[str] = None
    ref: Optional[str] = None      # release tag, never a moving branch
    manifest: Optional[dict] = None   # npm: package.json fields
    files: Optional[Dict[str, str]] = None  # any ecosystem: literal files
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

    # pypi
    Case("pypi-pure", "manifest", ecosystem="pypi",
         files={"requirements.txt": "requests==2.32.3\nclick==8.1.7\n"},
         why="pure-python wheels from the index"),
    Case("pypi-binary-wheels", "manifest", ecosystem="pypi",
         files={"requirements.txt": "cryptography==43.0.3\n"},
         why="compiled wheel, large binary artefact"),
    Case("pypi-build-isolation", "manifest", ecosystem="pypi",
         files={"requirements.txt": "pendulum==3.0.0\n"},
         why="build isolation fetches its own build backend"),
    Case("pypi-deep-tree", "manifest", ecosystem="pypi",
         files={"requirements.txt": "fastapi==0.115.4\nuvicorn==0.32.0\n"},
         why="wide transitive graph"),

    # cargo
    Case("cargo-simple", "manifest", ecosystem="cargo",
         files={"Cargo.toml": '[package]\nname = "compat"\nversion = "0.1.0"\n'
                              'edition = "2021"\n\n[dependencies]\n'
                              'serde = "1.0"\nserde_json = "1.0"\n',
                "src/main.rs": "fn main() {}\n"},
         why="sparse index plus crate downloads"),
    Case("cargo-deep-tree", "manifest", ecosystem="cargo",
         files={"Cargo.toml": '[package]\nname = "compat"\nversion = "0.1.0"\n'
                              'edition = "2021"\n\n[dependencies]\n'
                              'tokio = { version = "1", features = ["full"] }\n'
                              'clap = { version = "4", features = ["derive"] }\n',
                "src/main.rs": "fn main() {}\n"},
         why="hundreds of transitive crates"),
    Case("pypi-git-dependency", "manifest", ecosystem="pypi",
         files={"requirements.txt":
                "git+https://github.com/psf/requests@v2.32.3#egg=requests\n"},
         why="git dependency via the resolve phase"),
    Case("cargo-git-dependency", "manifest", ecosystem="cargo",
         files={"Cargo.toml": '[package]\nname = "compat"\nversion = "0.1.0"\n'
                              'edition = "2021"\n\n[dependencies]\n'
                              'anyhow = { git = "https://github.com/dtolnay/anyhow", '
                              'tag = "1.0.93" }\n',
                "src/main.rs": "fn main() {}\n"},
         why="git dependency via the resolve phase"),
]


@dataclass
class Result:
    case: Case
    control_ok: bool = False
    control_detail: str = ""
    control_attempts: int = 1
    blastgate_ok: bool = False
    blastgate_detail: str = ""
    blastgate_attempts: int = 1
    denied_hosts: List[str] = field(default_factory=list)
    commit: str = ""
    seconds: float = 0.0

    @property
    def verdict(self) -> str:
        if not self.control_ok:
            return "excluded"
        return "compatible" if self.blastgate_ok else "FALSE POSITIVE"


def _run(argv, timeout):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def prepare(case: Case, workdir: Path) -> tuple:
    """Materialise the project. Returns (path, commit) or (None, reason)."""
    source = workdir / "source"
    source.mkdir(parents=True)
    if case.kind == "manifest":
        if case.files:
            for name, content in case.files.items():
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
        else:
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


def image_for(project: Path, runtime: str, ecosystem: str = "npm") -> str:
    """The image blastgate would choose, used for the control too.

    The control has to differ from the test in exactly one variable: whether
    egress is restricted. An earlier version ran the control in plain
    node:20-alpine, which has no git, so every git-dependency project failed
    its control for a reason that had nothing to do with network policy and
    got excluded from the measurement it existed to provide.
    """
    if parse_git_dependencies(project, ecosystem):
        return ensure_install_image(runtime, ecosystem)
    return ECOSYSTEMS[ecosystem]["image"]


ATTEMPTS = 3

# Failures that cannot change between attempts. Matched against the complete
# output rather than the tail that gets reported.
DETERMINISTIC = ("ERESOLVE", "Conflicting peer dependency", "no matching version")


def is_deterministic(output: str) -> bool:
    return any(marker in output for marker in DETERMINISTIC)


NOISE = ("npm notice", "A complete log", "For a full report", "npm warn",
         "To update run", "Changelog:", "npm error A complete")


def summarise(output: str, limit: int = 240) -> str:
    """The lines that say why it failed, not the last few lines printed.

    An exclusion is only trustworthy if a reader can check it. Reporting the
    tail of npm's output gave "To update run: npm install -g npm@12.0.2" as the
    reason date-fns was excluded, which tells nobody anything.
    """
    interesting = [
        line.strip() for line in output.splitlines()
        if line.strip()
        and any(marker in line for marker in ("error", "Error", "ERROR", "fatal"))
        and not any(marker in line for marker in NOISE)
    ]
    if not interesting:
        interesting = [line.strip() for line in output.splitlines() if line.strip()]
    text = " | ".join(dict.fromkeys(interesting))
    return text[:limit]


def control_install(project: Path, runtime: str, image: str, command: List[str],
                    timeout: int = 900):
    """The same container with full network. What "working" looks like.

    Retried, because a control that flakes is worse than one that fails. A
    transient registry hiccup would otherwise exclude the project, silently
    shrinking the denominator and making the false positive rate look better by
    testing fewer things. Observed: `got` excluded itself on one run and
    installed fine on the next two.

    The blastgate run is retried the same number of times, so neither side gets
    an advantage, and the attempt count is reported either way.
    """
    argv = [
        runtime, "run", "--rm", "--network", "bridge",
        "--mount", f"type=bind,source={project},target=/workspace",
        "-w", "/workspace", "--entrypoint", command[0],
        image, *command[1:],
    ]
    detail = ""
    for attempt in range(1, ATTEMPTS + 1):
        result = _run(argv, timeout)
        if result.returncode == 0:
            return True, "", attempt
        full = (result.stderr or "") + (result.stdout or "")
        detail = summarise(full)
        # A dependency conflict is deterministic; retrying only wastes minutes.
        # Checked against the whole output, not the truncated tail: npm prints
        # the conflict well before the end, so matching on the tail never fired
        # and date-fns was retried three times for a failure that could not
        # change.
        if is_deterministic(full):
            return False, detail, attempt
    return False, detail, ATTEMPTS


def blastgate_install(project: Path, ecosystem: str = "npm", timeout: int = 900):
    audit = default_audit_path(project)
    anchors = default_anchor_path(project)
    for artefact in (audit, anchors):
        if artefact.exists():
            artefact.unlink()

    # Ask for whatever the project needs. For npm that starts the resolve
    # phase; for the others it is the old conditional grant.
    conditions = {"git-dependencies"}

    denied: List[str] = []
    ok, detail, attempts = False, "", ATTEMPTS
    for attempt in range(1, ATTEMPTS + 1):
        try:
            result = run_install(
                policy=load_policy(ecosystem),
                command=ECOSYSTEMS[ecosystem]["command"], project_dir=project,
                audit_path=audit, enabled_conditions=conditions, host_env={},
                timeout=timeout,
            )
            ok = result.exit_code == 0
            full = (result.stderr or "") + (result.stdout or "")
            detail = "" if ok else summarise(full)
        except Exception as e:
            ok, full = False, f"{type(e).__name__}: {e}"
            detail = summarise(full)
        if ok or is_deterministic(full):
            attempts = attempt
            break

    if audit.exists():
        seen = []
        for entry in AuditLog(audit).read_all():
            if not entry.allowed and entry.host not in seen:
                seen.append(entry.host)
        denied = seen
    return ok, detail, denied, attempts


def run_case(case: Case, runtime: str) -> Result:
    result = Result(case=case)
    started = time.time()
    workdir = Path(tempfile.mkdtemp(dir=Path.home() / ".blastgate-tests"))
    try:
        source, commit = prepare(case, workdir)
        if source is None:
            result.control_detail = commit
            return result
        result.commit = commit

        control_dir = workdir / "control"
        shutil.copytree(source, control_dir)
        image = image_for(control_dir, runtime, case.ecosystem)
        (result.control_ok, result.control_detail,
         result.control_attempts) = control_install(
            control_dir, runtime, image, ECOSYSTEMS[case.ecosystem]["command"]
        )
        shutil.rmtree(control_dir, ignore_errors=True)
        if not result.control_ok:
            return result

        test_dir = workdir / "blastgate"
        shutil.copytree(source, test_dir)
        (result.blastgate_ok, result.blastgate_detail, result.denied_hosts,
         result.blastgate_attempts) = blastgate_install(test_dir, case.ecosystem)
        return result
    finally:
        result.seconds = time.time() - started
        shutil.rmtree(workdir, ignore_errors=True)


def render(results: List[Result]) -> str:
    considered = [r for r in results if r.control_ok]
    failures = [r for r in considered if not r.blastgate_ok]
    excluded = [r for r in results if not r.control_ok]

    rate = (len(failures) / len(considered) * 100) if considered else 0.0
    lines = [
        f"**{len(considered) - len(failures)} of {len(considered)} real projects "
        f"install unchanged under blastgate. False positive rate: {rate:.0f}%.**",
        "",
        "| Project | Ecosystem | Why it is here | Verdict | Denied hosts |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in results:
        hosts = ", ".join(f"`{h}`" for h in r.denied_hosts[:4]) or "—"
        retried = ""
        if max(r.control_attempts, r.blastgate_attempts) > 1:
            retried = (f" (retried: control {r.control_attempts}x, "
                       f"blastgate {r.blastgate_attempts}x)")
        lines.append(
            f"| `{r.case.name}` | {r.case.ecosystem} | {r.case.why} | "
            f"{r.verdict}{retried} | {hosts} |"
        )
    if excluded:
        lines += ["", "Excluded because the control install also failed, so the"
                  " failure is not blastgate's:"]
        for r in excluded:
            lines.append(f"- `{r.case.name}`: {r.control_detail}")
    if failures:
        lines += ["", "False positives, in full:"]
        for r in failures:
            lines.append(f"- `{r.case.name}`: {r.blastgate_detail}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    runtime = detect_runtime()
    (Path.home() / ".blastgate-tests").mkdir(parents=True, exist_ok=True)
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
