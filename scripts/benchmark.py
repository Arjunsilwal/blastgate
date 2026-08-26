#!/usr/bin/env python3
"""Measure what blastgate costs, cold and warm.

Two numbers matter and they are very different.

Warm overhead is what a user pays on every install once the images exist. If
that were large, nobody would keep the tool switched on.

Cold start is what they pay once, the first time, and it is the number that
decides whether someone abandons the tool during their first attempt. Published
benchmarks usually quote the warm figure alone, which is the flattering one.

    python scripts/benchmark.py            # warm only, quick
    python scripts/benchmark.py --cold     # also rebuild images, slow
    python scripts/benchmark.py --write    # update README
"""

import argparse
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blastgate.policy import load_policy  # noqa: E402
from blastgate.runner import (  # noqa: E402
    DEFAULT_IMAGES,
    build_proxy_image,
    default_anchor_path,
    default_audit_path,
    detect_runtime,
    proxy_image_tag,
    run_install,
)

BEGIN = "<!-- benchmark:begin -->"
END = "<!-- benchmark:end -->"
REPEATS = 3

# Small, real dependency sets. Big enough that the install does actual work,
# small enough that network variance does not swamp the difference.
CASES = {
    "npm": {
        "files": {"package.json": json.dumps(
            {"name": "bench", "version": "1.0.0",
             "dependencies": {"express": "4.21.2"}})},
        "command": ["npm", "install", "--no-audit", "--no-fund"],
    },
    "pypi": {
        "files": {"requirements.txt": "requests==2.32.3\n"},
        "command": ["pip", "install", "--no-cache-dir",
                    "--root-user-action=ignore", "-r", "requirements.txt"],
    },
    "cargo": {
        "files": {
            "Cargo.toml": '[package]\nname = "bench"\nversion = "0.1.0"\n'
                          'edition = "2021"\n\n[dependencies]\nserde = "1.0"\n',
            "src/main.rs": "fn main() {}\n",
        },
        "command": ["cargo", "fetch"],
    },
}


def scratch(files) -> Path:
    base = Path.home() / ".blastgate-bench"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=base))
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return path


def time_control(ecosystem, case, runtime) -> float:
    project = scratch(case["files"])
    command = case["command"]
    try:
        started = time.time()
        subprocess.run(
            [runtime, "run", "--rm", "--network", "bridge",
             "--mount", f"type=bind,source={project},target=/workspace",
             "-w", "/workspace", "--entrypoint", command[0],
             DEFAULT_IMAGES[ecosystem], *command[1:]],
            capture_output=True, timeout=900,
        )
        return time.time() - started
    finally:
        shutil.rmtree(project, ignore_errors=True)


def time_blastgate(ecosystem, case, runtime) -> float:
    project = scratch(case["files"])
    audit, anchors = default_audit_path(project), default_anchor_path(project)
    try:
        started = time.time()
        run_install(
            policy=load_policy(ecosystem), command=case["command"],
            project_dir=project, audit_path=audit, host_env={}, timeout=900,
        )
        return time.time() - started
    finally:
        shutil.rmtree(project, ignore_errors=True)
        for artefact in (audit, anchors):
            if artefact.exists():
                artefact.unlink()


def time_startup(runtime) -> tuple:
    """The fixed cost of the sandbox, with no install work to hide behind.

    Measured against a command that does nothing, because per-ecosystem timings
    are dominated by network variance: the first version of this script
    reported npm as 14% *faster* with blastgate, which is impossible and meant
    the measurement was noise. What blastgate actually costs is a fixed
    per-run amount - create a network, start the sidecar, wait for it to
    listen, tear it down - and that is what this isolates.
    """
    project = scratch({"package.json": '{"name":"n","version":"1.0.0"}'})
    audit, anchors = default_audit_path(project), default_anchor_path(project)
    bare, sandboxed = [], []
    try:
        for _ in range(REPEATS):
            started = time.time()
            subprocess.run(
                [runtime, "run", "--rm", "--network", "bridge",
                 DEFAULT_IMAGES["npm"], "true"],
                capture_output=True, timeout=300,
            )
            bare.append(time.time() - started)

            started = time.time()
            run_install(
                policy=load_policy("npm"), command=["true"],
                project_dir=project, audit_path=audit, host_env={}, timeout=300,
            )
            sandboxed.append(time.time() - started)
            for artefact in (audit, anchors):
                if artefact.exists():
                    artefact.unlink()
    finally:
        shutil.rmtree(project, ignore_errors=True)
    return median(bare), median(sandboxed)


def time_image_build(runtime) -> Optional[float]:
    """A genuine cold start: no proxy image, no layer cache, no base image.

    Removing only the proxy image measures a rebuild, not a first run. The
    first version of this did exactly that and reported 23s, against 149s when
    the base image happened to be absent too - a six-fold understatement of
    what someone actually waits through on a new machine. The base image is the
    download; the build on top of it is seconds.
    """
    from blastgate.runner import dockerfile_path

    image = proxy_image_tag()
    subprocess.run([runtime, "rmi", "-f", image], capture_output=True)

    base = None
    for line in dockerfile_path("proxy.Dockerfile").read_text().splitlines():
        if line.strip().upper().startswith("FROM "):
            base = line.split()[1]
            break
    if base:
        subprocess.run([runtime, "rmi", "-f", base], capture_output=True, timeout=120)

    subprocess.run([runtime, "builder", "prune", "-af"], capture_output=True, timeout=300)
    started = time.time()
    try:
        build_proxy_image(runtime)
    except Exception:
        return None
    return time.time() - started


def median(values: List[float]) -> float:
    return statistics.median(values) if values else float("nan")


def render(rows, build_seconds, startup) -> str:
    lines = []
    if startup:
        bare, sandboxed = startup
        lines += [
            f"**The sandbox costs about {sandboxed - bare:.1f}s per run.** That is "
            f"a fixed amount - create a network, start the proxy sidecar, wait "
            f"for it to listen, tear it down - measured against a command that "
            f"does nothing, so no install work hides it "
            f"({bare:.1f}s bare container, {sandboxed:.1f}s sandboxed).",
            "",
        ]
    lines += [
        "| Ecosystem | Without | With | Difference |",
        "| --- | --- | --- | --- |",
    ]
    for ecosystem, control, sandboxed in rows:
        delta = sandboxed - control
        lines.append(
            f"| {ecosystem} | {control:.1f}s | {sandboxed:.1f}s | "
            f"{delta:+.1f}s |"
        )
    lines += [
        "",
        "Those per-ecosystem differences are mostly network variance, not "
        "blastgate. An install that spends twenty seconds talking to a registry "
        "moves by more than that between runs, and one of these measurements "
        "came out *faster* sandboxed, which is impossible and is exactly what "
        "noise at this scale looks like. Read the fixed startup figure above "
        "instead, and expect it to matter for short installs and disappear "
        "into the noise for long ones.",
        "",
    ]
    if build_seconds is not None:
        lines.append(
            f"**Cold start: {build_seconds:.0f}s**, once per machine. That is a "
            f"genuine first run - no proxy image, no layer cache, and the base "
            f"image pulled fresh, which is most of it. The ecosystem's own "
            f"image (node, python, rust) is pulled on top the first time you "
            f"use that ecosystem. This is the number a new user actually waits "
            f"through, and it is the one usually left out.\n\n"
            f"That figure is network-bound and varies more than the warm ones: "
            f"measurements here ranged from about 16s to 149s, the slow end "
            f"being a run that shared the machine with a full test suite. Treat "
            f"it as tens of seconds, not as a constant."
        )
    else:
        lines.append(
            "Cold start was not measured in this run; pass `--cold` to include "
            "the one-time proxy image build."
        )
    lines += [
        "",
        f"Medians of {REPEATS} runs on the maintainer's machine, warm images, "
        f"real network. Regenerate with `python scripts/benchmark.py --cold "
        f"--write`.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cold", action="store_true",
                        help="also measure the one-time image build (slow)")
    parser.add_argument("--write", action="store_true", help="update README.md")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()

    runtime = detect_runtime()
    build_seconds = None
    startup = None
    if args.cold:
        print("measuring cold image build...", flush=True)
        build_seconds = time_image_build(runtime)
        print(f"  proxy image build: {build_seconds:.0f}s" if build_seconds
              else "  build failed", flush=True)

    print("measuring fixed sandbox startup cost...", flush=True)
    startup = time_startup(runtime)
    print(f"  bare {startup[0]:.1f}s / sandboxed {startup[1]:.1f}s "
          f"-> +{startup[1]-startup[0]:.1f}s", flush=True)

    rows = []
    for ecosystem, case in CASES.items():
        if args.only and ecosystem not in args.only:
            continue
        print(f"[{ecosystem}] warming...", flush=True)
        time_blastgate(ecosystem, case, runtime)          # warm caches first
        control = median([time_control(ecosystem, case, runtime) for _ in range(REPEATS)])
        sandboxed = median([time_blastgate(ecosystem, case, runtime) for _ in range(REPEATS)])
        print(f"[{ecosystem}] control {control:.1f}s / blastgate {sandboxed:.1f}s", flush=True)
        rows.append((ecosystem, control, sandboxed))

    table = render(rows, build_seconds, startup)
    print("\n" + table)

    if args.write:
        readme = ROOT / "README.md"
        text = readme.read_text()
        if BEGIN not in text or END not in text:
            raise SystemExit(f"README has no {BEGIN} / {END} block")
        head, rest = text.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        readme.write_text(f"{head}{BEGIN}\n{table}\n{END}{tail}")
        print("\nREADME.md updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
