#!/usr/bin/env python3
"""Run the attack corpus and publish the result.

The number this prints is not chosen. It counts disclosed gaps and scenarios
that could not run as failures, which is why it is not 100% and should not be.

    python scripts/attack_report.py           # print
    python scripts/attack_report.py --write   # update README.md in place
"""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from attacks.executor import Report, run_corpus  # noqa: E402

BEGIN = "<!-- corpus:begin -->"
END = "<!-- corpus:end -->"


def render(report: Report) -> str:
    return f"{BEGIN}\n{report.to_markdown()}\n{END}"


def write_readme(report: Report, readme: Path) -> bool:
    text = readme.read_text()
    if BEGIN not in text or END not in text:
        raise SystemExit(
            f"{readme} has no {BEGIN} / {END} block to update."
        )
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    updated = head + render(report) + tail
    if updated == text:
        return False
    readme.write_text(updated)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update README.md in place")
    args = parser.parse_args()

    report = Report(run_corpus())
    print(report.to_markdown())

    if args.write:
        changed = write_readme(report, ROOT / "README.md")
        print("\nREADME.md " + ("updated" if changed else "already current"))

    # Exit non-zero on a real failure, not on a disclosed gap. A gap that is
    # documented and counted is the expected state; a regression is not.
    from attacks.executor import FALSE_POSITIVE, NOT_RUNNABLE, REGRESSION

    bad = (
        report.by_status(REGRESSION)
        + report.by_status(FALSE_POSITIVE)
        + report.by_status(NOT_RUNNABLE)
    )
    for outcome in bad:
        print(f"\n{outcome.status}: {outcome.scenario.id} — {outcome.detail}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
