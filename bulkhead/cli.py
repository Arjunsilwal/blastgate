"""Bulkhead CLI interface.

Phase 1 implements only the 'check' subcommand.
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from bulkhead.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bh",
        description="Bulkhead: Package install egress control and isolation",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check",
        help="Check a target host against an ecosystem policy without running anything",
    )
    check_parser.add_argument(
        "ecosystem",
        help="Target ecosystem (e.g. npm, pypi, cargo)",
    )
    check_parser.add_argument(
        "host",
        help="Destination hostname to evaluate",
    )
    check_parser.add_argument(
        "--allow",
        action="append",
        dest="allowed_conditions",
        default=[],
        help="Explicitly enable a condition (e.g. --allow git-dependencies)",
    )
    check_parser.add_argument(
        "--allowlists-dir",
        type=Path,
        default=None,
        help="Custom path to directory containing allowlist YAML files",
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv[1:]

    parser = build_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    if parsed_args.command == "check":
        try:
            policy = load_policy(
                parsed_args.ecosystem,
                allowlists_dir=parsed_args.allowlists_dir,
            )
        except PolicyError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        enabled_conditions = set(parsed_args.allowed_conditions)
        decision = policy.evaluate(
            parsed_args.host,
            enabled_conditions=enabled_conditions,
        )

        if decision.allowed:
            sys.stdout.write(f"ALLOW {decision.host} (matched: {decision.rule}) - {decision.reason}\n")
            return 0
        else:
            sys.stdout.write(f"DENY {decision.host} - {decision.reason}\n")
            return 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
