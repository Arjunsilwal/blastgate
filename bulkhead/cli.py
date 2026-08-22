"""Bulkhead CLI interface.

Phase 1 implements the 'check' subcommand. 'run' exists but refuses: there is no
enforcement point yet, and running an install without one would provide no
protection while appearing to. Failing closed is the correct behaviour, and it
stays correct when the container runtime is simply unavailable.
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from bulkhead.audit import AuditError, AuditLog, TamperError
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

    run_parser = subparsers.add_parser(
        "run",
        help="Run an install inside the sandbox (refuses: no enforcement point yet)",
    )
    run_parser.add_argument(
        "ecosystem",
        help="Target ecosystem (e.g. npm, pypi, cargo)",
    )
    run_parser.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="Install command to run inside the sandbox",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Review logged egress decisions and verify the log has not been altered",
    )
    audit_parser.add_argument(
        "path",
        type=Path,
        help="Path to the audit log",
    )
    audit_parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Check the chain and print nothing but the verdict",
    )

    return parser


REFUSAL = (
    "bh: refusing to run. Isolation and egress enforcement are not implemented "
    "(Phase 2 and 3).\n"
    "    Running an install without an enforcement point would provide no "
    "protection.\n"
    "    See docs/threat-model.md section 7.\n"
)


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv[1:]

    parser = build_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    if parsed_args.command == "run":
        # Deliberate fail-closed default. Never fall back to unsandboxed
        # execution: no execution path may be added here before the enforcement
        # point exists. See docs/threat-model.md section 6.
        sys.stderr.write(REFUSAL)
        return 2

    if parsed_args.command == "audit":
        log = AuditLog(parsed_args.path)
        try:
            entries = log.read_all()
            log.verify(entries)
        except TamperError as e:
            # Loud by design. A log that does not verify is the one output
            # nobody should be able to overlook.
            sys.stderr.write(f"TAMPERED: {e}\n")
            return 1
        except AuditError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        if not parsed_args.verify_only:
            for entry in entries:
                verdict = "ALLOW" if entry.allowed else "DENY "
                rule = entry.rule or "-"
                sys.stdout.write(
                    f"{entry.seq:>5}  {entry.timestamp}  {verdict}  "
                    f"{entry.host}  ({rule})\n"
                )

        sys.stdout.write(f"OK: chain verified, {len(entries)} entries\n")
        return 0

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
