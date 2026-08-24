"""Bulkhead CLI interface.

Four subcommands. 'check' evaluates a host against a policy without running
anything. 'run' performs an install inside the sandbox. 'audit' reviews and
verifies the log. 'proxy' runs the enforcement point in the foreground and
exists for the sidecar container to invoke; it is not normally typed by hand.

'run' still fails closed on every error path. If the runtime is missing, if the
network is not actually internal, or if the sidecar does not come up, it refuses
rather than falling back to an unsandboxed install. There is no code path here
that runs a command outside the sandbox.
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from bulkhead import BulkheadError
from bulkhead.audit import (
    AnchorStore,
    AuditError,
    AuditLog,
    TamperError,
    format_entry_count,
)
from bulkhead.policy import PolicyError, load_policy
from bulkhead.proxy import run_proxy_server
from bulkhead.runner import (
    RunnerError,
    anchor_path_for_audit,
    default_audit_path,
    run_install,
)


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
        help="Run an install inside the sandbox with the proxy as its only route out",
    )
    run_parser.add_argument(
        "ecosystem",
        help="Target ecosystem (e.g. npm, pypi, cargo)",
    )
    run_parser.add_argument(
        "argv",
        nargs="*",
        metavar="COMMAND",
        help="Install command to run inside the sandbox, after a '--' separator "
             "(e.g. bh run npm -- npm ci). REMAINDER is deliberately not used "
             "here: it silently swallows bulkhead's own options into the "
             "command, so --project and --audit would be ignored rather than "
             "rejected.",
    )
    run_parser.add_argument(
        "--project",
        type=Path,
        default=None,
        help="Project directory to mount (default: current directory)",
    )
    run_parser.add_argument(
        "--image",
        default=None,
        help="Image to run the install in (default: chosen per ecosystem)",
    )
    run_parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="Where to write the audit log (default: .bulkhead/audit.log)",
    )
    run_parser.add_argument(
        "--allow",
        action="append",
        dest="allowed_conditions",
        default=[],
        help="Explicitly enable a condition (e.g. --allow git-dependencies)",
    )
    run_parser.add_argument("--allowlists-dir", type=Path, default=None)

    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Run the egress proxy in the foreground (used inside the sidecar container)",
    )
    proxy_parser.add_argument("ecosystem", help="Target ecosystem (e.g. npm, pypi, cargo)")
    proxy_parser.add_argument(
        "--port", type=int, default=3128, help="Port to listen on (default: 3128)"
    )
    proxy_parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Address to bind. The default is only safe on an internal network "
             "whose only other member is the install container.",
    )
    proxy_parser.add_argument(
        "--audit", type=Path, default=None, help="Path to write the audit log"
    )
    proxy_parser.add_argument(
        "--allow",
        action="append",
        dest="allowed_conditions",
        default=[],
        help="Explicitly enable a condition (e.g. --allow git-dependencies)",
    )
    proxy_parser.add_argument("--allowlists-dir", type=Path, default=None)

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
    audit_parser.add_argument(
        "--anchor",
        type=Path,
        default=None,
        help="Anchor store to verify against (default: the one matching this log)",
    )
    audit_parser.add_argument(
        "--no-anchor",
        action="store_true",
        help="Verify the chain alone, without checking its anchor",
    )
    audit_parser.add_argument(
        "--require-anchor",
        action="store_true",
        help="Exit non-zero if no anchor exists. Use in CI, where 'truncation "
             "cannot be detected' should not pass silently.",
    )

    return parser


REFUSAL = (
    "bh: refusing to run. Isolation and egress enforcement are not implemented "
    "(Phase 2 and 3).\n"
    "    Running an install without an enforcement point would provide no "
    "protection.\n"
    "    See docs/threat-model.md section 7.\n"
)


def split_on_separator(args: List[str]) -> "tuple[List[str], List[str]]":
    """Split bulkhead's own arguments from the command to run in the sandbox.

    Done before argparse rather than with argparse.REMAINDER. REMAINDER would
    swallow --project and --audit into the install command, silently ignoring
    them; a mis-specified audit path is exactly the kind of thing that must
    fail loudly rather than be dropped.
    """
    if "--" in args:
        index = args.index("--")
        return args[:index], args[index + 1:]
    return args, []


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv[1:]

    args, sandbox_command = split_on_separator(list(args))

    parser = build_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    if parsed_args.command == "proxy":
        try:
            policy = load_policy(
                parsed_args.ecosystem, allowlists_dir=parsed_args.allowlists_dir
            )
        except PolicyError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2
        run_proxy_server(
            policy,
            port=parsed_args.port,
            audit_path=parsed_args.audit,
            enabled_conditions=set(parsed_args.allowed_conditions),
            host=parsed_args.bind,
        )
        return 0

    if parsed_args.command == "run":
        command = sandbox_command or list(parsed_args.argv)
        if not command:
            sys.stderr.write(
                "bh: no install command given.\n"
                "    Put the command after a '--' separator, for example:\n"
                "      bh run npm -- npm ci\n"
            )
            return 2

        try:
            policy = load_policy(
                parsed_args.ecosystem, allowlists_dir=parsed_args.allowlists_dir
            )
        except PolicyError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        project = (parsed_args.project or Path.cwd()).resolve()
        # Not inside the project: that directory is mounted writable into the
        # sandbox, so a log there is one the payload can rewrite.
        audit_path = parsed_args.audit or default_audit_path(project)

        try:
            result = run_install(
                policy=policy,
                command=command,
                project_dir=project,
                image=parsed_args.image,
                audit_path=audit_path,
                enabled_conditions=set(parsed_args.allowed_conditions),
            )
        except BulkheadError as e:
            # Every failure here is a refusal to run unprotected. Catching the
            # base class rather than RunnerError is deliberate: resolution
            # failures are refusals too, and one falling through as a traceback
            # would look like a crash rather than a decision.
            sys.stderr.write(f"bh: refusing to run. {e}\n")
            return 2

        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.stdout.write(
            f"\nbh: egress decisions recorded in {audit_path}\n"
            f"    review with: bh audit {audit_path}\n"
        )
        return result.exit_code

    if parsed_args.command == "audit":
        log = AuditLog(parsed_args.path)

        anchor = None
        anchor_store_path = None
        if not parsed_args.no_anchor:
            anchor_store_path = parsed_args.anchor or anchor_path_for_audit(parsed_args.path)
            try:
                store = AnchorStore(anchor_store_path)
                store.verify()
                anchor = store.latest_for(parsed_args.path)
            except TamperError as e:
                sys.stderr.write(f"TAMPERED: anchor store: {e}\n")
                return 1
            except AuditError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 2

        try:
            entries = log.read_all()
            if anchor is not None:
                log.verify_against_anchor(anchor, entries)
            else:
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

        if anchor is not None:
            sys.stdout.write(
                f"OK: chain verified against anchor, {format_entry_count(len(entries))} "
                f"(anchored at {anchor.entry_count} by run {anchor.run_id[:8]})\n"
            )
            return 0

        # Deliberately not the same word as a verified log. The chain being
        # internally consistent says nothing about entries removed from the
        # end, and reporting both states identically would hide that.
        sys.stdout.write(
            f"UNANCHORED: chain is internally consistent, {format_entry_count(len(entries))}.\n"
            f"    No anchor found"
            + (f" at {anchor_store_path}" if anchor_store_path else " (--no-anchor)")
            + ", so truncation cannot be detected.\n"
        )
        return 1 if parsed_args.require_anchor else 0

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
