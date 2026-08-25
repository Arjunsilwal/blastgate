"""The machine-readable contract a pipeline can be built on.

The interesting question is not whether denials are reported. It is which
denials are worth stopping a build for. A gate that fires on every refused
request trains everyone to disable it, and then it protects nothing.
"""

import json
from pathlib import Path

import pytest
import yaml

from blastgate.cli import (
    EXIT_REFUSED,
    EXIT_UNEXPECTED_EGRESS,
    SCHEMA,
    summarise_run,
    write_summary,
)
from blastgate.policy import load_policy
from blastgate.runner import SandboxResult


@pytest.fixture
def npm():
    return load_policy("npm")


def log_with(tmp_path, decisions):
    from blastgate.audit import AuditLog

    log = AuditLog(tmp_path / "audit.log")
    for host, allowed in decisions:
        log.append("npm", host, allowed, "exact" if allowed else None, "test")
    return log.path


class TestKnownVersusUnknownHosts:
    """The classification the whole gate rests on."""

    @pytest.mark.parametrize("host", [
        "registry.npmjs.org",       # allowed outright
        "codeload.github.com",      # named, refused during install by design
        "github.com",               # named in the conditional tier
        "cdn.npmjs.org",            # matched by a wildcard
    ])
    def test_hosts_the_allowlist_names_are_known(self, npm, host):
        assert npm.knows_host(host) is True

    @pytest.mark.parametrize("host", [
        "exfil.attacker.test",
        "webhook.site",
        "registry.npmjs.org.attacker.test",
        "not a hostname at all",
    ])
    def test_hosts_nobody_listed_are_unknown(self, npm, host):
        assert npm.knows_host(host) is False

    def test_a_lookalike_is_not_known_by_accident(self, npm):
        # The suffix contains the registry name; the host is not the registry.
        assert npm.knows_host("registry.npmjs.org.evil.test") is False


class TestSummary:
    def test_a_clean_run_reports_no_unexpected_egress(self, npm, tmp_path):
        audit = log_with(tmp_path, [("registry.npmjs.org", True)])
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""), audit
        )
        assert summary["schema"] == SCHEMA
        assert summary["install_ok"] is True
        assert summary["decisions"] == {"total": 1, "allowed": 1, "denied": 0}
        assert summary["unexpected_egress"] == []

    def test_a_named_host_being_refused_is_not_escalated(self, npm, tmp_path):
        # npm probes this during a git-dependency install and carries on.
        # Escalating it would make the gate useless within a week.
        audit = log_with(tmp_path, [
            ("registry.npmjs.org", True), ("codeload.github.com", False),
        ])
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""), audit
        )
        assert summary["decisions"]["denied"] == 1
        assert summary["denied"][0]["known_to_allowlist"] is True
        assert summary["unexpected_egress"] == []

    def test_an_unlisted_host_is_escalated(self, npm, tmp_path):
        audit = log_with(tmp_path, [
            ("registry.npmjs.org", True), ("exfil.attacker.test", False),
        ])
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""), audit
        )
        assert [d["host"] for d in summary["unexpected_egress"]] == ["exfil.attacker.test"]

    def test_a_successful_install_can_still_have_unexpected_egress(self, npm, tmp_path):
        # The case the exit code exists for: nothing about the install failing
        # would reveal this.
        audit = log_with(tmp_path, [("exfil.attacker.test", False)])
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""), audit
        )
        assert summary["install_ok"] is True
        assert summary["unexpected_egress"]

    def test_a_missing_log_is_an_empty_summary_not_a_crash(self, npm, tmp_path):
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""),
            tmp_path / "absent.log",
        )
        assert summary["decisions"]["total"] == 0

    def test_the_summary_is_written_where_asked(self, npm, tmp_path):
        audit = log_with(tmp_path, [("registry.npmjs.org", True)])
        summary = summarise_run(
            npm, tmp_path, ["npm", "ci"], SandboxResult(0, "", ""), audit
        )
        destination = tmp_path / "nested" / "summary.json"
        write_summary(summary, destination)
        assert json.loads(destination.read_text())["schema"] == SCHEMA


class TestExitCodes:
    def test_the_codes_are_distinct_and_stable(self):
        # A pipeline branches on these, so they are part of the interface.
        assert EXIT_REFUSED == 2
        assert EXIT_UNEXPECTED_EGRESS == 3
        assert EXIT_REFUSED != EXIT_UNEXPECTED_EGRESS


class TestAction:
    @pytest.fixture
    def action(self):
        path = Path(__file__).resolve().parent.parent / "action.yml"
        if not path.is_file():
            pytest.skip("not running from a source checkout")
        return yaml.safe_load(path.read_text())

    def test_the_action_is_a_composite_with_the_inputs_it_documents(self, action):
        assert action["runs"]["using"] == "composite"
        for name in ("ecosystem", "command", "project", "allow",
                     "fail-on-unexpected-egress"):
            assert name in action["inputs"], name

    def test_the_gate_is_on_by_default(self, action):
        # Off by default would mean most users never get the signal.
        assert action["inputs"]["fail-on-unexpected-egress"]["default"] == "true"

    def test_the_action_refuses_without_a_container_runtime(self, action):
        # Otherwise a runtime-less runner looks like an install failure.
        steps = " ".join(step.get("run", "") for step in action["runs"]["steps"])
        assert "no container runtime found" in steps

    def test_the_action_exposes_the_audit_log(self, action):
        assert "audit-log" in action["outputs"]
        assert "unexpected-egress" in action["outputs"]
