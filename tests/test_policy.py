import sys
from pathlib import Path
import pytest

from bulkhead.policy import (
    Policy,
    PolicyDecision,
    PolicyError,
    InvalidHostError,
    ExactRule,
    WildcardRule,
    ConditionalRule,
    load_policy,
)
from bulkhead.cli import main as cli_main


@pytest.fixture
def allowlists_dir():
    return Path(__file__).parent.parent / "allowlists"


@pytest.fixture
def npm_policy(allowlists_dir):
    return load_policy("npm", allowlists_dir=allowlists_dir)


@pytest.fixture
def pypi_policy(allowlists_dir):
    return load_policy("pypi", allowlists_dir=allowlists_dir)


@pytest.fixture
def cargo_policy(allowlists_dir):
    return load_policy("cargo", allowlists_dir=allowlists_dir)


class TestExactRules:
    def test_npm_exact_allowed(self, npm_policy):
        decision = npm_policy.evaluate("registry.npmjs.org")
        assert decision.allowed is True
        assert decision.matched_tier == "exact"
        assert decision.rule == "exact:registry.npmjs.org"
        assert "Primary package registry" in decision.reason
        assert decision.host == "registry.npmjs.org"

    def test_npm_yarn_exact_allowed(self, npm_policy):
        decision = npm_policy.evaluate("registry.yarnpkg.com")
        assert decision.allowed is True
        assert decision.matched_tier == "exact"
        assert decision.rule == "exact:registry.yarnpkg.com"

    def test_pypi_exact_allowed(self, pypi_policy):
        decision = pypi_policy.evaluate("pypi.org")
        assert decision.allowed is True
        assert decision.matched_tier == "exact"
        assert decision.rule == "exact:pypi.org"

        files_decision = pypi_policy.evaluate("files.pythonhosted.org")
        assert files_decision.allowed is True
        assert files_decision.matched_tier == "exact"
        assert files_decision.rule == "exact:files.pythonhosted.org"

    def test_cargo_exact_allowed(self, cargo_policy):
        decision = cargo_policy.evaluate("crates.io")
        assert decision.allowed is True
        assert decision.matched_tier == "exact"
        assert decision.rule == "exact:crates.io"

        index_decision = cargo_policy.evaluate("index.crates.io")
        assert index_decision.allowed is True
        assert index_decision.matched_tier == "exact"
        assert index_decision.rule == "exact:index.crates.io"


class TestWildcardRules:
    def test_npm_wildcard_subdomain_allowed(self, npm_policy):
        decision = npm_policy.evaluate("cdn.npmjs.org")
        assert decision.allowed is True
        assert decision.matched_tier == "wildcard"
        assert decision.rule == "wildcard:*.npmjs.org"
        assert decision.host == "cdn.npmjs.org"

    def test_npm_nested_subdomain_wildcard_allowed(self, npm_policy):
        decision = npm_policy.evaluate("edge.us-east.npmjs.org")
        assert decision.allowed is True
        assert decision.matched_tier == "wildcard"
        assert decision.rule == "wildcard:*.npmjs.org"

    def test_pypi_wildcard_subdomain_allowed(self, pypi_policy):
        decision = pypi_policy.evaluate("cdn.pythonhosted.org")
        assert decision.allowed is True
        assert decision.matched_tier == "wildcard"
        assert decision.rule == "wildcard:*.pythonhosted.org"

    def test_cargo_wildcard_subdomain_allowed(self, cargo_policy):
        decision = cargo_policy.evaluate("mirror.crates.io")
        assert decision.allowed is True
        assert decision.matched_tier == "wildcard"
        assert decision.rule == "wildcard:*.crates.io"


class TestConditionalRules:
    def test_conditional_denied_by_default(self, npm_policy):
        decision = npm_policy.evaluate("github.com")
        assert decision.allowed is False
        assert decision.matched_tier == "conditional"
        assert "git-dependencies" in decision.reason
        assert decision.rule is None

    def test_conditional_denied_when_different_condition_enabled(self, npm_policy):
        decision = npm_policy.evaluate("github.com", enabled_conditions={"other-condition"})
        assert decision.allowed is False
        assert decision.matched_tier == "conditional"
        assert "git-dependencies" in decision.reason

    def test_conditional_allowed_when_condition_enabled(self, npm_policy):
        decision = npm_policy.evaluate("github.com", enabled_conditions={"git-dependencies"})
        assert decision.allowed is True
        assert decision.matched_tier == "conditional"
        assert decision.rule == "conditional:github.com"
        assert "git repository" in decision.reason.lower()

    def test_conditional_raw_github_when_condition_enabled(self, npm_policy):
        decision = npm_policy.evaluate("raw.githubusercontent.com", enabled_conditions={"git-dependencies"})
        assert decision.allowed is True
        assert decision.matched_tier == "conditional"
        assert decision.rule == "conditional:raw.githubusercontent.com"


class TestDefaultDeny:
    def test_unlisted_domain_denied(self, npm_policy):
        decision = npm_policy.evaluate("evil.com")
        assert decision.allowed is False
        assert decision.rule is None
        assert decision.matched_tier is None
        assert "default deny" in decision.reason.lower()

    def test_cross_ecosystem_denied(self, npm_policy):
        decision = npm_policy.evaluate("pypi.org")
        assert decision.allowed is False
        assert decision.rule is None
        assert decision.matched_tier is None

    def test_generic_internet_denied(self, npm_policy):
        for host in ["google.com", "pastebin.com", "webhook.site", "attacker.io"]:
            decision = npm_policy.evaluate(host)
            assert decision.allowed is False
            assert decision.rule is None


class TestEvasion:
    def test_case_variation_exact(self, npm_policy):
        for host in [
            "REGISTRY.NPMJS.ORG",
            "Registry.NpmJs.Org",
            "registry.NPMJS.org",
        ]:
            decision = npm_policy.evaluate(host)
            assert decision.allowed is True
            assert decision.matched_tier == "exact"
            assert decision.host == "registry.npmjs.org"

    def test_case_variation_wildcard(self, npm_policy):
        for host in [
            "CDN.NPMJS.ORG",
            "Cdn.Npmjs.Org",
        ]:
            decision = npm_policy.evaluate(host)
            assert decision.allowed is True
            assert decision.matched_tier == "wildcard"
            assert decision.host == "cdn.npmjs.org"

    def test_trailing_dot_exact(self, npm_policy):
        decision = npm_policy.evaluate("registry.npmjs.org.")
        assert decision.allowed is True
        assert decision.matched_tier == "exact"
        assert decision.host == "registry.npmjs.org"

    def test_trailing_dot_wildcard(self, npm_policy):
        decision = npm_policy.evaluate("cdn.npmjs.org.")
        assert decision.allowed is True
        assert decision.matched_tier == "wildcard"
        assert decision.host == "cdn.npmjs.org"

    def test_multiple_trailing_dots_denied(self, npm_policy):
        decision = npm_policy.evaluate("registry.npmjs.org..")
        assert decision.allowed is False
        assert decision.rule is None

    def test_leading_dot_denied(self, npm_policy):
        decision = npm_policy.evaluate(".registry.npmjs.org")
        assert decision.allowed is False
        assert decision.rule is None

    def test_port_stripping_and_handling(self, npm_policy):
        decision_443 = npm_policy.evaluate("registry.npmjs.org:443")
        assert decision_443.allowed is True
        assert decision_443.matched_tier == "exact"
        assert decision_443.host == "registry.npmjs.org"

        decision_8080 = npm_policy.evaluate("registry.npmjs.org:8080")
        assert decision_8080.allowed is True
        assert decision_8080.matched_tier == "exact"
        assert decision_8080.host == "registry.npmjs.org"

        decision_evil_port = npm_policy.evaluate("evil.com:443")
        assert decision_evil_port.allowed is False

    def test_invalid_port_denied(self, npm_policy):
        for invalid in [
            "registry.npmjs.org:abc",
            "registry.npmjs.org:999999",
            "registry.npmjs.org:-1",
            "registry.npmjs.org:",
        ]:
            decision = npm_policy.evaluate(invalid)
            assert decision.allowed is False

    def test_lookalike_domains_denied(self, npm_policy):
        lookalikes = [
            "registry.npmjs.org.evil.com",
            "registry.npmjs.org.attacker.io",
            "registry.npmjs.org-evil.com",
            "registry.npmjs.org.fake.net",
            "pypi.org.attacker.com",
            "crates.io.evil.org",
        ]
        for host in lookalikes:
            decision = npm_policy.evaluate(host)
            assert decision.allowed is False
            assert decision.rule is None

    def test_prefix_spoofing_suffix_wildcard_denied(self, npm_policy):
        # Wildcard rule is *.npmjs.org. Non-subdomain prefix matches must be DENIED.
        prefix_spoofs = [
            "evilnpmjs.org",
            "fake-npmjs.org",
            "notnpmjs.org",
            "attacker-npmjs.org",
            "sub.evilnpmjs.org",
            "my_npmjs.org",
            "npmjs.org.evil.com",
        ]
        for host in prefix_spoofs:
            decision = npm_policy.evaluate(host)
            assert decision.allowed is False
            assert decision.rule is None

    def test_raw_ipv4_denied(self, npm_policy):
        raw_ips = [
            "127.0.0.1",
            "1.1.1.1",
            "8.8.8.8",
            "169.254.169.254",   # Cloud metadata IP
            "10.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1:443",
            "169.254.169.254:80",
        ]
        for ip in raw_ips:
            decision = npm_policy.evaluate(ip)
            assert decision.allowed is False
            assert decision.rule is None

    def test_raw_ipv6_denied(self, npm_policy):
        raw_ipv6 = [
            "::1",
            "[::1]",
            "[::1]:443",
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:db8::1]:8080",
            "fe80::1",
            "[fe80::1]",
        ]
        for ip in raw_ipv6:
            decision = npm_policy.evaluate(ip)
            assert decision.allowed is False
            assert decision.rule is None

    def test_alternate_ip_encodings_denied(self, npm_policy):
        alt_ips = [
            "2130706433",          # Decimal for 127.0.0.1
            "0177.0.0.1",          # Octal
            "0x7f.1",              # Hex
            "0x7f.0x0.0x0.0x1",    # Hex
        ]
        for ip in alt_ips:
            decision = npm_policy.evaluate(ip)
            assert decision.allowed is False
            assert decision.rule is None

    def test_uri_injection_and_malformed_hosts(self, npm_policy):
        malformed = [
            "",
            "   ",
            "http://registry.npmjs.org/path?query=1",
            "registry.npmjs.org/path",
            "user:pass@registry.npmjs.org",
            "user@registry.npmjs.org",
            "registry.npmjs.org@evil.com",
            "registry.npmjs.org\x00.evil.com",
            "registry.npmjs.org;curl evil.com",
            "registry.npmjs.org\nevil.com",
            "registry.npmjs.org\revil.com",
            "registry.npmjs.org && evil.com",
        ]
        for bad in malformed:
            decision = npm_policy.evaluate(bad)
            assert decision.allowed is False


class TestPolicySchemaAndLoading:
    def test_load_all_shipped_ecosystems(self, allowlists_dir):
        for eco in ["npm", "pypi", "cargo"]:
            policy = load_policy(eco, allowlists_dir=allowlists_dir)
            assert policy.ecosystem == eco
            assert len(policy.exact_rules) > 0
            assert len(policy.wildcard_rules) > 0
            assert len(policy.conditional_rules) > 0

    def test_load_missing_ecosystem_raises(self, allowlists_dir):
        with pytest.raises(PolicyError, match="No allowlist found"):
            load_policy("nonexistent", allowlists_dir=allowlists_dir)

    def test_invalid_yaml_structure_raises(self):
        with pytest.raises(PolicyError):
            Policy.from_dict({"ecosystem": "test"})  # missing required sections

    def test_rule_without_reason_raises(self):
        with pytest.raises(PolicyError, match="reason"):
            Policy.from_dict({
                "ecosystem": "test",
                "exact": [{"host": "example.com"}],  # missing reason
                "wildcard": [],
                "conditional": [],
            })

    def test_wildcard_must_start_with_star_dot(self):
        with pytest.raises(PolicyError, match="must start with"):
            Policy.from_dict({
                "ecosystem": "test",
                "exact": [],
                "wildcard": [{"pattern": "npmjs.org", "reason": "test"}],
                "conditional": [],
            })


class TestCliCheck:
    def test_cli_check_allowed_exit_code(self, allowlists_dir, capsys):
        rc = cli_main(["check", "npm", "registry.npmjs.org", "--allowlists-dir", str(allowlists_dir)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "registry.npmjs.org" in captured.out
        assert "exact:registry.npmjs.org" in captured.out

    def test_cli_check_denied_exit_code(self, allowlists_dir, capsys):
        rc = cli_main(["check", "npm", "evil.com", "--allowlists-dir", str(allowlists_dir)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "DENY" in captured.out

    def test_cli_check_conditional_denied_without_flag(self, allowlists_dir, capsys):
        rc = cli_main(["check", "npm", "github.com", "--allowlists-dir", str(allowlists_dir)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "DENY" in captured.out

    def test_cli_check_conditional_allowed_with_flag(self, allowlists_dir, capsys):
        rc = cli_main(["check", "npm", "github.com", "--allow", "git-dependencies", "--allowlists-dir", str(allowlists_dir)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "conditional:github.com" in captured.out

    def test_cli_check_invalid_ecosystem(self, allowlists_dir, capsys):
        rc = cli_main(["check", "nonexistent", "example.com", "--allowlists-dir", str(allowlists_dir)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "Error" in captured.err or "Error" in captured.out


class TestCliRun:
    """`bh run` must refuse rather than run without an enforcement point.

    These tests fail if an execution path is ever added to the run command
    before isolation and egress enforcement exist.
    """

    @pytest.fixture
    def no_execution_allowed(self, monkeypatch):
        """Make any attempt to execute a subprocess a test failure."""
        import os
        import subprocess

        def forbidden(*args, **kwargs):
            raise AssertionError("bh run attempted to execute a command")

        for target, name in (
            (subprocess, "run"),
            (subprocess, "call"),
            (subprocess, "check_call"),
            (subprocess, "check_output"),
            (subprocess, "Popen"),
            (os, "system"),
            (os, "execvp"),
            (os, "execv"),
            (os, "posix_spawn"),
            (os, "fork"),
        ):
            monkeypatch.setattr(target, name, forbidden)

    def test_run_refuses_and_never_executes(self, no_execution_allowed, capsys):
        exit_code = cli_main(["run", "npm", "install"])
        captured = capsys.readouterr()
        assert exit_code == 2
        assert "refusing to run" in captured.err
        assert captured.out == ""

    def test_run_refuses_for_every_ecosystem(self, no_execution_allowed):
        for ecosystem in ("npm", "pypi", "cargo"):
            assert cli_main(["run", ecosystem, "install"]) == 2

    def test_run_refuses_with_no_install_arguments(self, no_execution_allowed):
        assert cli_main(["run", "npm"]) == 2

    def test_run_refusal_cites_the_threat_model(self, no_execution_allowed, capsys):
        cli_main(["run", "npm", "install"])
        assert "threat-model.md" in capsys.readouterr().err
