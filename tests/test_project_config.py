"""Project configuration, the shim, and telling a user what to do about a denial.

The theme is that a control nobody can work with gets removed. A denial that
does not say what to do about it, and a command nobody wants to type, both end
the same way.
"""

from pathlib import Path

import pytest

from blastgate.cli import SHIM_TOOLS, UNSUPPORTED_TOOLS, expand_shim, project_config_hint
from blastgate.policy import (
    PROJECT_CONFIG_NAME,
    PolicyError,
    load_policy,
    load_project_allowances,
)


def write_config(directory: Path, text: str) -> Path:
    path = directory / PROJECT_CONFIG_NAME
    path.write_text(text)
    return path


class TestProjectConfig:
    def test_a_project_can_add_a_host(self, tmp_path):
        write_config(tmp_path, "version: 1\nallow:\n"
                               "  - host: artifacts.internal.test\n"
                               "    reason: internal mirror\n")
        policy = load_policy("npm", project_dir=tmp_path)
        assert policy.evaluate("artifacts.internal.test").allowed is True

    def test_the_origin_of_an_added_host_is_visible(self, tmp_path):
        # A reader of the audit log should not have to guess whether a host
        # shipped with the tool or was added locally.
        write_config(tmp_path, "version: 1\nallow:\n"
                               "  - host: artifacts.internal.test\n"
                               "    reason: internal mirror\n")
        decision = load_policy("npm", project_dir=tmp_path).evaluate("artifacts.internal.test")
        assert decision.reason.startswith("[project]")

    def test_adding_a_host_does_not_widen_anything_else(self, tmp_path):
        write_config(tmp_path, "version: 1\nallow:\n"
                               "  - host: artifacts.internal.test\n"
                               "    reason: internal mirror\n")
        policy = load_policy("npm", project_dir=tmp_path)
        assert policy.evaluate("exfil.attacker.test").allowed is False
        assert policy.evaluate("github.com").allowed is False

    def test_a_host_without_a_reason_is_refused(self, tmp_path):
        # Same rule as the shipped allowlists. Widening egress should have to
        # say why, in words a reviewer can disagree with.
        write_config(tmp_path, "version: 1\nallow:\n  - host: x.test\n")
        with pytest.raises(PolicyError, match="no reason"):
            load_policy("npm", project_dir=tmp_path)

    @pytest.mark.parametrize("key", [
        "disable_proxy", "allowed_ports", "no_anchor", "deny", "wildcard",
    ])
    def test_any_key_that_could_weaken_a_control_is_refused(self, tmp_path, key):
        # Refused loudly rather than ignored. A key that looks like it turns
        # something off, and is silently skipped, is worse than an error.
        write_config(tmp_path, f"version: 1\n{key}: true\n")
        with pytest.raises(PolicyError, match="cannot disable or weaken"):
            load_policy("npm", project_dir=tmp_path)

    def test_no_config_is_not_an_error(self, tmp_path):
        assert load_project_allowances(tmp_path) == []
        assert load_policy("npm", project_dir=tmp_path).evaluate("exfil.test").allowed is False

    def test_malformed_yaml_is_refused(self, tmp_path):
        write_config(tmp_path, "version: 1\nallow: [unclosed\n")
        with pytest.raises(PolicyError):
            load_policy("npm", project_dir=tmp_path)

    def test_a_project_cannot_allow_a_raw_address(self, tmp_path):
        # The evasion checks still apply to anything added here.
        write_config(tmp_path, "version: 1\nallow:\n  - host: 203.0.113.10\n"
                               "    reason: trying it on\n")
        with pytest.raises(PolicyError):
            load_policy("npm", project_dir=tmp_path)


class TestShim:
    @pytest.mark.parametrize("tool,ecosystem", sorted(SHIM_TOOLS.items()))
    def test_a_tool_expands_to_the_explicit_form(self, tool, ecosystem):
        assert expand_shim([tool, "install"]) == ["run", ecosystem, "--", tool, "install"]

    @pytest.mark.parametrize("command", [
        ["run", "npm", "--", "npm", "ci"],
        ["check", "npm", "registry.npmjs.org"],
        ["audit", "/tmp/x.log"],
        ["creds", "list"],
        ["proxy", "npm"],
        [],
    ])
    def test_real_subcommands_are_untouched(self, command):
        assert expand_shim(list(command)) == command

    def test_flags_after_the_tool_go_to_the_tool(self, expected=None):
        assert expand_shim(["npm", "ci", "--omit=dev"]) == [
            "run", "npm", "--", "npm", "ci", "--omit=dev"
        ]

    @pytest.mark.parametrize("tool", sorted(UNSUPPORTED_TOOLS))
    def test_tools_with_no_image_are_named_rather_than_guessed_at(self, tool):
        # `yarn: not found` from inside a container tells the user nothing.
        from blastgate.cli import main

        assert main([tool, "install"]) == 2


class TestDenialHint:
    def test_the_hint_is_pasteable(self, tmp_path):
        text = project_config_hint({"exfil.attacker.test"}, tmp_path)
        assert str(tmp_path / PROJECT_CONFIG_NAME) in text
        assert "- host: exfil.attacker.test" in text
        assert "reason:" in text

    def test_the_hint_says_what_adding_a_host_costs(self, tmp_path):
        # Otherwise it reads as "paste this to make the error go away".
        text = project_config_hint({"a.test"}, tmp_path)
        assert "every install in this project" in text

    def test_several_hosts_are_all_listed(self, tmp_path):
        text = project_config_hint({"a.test", "b.test"}, tmp_path)
        assert "- host: a.test" in text and "- host: b.test" in text
