"""Tests for what crosses the sandbox boundary.

The environment tests are written as a default-deny assertion: the sandbox
receives what it was explicitly given and nothing else. They are deliberately
not a list of credential names to block, because that list can never be
complete. The credential names that appear here are targets from real registry
campaigns, present to demonstrate the control rather than to define it.
"""

import pytest

from blastgate.runner import (
    SAFE_PASSTHROUGH,
    CredentialForwardError,
    EnvironmentDecision,
    RunnerError,
    RuntimeUnavailableError,
    detect_runtime,
    is_credential_shaped,
    strip_environment,
)


REAL_CREDENTIAL_NAMES = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "TWINE_PASSWORD",
    "PYPI_API_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "DOCKER_PASSWORD",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "GPG_PRIVATE_KEY",
    "VAULT_TOKEN",
    "CLOUDFLARE_API_KEY",
    "STRIPE_SECRET_KEY",
    "SLACK_WEBHOOK_URL",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HF_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
]


class TestDefaultDeny:
    """The primary control: unknown variables do not cross the boundary."""

    def test_unknown_variable_is_withheld(self):
        decision = strip_environment({"SOME_INTERNAL_THING": "value"})
        assert decision.passed == {}
        assert "SOME_INTERNAL_THING" in decision.withheld

    def test_variable_invented_tomorrow_is_withheld(self):
        # The control must hold for credential names that do not exist yet and
        # match none of the shape rules. This is why the primary control is an
        # allowlist and not a denylist.
        decision = strip_environment({"QUUX_9_DEPLOY_HANDLE": "value"})
        assert decision.passed == {}
        assert decision.withheld == ("QUUX_9_DEPLOY_HANDLE",)

    def test_empty_environment_yields_empty_sandbox(self):
        decision = strip_environment({})
        assert decision.passed == {}
        assert decision.withheld == ()

    def test_safe_variables_pass(self):
        env = {"LANG": "en_US.UTF-8", "TERM": "xterm-256color", "TZ": "UTC"}
        decision = strip_environment(env)
        assert decision.passed == env
        assert decision.withheld == ()

    def test_host_paths_do_not_cross(self):
        # HOME and PWD name host paths that do not exist in the sandbox, and
        # HOME is where credential files live.
        decision = strip_environment(
            {"HOME": "/Users/someone", "PWD": "/Users/someone/proj", "PATH": "/usr/bin"}
        )
        assert decision.passed == {}
        assert set(decision.withheld) == {"HOME", "PWD", "PATH"}

    def test_proxy_settings_are_not_inherited(self):
        # Inheriting the host's proxy configuration would let a payload reach a
        # destination other than the enforcement point.
        env = {"HTTP_PROXY": "http://evil:8080", "HTTPS_PROXY": "http://evil:8080",
               "NO_PROXY": "*", "http_proxy": "http://evil:8080"}
        decision = strip_environment(env)
        assert decision.passed == {}

    def test_registry_redirection_is_not_inherited(self):
        # These can point the package manager at a different registry, which is
        # the one thing the allowlist exists to pin down.
        env = {"npm_config_registry": "http://evil/", "PIP_INDEX_URL": "http://evil/",
               "CARGO_REGISTRIES_CRATES_IO_INDEX": "http://evil/"}
        decision = strip_environment(env)
        assert decision.passed == {}

    @pytest.mark.parametrize("name", REAL_CREDENTIAL_NAMES)
    def test_real_credential_names_are_withheld(self, name):
        decision = strip_environment({name: "sensitive-value"})
        assert decision.passed == {}
        assert name in decision.withheld

    def test_credential_value_never_appears_in_passed_environment(self):
        env = {name: f"secret-{name}" for name in REAL_CREDENTIAL_NAMES}
        env["LANG"] = "en_US.UTF-8"
        decision = strip_environment(env)
        assert decision.passed == {"LANG": "en_US.UTF-8"}
        assert not any("secret-" in v for v in decision.passed.values())

    def test_withheld_records_names_only_not_values(self):
        # The decision object is logged. It must not become a place secrets
        # accumulate.
        decision = strip_environment({"AWS_SECRET_ACCESS_KEY": "AKIAsensitive"})
        assert "AKIAsensitive" not in repr(decision)


class TestExplicitForwarding:
    def test_forwarded_variable_passes(self):
        decision = strip_environment({"BUILD_NUMBER": "42"}, forward=["BUILD_NUMBER"])
        assert decision.passed == {"BUILD_NUMBER": "42"}
        assert decision.forwarded == ("BUILD_NUMBER",)

    def test_forwarding_does_not_open_other_variables(self):
        env = {"BUILD_NUMBER": "42", "OTHER": "x"}
        decision = strip_environment(env, forward=["BUILD_NUMBER"])
        assert decision.passed == {"BUILD_NUMBER": "42"}

    @pytest.mark.parametrize("name", REAL_CREDENTIAL_NAMES)
    def test_forwarding_a_credential_fails_closed(self, name):
        # Second layer. An explicit request is not sufficient authority to put
        # a credential inside a sandbox whose purpose is having none.
        with pytest.raises(CredentialForwardError):
            strip_environment({name: "value"}, forward=[name])

    def test_forwarding_unset_variable_is_an_error(self):
        with pytest.raises(RunnerError):
            strip_environment({}, forward=["NOT_SET"])

    def test_invalid_variable_name_rejected(self):
        for bad in ("has-dash", "has space", "1LEADING", "has=equals", ""):
            with pytest.raises(RunnerError):
                strip_environment({}, forward=[bad])


class TestCredentialShape:
    @pytest.mark.parametrize("name", REAL_CREDENTIAL_NAMES)
    def test_real_credentials_are_credential_shaped(self, name):
        assert is_credential_shaped(name)

    def test_case_insensitive(self):
        assert is_credential_shaped("npm_token")
        assert is_credential_shaped("Aws_Secret_Access_Key")

    def test_benign_names_are_not_credential_shaped(self):
        for name in ("BUILD_NUMBER", "LANG", "TERM", "CI", "NODE_ENV", "TZ"):
            assert not is_credential_shaped(name), name

    def test_shape_check_never_inspects_values(self):
        # Shape only. A benign name holding a secret is a disclosed gap, not a
        # thing this function pretends to catch.
        assert not is_credential_shaped("BUILD_NUMBER")


class TestRuntimeDetection:
    def test_missing_runtime_raises_rather_than_returning_none(self):
        # Fail closed. A caller must not be able to treat absence as
        # permission to run the install directly.
        with pytest.raises(RuntimeUnavailableError):
            detect_runtime(candidates=("definitely-not-a-real-runtime",))

    def test_detects_available_runtime(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda c: "/usr/local/bin/docker" if c == "docker" else None)
        assert detect_runtime(candidates=("docker", "podman")) == "docker"

    def test_prefers_first_candidate(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda c: f"/usr/local/bin/{c}")
        assert detect_runtime(candidates=("docker", "podman")) == "docker"


class TestSafePassthroughList:
    def test_no_safe_variable_is_credential_shaped(self):
        # A contradiction between the two layers would be a hole.
        for name in SAFE_PASSTHROUGH:
            assert not is_credential_shaped(name), name


class TestProxyImageFreshness:
    """A stale proxy image would enforce a policy that is no longer on disk.

    That is not a build annoyance. The sidecar would keep applying whatever
    allowlist it was built with while the files say something else, and nothing
    would surface the mismatch.
    """

    def test_changing_an_allowlist_changes_the_image_tag(self, tmp_path):
        from blastgate.runner import proxy_image_tag

        (tmp_path / "allowlists").mkdir()
        (tmp_path / "docker").mkdir()
        (tmp_path / "proxy.py").write_text("# code\n")
        (tmp_path / "docker" / "proxy.Dockerfile").write_text("FROM scratch\n")
        allowlist = tmp_path / "allowlists" / "npm.yaml"
        allowlist.write_text("ecosystem: npm\nexact: []\n")

        before = proxy_image_tag(tmp_path)
        allowlist.write_text("ecosystem: npm\nexact: [{host: evil.test}]\n")
        after = proxy_image_tag(tmp_path)

        assert before != after

    def test_changing_source_changes_the_image_tag(self, tmp_path):
        from blastgate.runner import proxy_image_tag

        (tmp_path / "allowlists").mkdir()
        (tmp_path / "docker").mkdir()
        (tmp_path / "allowlists" / "npm.yaml").write_text("ecosystem: npm\n")
        (tmp_path / "docker" / "proxy.Dockerfile").write_text("FROM scratch\n")
        source = tmp_path / "proxy.py"
        source.write_text("# original\n")

        before = proxy_image_tag(tmp_path)
        source.write_text("# modified enforcement logic\n")
        assert proxy_image_tag(tmp_path) != before

    def test_the_tag_is_stable_when_nothing_changes(self, tmp_path):
        from blastgate.runner import proxy_image_tag

        (tmp_path / "allowlists").mkdir()
        (tmp_path / "docker").mkdir()
        (tmp_path / "allowlists" / "npm.yaml").write_text("ecosystem: npm\n")
        (tmp_path / "docker" / "proxy.Dockerfile").write_text("FROM scratch\n")
        (tmp_path / "proxy.py").write_text("# code\n")

        assert proxy_image_tag(tmp_path) == proxy_image_tag(tmp_path)


class TestUserMapping:
    """Whether to pin the container to the invoking uid, which is runtime-specific.

    Docker runs the container as root in the host's user namespace, so with
    CAP_DAC_OVERRIDE dropped it cannot write to a bind mount owned by the user.
    Rootless podman already maps the invoking user to root inside the
    container, so the same flag moves the process onto a subordinate uid that
    owns nothing.

    CI found this by regression: the flag that fixed Linux under docker broke
    Linux under podman, with the identical error message.
    """

    def test_docker_pins_the_invoking_uid(self, monkeypatch):
        import os as _os

        from blastgate.runner import user_args

        monkeypatch.setattr("blastgate.runner.podman_is_rootless", lambda r: False)
        assert user_args("docker") == ["--user", f"{_os.getuid()}:{_os.getgid()}"]

    def test_rootless_podman_is_left_alone(self, monkeypatch):
        from blastgate.runner import user_args

        monkeypatch.setattr("blastgate.runner.podman_is_rootless", lambda r: True)
        assert user_args("podman") == []

    def test_rootful_podman_pins_like_docker(self, monkeypatch):
        from blastgate.runner import user_args

        monkeypatch.setattr("blastgate.runner.podman_is_rootless", lambda r: False)
        assert user_args("podman")[0] == "--user"

    def test_an_unprobeable_runtime_falls_back_to_pinning(self, monkeypatch):
        # A runtime we cannot even ask fails later with a clearer message than
        # anything guessed here.
        from blastgate.runner import podman_is_rootless

        podman_is_rootless.cache_clear()
        monkeypatch.setattr(
            "blastgate.runner._run",
            lambda *a, **k: (_ for _ in ()).throw(OSError("not installed")),
        )
        assert podman_is_rootless("podman") is False
        podman_is_rootless.cache_clear()
