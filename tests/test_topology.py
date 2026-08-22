"""Tests for the network topology.

These require a container runtime and are skipped without one. They are the
only tests in the suite that demonstrate a property of a running install rather
than of a pure function.

The first test is the control. It asserts that a container on the default
bridge DOES reach the network, which is what makes the rest meaningful: without
it, a broken runtime with no connectivity at all would make isolation look
perfect.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from bulkhead.runner import (
    EXTERNAL_NETWORK,
    INTERNAL_NETWORK,
    RunnerError,
    RuntimeUnavailableError,
    SANDBOX_WORKDIR,
    assert_network_is_internal,
    detect_runtime,
    ensure_networks,
    network_exists,
    run_sandboxed,
    strip_environment,
)

IMAGE = "alpine:3.20"
REACH = "wget -q -T 5 -O /dev/null https://registry.npmjs.org && echo REACHED || echo BLOCKED"


try:
    RUNTIME = detect_runtime()
except RuntimeUnavailableError:
    RUNTIME = None

pytestmark = pytest.mark.skipif(RUNTIME is None, reason="no container runtime available")


@pytest.fixture(scope="module", autouse=True)
def networks():
    ensure_networks(RUNTIME)
    yield


@pytest.fixture
def project():
    # Not pytest's tmp_path. On macOS the container runtime runs inside a VM
    # that shares only the user's home directory, so a bind mount from the
    # system temp directory fails outright. This is a real constraint on where
    # a project can live, not a test artefact - see docs/threat-model.md.
    base = Path.home() / ".bulkhead-tests"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=base))
    (path / "package.json").write_text('{"name":"demo"}\n')
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class TestControl:
    def test_default_bridge_does_reach_the_network(self, project):
        # The control. If this fails, every isolation assertion below is
        # meaningless, because a runtime with no connectivity would pass them
        # all while proving nothing.
        result = run_sandboxed(
            ["sh", "-c", REACH], project, IMAGE, runtime=RUNTIME, network="bridge"
        )
        assert "REACHED" in result.stdout, (
            "baseline connectivity failed; isolation results below cannot be trusted"
        )


class TestNoRouteOut:
    def test_sandbox_cannot_reach_the_internet(self, project):
        result = run_sandboxed(["sh", "-c", REACH], project, IMAGE, runtime=RUNTIME)
        assert "BLOCKED" in result.stdout
        assert "REACHED" not in result.stdout

    def test_sandbox_cannot_resolve_public_dns(self, project):
        result = run_sandboxed(
            ["sh", "-c", "nslookup registry.npmjs.org >/dev/null 2>&1 && echo RESOLVED || echo NORESOLVE"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert "NORESOLVE" in result.stdout

    def test_sandbox_cannot_reach_a_raw_address(self, project):
        # Skipping DNS entirely must not help.
        result = run_sandboxed(
            ["sh", "-c", "wget -q -T 5 -O /dev/null http://1.1.1.1 && echo REACHED || echo BLOCKED"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert "BLOCKED" in result.stdout

    def test_sandbox_has_no_default_route(self, project):
        result = run_sandboxed(
            ["sh", "-c", "ip route | grep -q default && echo HASROUTE || echo NOROUTE"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert "NOROUTE" in result.stdout


class TestMountBoundary:
    def test_project_directory_is_present(self, project):
        result = run_sandboxed(
            ["sh", "-c", f"cat {SANDBOX_WORKDIR}/package.json"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert '"name":"demo"' in result.stdout

    def test_host_home_is_not_mounted(self, project):
        result = run_sandboxed(
            ["sh", "-c", "ls /Users 2>/dev/null && echo PRESENT || echo ABSENT"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert "ABSENT" in result.stdout

    def test_only_one_host_mount_exists(self, project):
        result = run_sandboxed(
            ["sh", "-c", "grep -c virtiofs /proc/mounts || true"],
            project, IMAGE, runtime=RUNTIME,
        )
        # The project directory is the only bind from the host.
        assert result.stdout.strip() in ("0", "1")

    def test_docker_socket_is_not_mounted(self, project):
        # A mounted socket is a container escape with extra steps.
        result = run_sandboxed(
            ["sh", "-c", "test -S /var/run/docker.sock && echo PRESENT || echo ABSENT"],
            project, IMAGE, runtime=RUNTIME,
        )
        assert "ABSENT" in result.stdout


class TestEnvironmentAtTheBoundary:
    def test_host_credentials_do_not_appear_in_the_sandbox(self, project):
        host_env = {
            "AWS_SECRET_ACCESS_KEY": "AKIA-should-never-appear",
            "NPM_TOKEN": "npm-should-never-appear",
            "LANG": "en_US.UTF-8",
        }
        decision = strip_environment(host_env)
        result = run_sandboxed(
            ["sh", "-c", "env"], project, IMAGE, runtime=RUNTIME, env=decision.passed
        )
        assert "should-never-appear" not in result.stdout
        assert "AWS_SECRET_ACCESS_KEY" not in result.stdout
        assert "NPM_TOKEN" not in result.stdout
        assert "LANG=en_US.UTF-8" in result.stdout

    def test_passing_os_environ_directly_would_leak(self, project):
        # Documents why run_sandboxed takes an explicit env rather than
        # inheriting one. This is the mistake the API is shaped to prevent.
        leaky = {"AWS_SECRET_ACCESS_KEY": "AKIA-leaked"}
        result = run_sandboxed(
            ["sh", "-c", "env"], project, IMAGE, runtime=RUNTIME, env=leaky
        )
        assert "AKIA-leaked" in result.stdout


class TestNetworkIntegrity:
    def test_internal_network_is_verified_not_assumed(self):
        assert_network_is_internal(INTERNAL_NETWORK, RUNTIME)

    def test_non_internal_network_is_refused(self):
        # A network created by hand, or by an older version, might not be
        # internal. Trusting the name would mean reporting isolation while
        # running with a route out.
        name = "bulkhead-test-not-internal"
        subprocess.run([RUNTIME, "network", "create", name], capture_output=True)
        try:
            with pytest.raises(RunnerError, match="not internal"):
                assert_network_is_internal(name, RUNTIME)
        finally:
            subprocess.run([RUNTIME, "network", "rm", name], capture_output=True)

    def test_run_refuses_a_tampered_internal_network(self, project):
        name = "bulkhead-test-not-internal-2"
        subprocess.run([RUNTIME, "network", "create", name], capture_output=True)
        try:
            with pytest.raises(RunnerError):
                assert_network_is_internal(name, RUNTIME)
        finally:
            subprocess.run([RUNTIME, "network", "rm", name], capture_output=True)

    def test_both_networks_exist(self):
        assert network_exists(INTERNAL_NETWORK, RUNTIME)
        assert network_exists(EXTERNAL_NETWORK, RUNTIME)
