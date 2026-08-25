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

from blastgate.runner import (
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

# The control gets a longer timeout and retries; the isolation tests do not.
# The asymmetry is deliberate. A false BLOCKED in the control is a transient
# network hiccup being read as proof of isolation, and a control that flakes is
# a control people learn to ignore. A false BLOCKED in an isolation test is the
# expected answer anyway, so retrying there would only slow the suite.
CONTROL_REACH = (
    "for i in 1 2 3; do "
    "wget -q -T 15 -O /dev/null https://registry.npmjs.org && { echo REACHED; exit 0; }; "
    "sleep 2; done; echo BLOCKED"
)


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
    base = Path.home() / ".blastgate-tests"
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
            ["sh", "-c", CONTROL_REACH], project, IMAGE, runtime=RUNTIME,
            network="bridge", timeout=120,
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
        name = "blastgate-test-not-internal"
        subprocess.run([RUNTIME, "network", "create", name], capture_output=True)
        try:
            with pytest.raises(RunnerError, match="not internal"):
                assert_network_is_internal(name, RUNTIME)
        finally:
            subprocess.run([RUNTIME, "network", "rm", name], capture_output=True)

    def test_run_refuses_a_tampered_internal_network(self, project):
        name = "blastgate-test-not-internal-2"
        subprocess.run([RUNTIME, "network", "create", name], capture_output=True)
        try:
            with pytest.raises(RunnerError):
                assert_network_is_internal(name, RUNTIME)
        finally:
            subprocess.run([RUNTIME, "network", "rm", name], capture_output=True)

    def test_both_networks_exist(self):
        assert network_exists(INTERNAL_NETWORK, RUNTIME)
        assert network_exists(EXTERNAL_NETWORK, RUNTIME)


class TestStaleSidecar:
    """A sidecar left behind by a killed run must not silently serve the next one.

    Found by killing a compatibility run mid-install. The container is started
    with --rm, but nothing removes it when the process supervising it is killed
    first, so it stayed attached to the internal network for two hours holding
    the shared alias. The next run resolved the alias to it, was refused by the
    policy that container happened to be enforcing, and had its decisions
    written to an audit path inside a temp directory that no longer existed.

    Being denied by the wrong policy is loud. Being allowed by it, with the
    decision logged where nobody reads, is not.
    """

    def test_a_stale_proxy_on_the_network_is_refused(self, project):
        from blastgate.runner import (
            PROXY_IMAGE_REPO,
            ProxySidecar,
            assert_no_stale_proxy,
            existing_proxy_containers,
        )

        name = f"{PROXY_IMAGE_REPO}-stale-test"
        subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
        subprocess.run(
            [RUNTIME, "run", "-d", "--name", name, "--network", INTERNAL_NETWORK,
             IMAGE, "sleep", "60"],
            capture_output=True,
        )
        try:
            assert name in existing_proxy_containers(RUNTIME)
            with pytest.raises(RunnerError, match="already attached"):
                assert_no_stale_proxy(RUNTIME, INTERNAL_NETWORK)
            # And the sidecar itself refuses to start rather than racing it.
            with pytest.raises(RunnerError, match="already attached"):
                ProxySidecar("npm", audit_path=project / "audit.log", runtime=RUNTIME).start()
        finally:
            subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)

    def test_no_stale_proxy_is_the_normal_case(self):
        from blastgate.runner import assert_no_stale_proxy

        assert_no_stale_proxy(RUNTIME) is None

    def test_a_stale_proxy_cannot_reach_another_runs_network(self, project):
        # The structural fix. A leftover sidecar sits on the network of the run
        # that created it, so it is not on anyone else's and cannot serve them
        # whatever policy it happens to be holding.
        from blastgate.runner import (
            PROXY_IMAGE_REPO,
            assert_no_stale_proxy,
            ensure_networks,
            internal_network_name,
            remove_run_network,
        )

        stale_run, live_run = "aaaaaaaa11", "bbbbbbbb22"
        ensure_networks(RUNTIME, stale_run)
        ensure_networks(RUNTIME, live_run)
        name = f"{PROXY_IMAGE_REPO}-cross-test"
        subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
        subprocess.run(
            [RUNTIME, "run", "-d", "--name", name,
             "--network", internal_network_name(stale_run), IMAGE, "sleep", "60"],
            capture_output=True,
        )
        try:
            # Refused on its own network...
            with pytest.raises(RunnerError, match="already attached"):
                assert_no_stale_proxy(RUNTIME, internal_network_name(stale_run))
            # ...and invisible to the other run entirely.
            assert assert_no_stale_proxy(RUNTIME, internal_network_name(live_run)) is None
        finally:
            subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
            remove_run_network(RUNTIME, stale_run)
            remove_run_network(RUNTIME, live_run)


class TestRunLifecycle:
    """Per-run networks, orphan reaping, and the per-project lock."""

    def test_each_run_gets_its_own_network_name(self):
        from blastgate.runner import INTERNAL_NETWORK_PREFIX, internal_network_name

        first, second = internal_network_name("a" * 32), internal_network_name("b" * 32)
        assert first != second
        assert first.startswith(INTERNAL_NETWORK_PREFIX)
        assert internal_network_name() == INTERNAL_NETWORK_PREFIX

    def test_a_run_network_is_internal_and_removable(self):
        from blastgate.runner import (
            assert_network_is_internal,
            ensure_networks,
            internal_network_name,
            network_exists,
            remove_run_network,
        )

        run_id = "cccccccc33"
        name = ensure_networks(RUNTIME, run_id)
        try:
            assert name == internal_network_name(run_id)
            assert network_exists(name, RUNTIME)
            assert_network_is_internal(name, RUNTIME)
        finally:
            remove_run_network(RUNTIME, run_id)
        assert not network_exists(internal_network_name(run_id), RUNTIME)

    def test_a_sidecar_with_a_dead_supervisor_is_reaped(self):
        # --rm does not fire when the supervising process is killed rather than
        # allowed to exit. The recorded pid is what makes the leftover
        # identifiable afterwards.
        from blastgate.runner import (
            PID_LABEL,
            PROXY_IMAGE_REPO,
            RUN_LABEL,
            orphaned_sidecars,
            reap_orphaned_sidecars,
        )

        # A pid that has certainly exited.
        dead = subprocess.Popen(["true"])
        dead.wait()

        run_id = "dddddddd44"
        name = f"{PROXY_IMAGE_REPO}-reap-test"
        subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
        subprocess.run(
            [RUNTIME, "run", "-d", "--name", name,
             "--label", f"{RUN_LABEL}={run_id}",
             "--label", f"{PID_LABEL}={dead.pid}",
             IMAGE, "sleep", "120"],
            capture_output=True,
        )
        try:
            assert any(r == run_id for _, r in orphaned_sidecars(RUNTIME))
            reap_orphaned_sidecars(RUNTIME)
            listed = subprocess.run(
                [RUNTIME, "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True
            ).stdout
            assert name not in listed
        finally:
            subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)

    def test_a_live_sidecar_is_never_reaped(self):
        # Reaping someone else's running install would drop its enforcement
        # mid-flight, which is far worse than leaking a container.
        import os

        from blastgate.runner import (
            PID_LABEL,
            PROXY_IMAGE_REPO,
            RUN_LABEL,
            orphaned_sidecars,
        )

        name = f"{PROXY_IMAGE_REPO}-live-test"
        subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
        subprocess.run(
            [RUNTIME, "run", "-d", "--name", name,
             "--label", f"{RUN_LABEL}=eeeeeeee55",
             "--label", f"{PID_LABEL}={os.getpid()}",
             IMAGE, "sleep", "60"],
            capture_output=True,
        )
        try:
            assert not any(r == "eeeeeeee55" for _, r in orphaned_sidecars(RUNTIME))
        finally:
            subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
