"""End-to-end tests: a real install, in the sandbox, through the proxy.

These are the only tests that exercise the whole thesis at once. They need a
container runtime and are skipped without one.

The important test here is test_a_payload_that_ignores_the_proxy_is_still_blocked.
The proxy environment variables are configuration, and a payload has no reason
to honour configuration. What stops it is that there is no route out to find.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from bulkhead.audit import AuditLog
from bulkhead.policy import load_policy
from bulkhead.runner import (
    RunnerError,
    assert_audit_log_unreachable,
    default_audit_path,
    detect_runtime,
    ensure_proxy_image,
    run_install,
)

try:
    RUNTIME = detect_runtime()
except Exception:
    RUNTIME = None

pytestmark = pytest.mark.skipif(RUNTIME is None, reason="no container runtime available")

IMAGE = "python:3.12-alpine"


@pytest.fixture(scope="module", autouse=True)
def proxy_image():
    ensure_proxy_image(RUNTIME)


@pytest.fixture
def project():
    base = Path.home() / ".bulkhead-tests"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=base))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def audit(project):
    from bulkhead.runner import default_anchor_path

    path = default_audit_path(project)
    anchors = default_anchor_path(project)
    for artefact in (path, anchors):
        if artefact.exists():
            artefact.unlink()
    yield path
    for artefact in (path, anchors):
        if artefact.exists():
            artefact.unlink()


def reach(host):
    return (
        "import urllib.request as u\n"
        f"try:\n"
        f"    u.urlopen('https://{host}', timeout=10)\n"
        f"    print('REACHED')\n"
        f"except Exception as e:\n"
        f"    print('BLOCKED', type(e).__name__)\n"
    )


def install(command, project, audit, **kw):
    return run_install(
        policy=load_policy(kw.pop("ecosystem", "npm")),
        command=command,
        project_dir=project,
        image=IMAGE,
        audit_path=audit,
        host_env={},
        **kw,
    )


class TestTheWholeThing:
    def test_an_allowlisted_host_is_reachable_through_the_proxy(self, project, audit):
        result = install(["python", "-c", reach("registry.npmjs.org")], project, audit)
        assert "REACHED" in result.stdout

    def test_a_denied_host_is_not_reachable(self, project, audit):
        result = install(["python", "-c", reach("exfil.attacker.test")], project, audit)
        assert "BLOCKED" in result.stdout
        assert "REACHED" not in result.stdout

    def test_a_payload_that_ignores_the_proxy_is_still_blocked(self, project, audit):
        # The proxy variables are configuration, and a payload has no reason to
        # honour configuration. This connects directly, bypassing them entirely.
        # It fails because the topology leaves no route to find, which is the
        # difference between a setting and a control.
        script = (
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('registry.npmjs.org', 443), timeout=8)\n"
            "    print('REACHED')\n"
            "except Exception as e:\n"
            "    print('BLOCKED', type(e).__name__)\n"
        )
        result = install(["python", "-c", script], project, audit)
        assert "BLOCKED" in result.stdout

    def test_the_proxy_is_the_only_host_reachable(self, project, audit):
        script = (
            "import socket\n"
            "for target in [('bulkhead-proxy', 3128), ('1.1.1.1', 443)]:\n"
            "    try:\n"
            "        socket.create_connection(target, timeout=5); print(target[0], 'OPEN')\n"
            "    except Exception:\n"
            "        print(target[0], 'CLOSED')\n"
        )
        result = install(["python", "-c", script], project, audit)
        assert "bulkhead-proxy OPEN" in result.stdout
        assert "1.1.1.1 CLOSED" in result.stdout


class TestTheAuditLog:
    def test_both_decisions_are_recorded_and_the_chain_verifies(self, project, audit):
        script = reach("registry.npmjs.org") + reach("exfil.attacker.test")
        install(["python", "-c", script], project, audit)

        log = AuditLog(audit)
        entries = log.read_all()
        hosts = {e.host: e.allowed for e in entries}
        assert hosts.get("registry.npmjs.org") is True
        assert hosts.get("exfil.attacker.test") is False
        assert log.verify() is True

    def test_the_log_is_outside_the_project(self, project, audit):
        install(["python", "-c", reach("registry.npmjs.org")], project, audit)
        assert audit.exists()
        assert_audit_log_unreachable(audit, project)

    def test_the_sandbox_cannot_see_the_log(self, project, audit):
        # The audit directory is mounted into the proxy container and nowhere
        # else. A tamper-evident chain the payload can delete is not evidence.
        install(["python", "-c", reach("registry.npmjs.org")], project, audit)
        result = install(
            ["sh", "-c", f"test -e {audit} && echo VISIBLE || echo INVISIBLE"],
            project, audit,
        )
        assert "INVISIBLE" in result.stdout

    def test_a_log_inside_the_project_is_refused(self, project):
        # The project is mounted writable into the sandbox, so this would be a
        # log the payload could rewrite.
        with pytest.raises(RunnerError, match="payload could rewrite"):
            install(["true"], project, project / ".bulkhead" / "audit.log")


class TestARealInstall:
    def test_npm_install_succeeds_inside_the_sandbox(self, project, audit):
        (project / "package.json").write_text(
            '{"name":"demo","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}\n'
        )
        result = run_install(
            policy=load_policy("npm"),
            command=["npm", "install", "--no-audit", "--no-fund"],
            project_dir=project,
            image="node:20-alpine",
            audit_path=audit,
            host_env={},
            timeout=600,
        )
        assert result.exit_code == 0, f"install failed: {result.stderr[-800:]}"
        assert (project / "node_modules" / "is-odd").is_dir()
        assert AuditLog(audit).verify() is True


class TestAnchoring:
    """The anchor is written by the host runner, not by the proxy.

    That separation is the control. The proxy container writes the audit log
    and has the audit directory mounted; it has never seen the anchor store.
    """

    def test_a_run_writes_an_anchor(self, project, audit):
        from bulkhead.audit import AnchorStore
        from bulkhead.runner import default_anchor_path

        anchor_path = default_anchor_path(project)
        install(["python", "-c", reach("registry.npmjs.org")], project, audit)

        store = AnchorStore(anchor_path)
        assert store.verify() is True
        anchor = store.latest_for(audit)
        assert anchor is not None and anchor.entry_count >= 1
        AuditLog(audit).verify_against_anchor(anchor)

    def test_truncating_the_log_after_a_run_is_detected(self, project, audit):
        from bulkhead.audit import AnchorStore, TamperError
        from bulkhead.runner import default_anchor_path

        script = reach("registry.npmjs.org") + reach("exfil.attacker.test")
        install(["python", "-c", script], project, audit)

        anchor = AnchorStore(default_anchor_path(project)).latest_for(audit)
        lines = audit.read_text().splitlines()
        assert len(lines) >= 2
        # Drop the denial, which is exactly what an attacker would remove.
        audit.write_text("\n".join(lines[:-1]) + "\n")

        log = AuditLog(audit)
        assert log.verify() is True
        with pytest.raises(TamperError, match="truncated"):
            log.verify_against_anchor(anchor)

    def test_the_sandbox_cannot_see_the_anchor_store(self, project, audit):
        from bulkhead.runner import default_anchor_path

        anchor_path = default_anchor_path(project)
        install(["python", "-c", reach("registry.npmjs.org")], project, audit)
        result = install(
            ["sh", "-c", f"test -e {anchor_path} && echo VISIBLE || echo INVISIBLE"],
            project, audit,
        )
        assert "INVISIBLE" in result.stdout

    def test_an_anchor_beside_the_audit_log_is_refused(self, project, audit):
        # The audit directory is mounted into the proxy container. An anchor
        # there could be rewritten by the process that writes the log.
        from bulkhead.runner import RunnerError

        with pytest.raises(RunnerError, match="audit directory"):
            install(
                ["true"], project, audit,
                anchor_path=audit.parent / "sneaky.anchors",
            )


@pytest.fixture(scope="module")
def git_install():
    """One real install of a git dependency, shared by the assertions below."""
    import json as _json

    from bulkhead.runner import default_anchor_path

    base = Path.home() / ".bulkhead-tests"
    base.mkdir(parents=True, exist_ok=True)
    project = Path(tempfile.mkdtemp(dir=base))
    (project / "package.json").write_text(_json.dumps({
        "name": "demo", "version": "1.0.0",
        "dependencies": {"is-odd": "github:jonschlinkert/is-odd"},
    }) + "\n")

    audit = default_audit_path(project)
    anchors = default_anchor_path(project)
    for artefact in (audit, anchors):
        if artefact.exists():
            artefact.unlink()

    result = run_install(
        policy=load_policy("npm"),
        command=["npm", "install", "--no-audit", "--no-fund"],
        project_dir=project, audit_path=audit,
        enabled_conditions={"git-dependencies"}, host_env={}, timeout=900,
    )
    yield project, audit, result
    shutil.rmtree(project, ignore_errors=True)
    for artefact in (audit, anchors):
        if artefact.exists():
            artefact.unlink()


@pytest.mark.skipif(RUNTIME is None, reason="no container runtime available")
class TestTwoPhaseResolution:
    """The forge gap, closed by separating resolution from execution."""

    def test_a_git_dependency_installs(self, git_install):
        # The false-positive guard, and the most likely thing to break. Closing
        # a gap by breaking the feature it belonged to is not closing it.
        project, _, result = git_install
        assert result.exit_code == 0, result.stderr[-1000:]
        assert (project / "node_modules" / "is-odd").is_dir()

    def test_the_resolve_phase_did_reach_the_forge(self, git_install):
        # Otherwise the test below proves nothing: an install that never needed
        # a forge would also show no forge access during install.
        _, audit, _ = git_install
        resolve = [e for e in AuditLog(audit).read_all() if e.ecosystem == "npm-resolve"]
        assert any(e.host == "github.com" and e.allowed for e in resolve)

    def test_the_install_phase_never_reaches_a_forge(self, git_install):
        # The whole point. During the phase where package code executes, no
        # forge is allowed - including the one the dependency came from.
        _, audit, _ = git_install
        install = [e for e in AuditLog(audit).read_all() if e.ecosystem == "npm"]
        forge_allows = [
            e for e in install
            if e.allowed and ("github" in e.host or "gitlab" in e.host or "bitbucket" in e.host)
        ]
        assert not forge_allows, [(e.host, e.rule) for e in forge_allows]

    def test_a_forge_request_during_install_is_denied_and_logged(self, git_install):
        # npm does try. The denial is in the log rather than absent from it,
        # which is the difference between enforcement and never being asked.
        _, audit, _ = git_install
        install = [e for e in AuditLog(audit).read_all() if e.ecosystem == "npm"]
        denials = [e for e in install if not e.allowed]
        assert denials, "expected at least one denied request during install"

    def test_the_git_cache_is_read_only_in_the_install(self, git_install):
        # A writable cache would be a channel from the install back into the
        # phase that has forge access.
        from bulkhead.runner import CACHE_MOUNT

        project, audit, _ = git_install
        result = run_install(
            policy=load_policy("npm"),
            command=["sh", "-c", f"touch {CACHE_MOUNT}/probe 2>/dev/null && echo WRITABLE || echo READONLY"],
            project_dir=project, audit_path=audit,
            enabled_conditions={"git-dependencies"}, host_env={}, timeout=600,
        )
        assert "READONLY" in result.stdout

    def test_git_dependencies_without_the_flag_are_refused(self, git_install):
        # Fail closed. The alternative is an install that reaches a forge it
        # was never granted.
        from bulkhead.runner import UnresolvableDependencyError

        project, audit, _ = git_install
        with pytest.raises(UnresolvableDependencyError, match="resolve phase is not enabled"):
            run_install(
                policy=load_policy("npm"), command=["true"],
                project_dir=project, audit_path=audit,
                enabled_conditions=set(), host_env={}, timeout=300,
            )

    def test_the_resolve_policy_cannot_reach_the_registry(self):
        # Resolution fetches git refs. Anything reaching for the registry under
        # this policy is not resolution.
        policy = load_policy("npm-resolve")
        assert policy.evaluate("registry.npmjs.org").allowed is False
        assert policy.evaluate("github.com").allowed is True
