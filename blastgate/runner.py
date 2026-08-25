"""Container lifecycle and the boundary the install runs behind.

This module owns the topology, which is the actual security property. Two
parts:

1. What crosses the boundary. Environment filtering and runtime detection are
   pure functions with no I/O, tested exhaustively without a container runtime.

2. The topology. Two networks, of which the install container joins only the
   internal one, and a single bind mount. Demonstrated in tests/test_topology.py
   against a real runtime, with a control test asserting that a container on the
   default bridge does reach the network - without it, a runtime with no
   connectivity at all would make isolation look perfect.

3. The enforcement point as a sidecar. The proxy runs in its own container
   joined to both networks, which makes it the only route out. The install
   container reaches it by name and can reach nothing else.

4. Two-phase resolution. Git dependencies are needed during resolution; the
   payload runs during install. Those are only the same phase because nothing
   separates them, so this separates them. Declared dependencies are fetched
   first, under a policy where forges are reachable and no package code runs,
   and served during the install from a read-only mirror. The forge is not in
   the install's allowlist at all.

Deciding *what* to fetch is not here. That is resolve.py, which is pure and
therefore testable without a runtime. This module fetches, which needs
containers, and running containers is the one thing that cannot be pure.

The proxy environment variables handed to the install are configuration, and a
payload has no reason to honour them. What stops it is that there is no route to
find. See tests/test_end_to_end.py.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from blastgate import BlastgateError
from blastgate.audit import AnchorStore, AuditLog
from blastgate.resolve import (
    CACHE_MOUNT,
    GIT_CACHE_DIR,
    GIT_IMAGE,
    GITCONFIG_NAME,
    RESOLVE_ONLY_CONDITIONS,
    install_phase_conditions,
    resolve_policy_for,
    GitDependency,
    UnresolvableDependencyError,
    clone_script,
    link_bare_aliases,
    parse_git_dependencies,
    write_git_redirect_config,
)


class RunnerError(BlastgateError):
    """Base error for sandbox construction failures."""


class RuntimeUnavailableError(RunnerError):
    """Raised when no container runtime is available.

    Blastgate never falls back to unsandboxed execution. An absent runtime is a
    refusal, not a degraded mode.
    """


class CredentialForwardError(RunnerError):
    """Raised when a caller asks to forward a credential-shaped variable."""


# Environment variables passed into the sandbox by name.
#
# This is a default-deny allowlist, not a denylist of credential names. The
# distinction is the whole control: a denylist has to anticipate every
# credential variable that will ever exist, and new ones appear constantly. An
# allowlist only has to know what an install legitimately needs, which is a
# short and slow-moving list.
#
# Deliberately absent:
#   HOME, USER, PWD  - host paths and identities that do not exist in the
#                      sandbox; the container supplies its own.
#   HTTP_PROXY et al - set by blastgate to point at the enforcement point.
#                      Inheriting the host's value would be a bypass.
#   npm_config_*,    - can redirect the registry itself, which is the one
#   PIP_INDEX_URL      thing an allowlist exists to pin down.
SAFE_PASSTHROUGH = frozenset({
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
    "COLUMNS",
    "LINES",
    "NO_COLOR",
    "FORCE_COLOR",
    "CI",
    "SOURCE_DATE_EPOCH",
})

# Substrings that mark a name as credential-shaped, checked case-insensitively.
# This is the second layer, and it only ever applies to variables a user asked
# to forward explicitly. It is not the primary control.
_CREDENTIAL_SUBSTRINGS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "PRIVATE",
    "APIKEY",
    "API_KEY",
    "AUTH",
    "SESSION",
    "COOKIE",
    "SIGNATURE",
    "CERT",
    "_KEY",
    "KEY_",
)

# Prefixes belonging to systems that issue credentials. A variable under one of
# these is treated as credential-shaped even when its name looks harmless,
# because the namespace as a whole is sensitive.
_CREDENTIAL_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "GLPAT_",
    "BITBUCKET_",
    "NPM_",
    "YARN_",
    "PYPI_",
    "TWINE_",
    "CARGO_",
    "DOCKER_",
    "KUBE",
    "SSH_",
    "GPG_",
    "GNUPG_",
    "VAULT_",
    "CLOUDFLARE_",
    "CF_",
    "STRIPE_",
    "SLACK_",
    "OPENAI_",
    "ANTHROPIC_",
    "HF_",
)

# Exact names that are credential-shaped without matching the rules above.
_CREDENTIAL_EXACT = frozenset({
    "KEY",
    "PASS",
    "PWD_HASH",
    "NETRC",
    "PGPASSFILE",
    "PGUSER",
    "PGHOST",
})

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class EnvironmentDecision:
    """What was passed into the sandbox, and what was withheld."""
    passed: Dict[str, str]
    withheld: Tuple[str, ...]
    forwarded: Tuple[str, ...]


def is_credential_shaped(name: str) -> bool:
    """Report whether a variable name looks like it carries a credential.

    Shape only. This function never sees a value, and a name that looks
    harmless may still hold a secret - see docs/threat-model.md section 8.2.
    """
    if not isinstance(name, str) or not name:
        return False

    upper = name.upper()

    if upper in _CREDENTIAL_EXACT:
        return True
    if any(upper.startswith(prefix) for prefix in _CREDENTIAL_PREFIXES):
        return True
    if any(marker in upper for marker in _CREDENTIAL_SUBSTRINGS):
        return True
    # A bare trailing or leading KEY component, e.g. SIGNING-KEY or KEY2.
    if upper == "KEY" or upper.endswith("KEY") or upper.startswith("KEY"):
        return True
    return False


def strip_environment(
    env: Mapping[str, str],
    forward: Optional[Iterable[str]] = None,
) -> EnvironmentDecision:
    """Build the sandbox environment from the host environment.

    Default deny. A variable is passed only if it is in SAFE_PASSTHROUGH or the
    caller named it in `forward`. Everything else is withheld, including
    variables this code has never heard of, which is the point.

    Raises CredentialForwardError if a forwarded name is credential-shaped.
    Forwarding a credential into the sandbox defeats the control the sandbox
    exists to provide, so it fails closed rather than warning.
    """
    if env is None:
        raise RunnerError("environment must be a mapping")

    requested = list(forward or [])
    for name in requested:
        if not isinstance(name, str) or not _ENV_NAME_RE.match(name):
            raise RunnerError(f"invalid environment variable name: {name!r}")
        if is_credential_shaped(name):
            raise CredentialForwardError(
                f"refusing to forward credential-shaped variable {name!r} into "
                f"the sandbox. An install that can read a credential can "
                f"exfiltrate it."
            )

    forward_set = set(requested)
    passed: Dict[str, str] = {}
    withheld = []

    for name, value in sorted(env.items()):
        if name in SAFE_PASSTHROUGH or name in forward_set:
            passed[name] = value
        else:
            withheld.append(name)

    missing = tuple(sorted(forward_set - set(env)))
    if missing:
        raise RunnerError(
            f"cannot forward variables that are not set: {', '.join(missing)}"
        )

    return EnvironmentDecision(
        passed=passed,
        withheld=tuple(withheld),
        forwarded=tuple(sorted(forward_set)),
    )


def detect_runtime(candidates: Sequence[str] = ("docker", "podman")) -> str:
    """Return the first available container runtime.

    Raises RuntimeUnavailableError if none is present. Callers must not
    interpret the exception as permission to run the install directly.
    """
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return candidate
    raise RuntimeUnavailableError(
        "no container runtime found (looked for: "
        + ", ".join(candidates)
        + "). Blastgate will not run an install outside a sandbox."
    )


# --- Topology -------------------------------------------------------------
#
# Two networks. The install container is joined only to the internal one, which
# has no gateway, so there is no route to the internet for a payload to find.
# The proxy is the only host reachable from it, and the proxy is the only thing
# joined to both. This is a property of the topology, not a configuration
# preference: a payload cannot opt out of policy because there is nothing to
# opt out to.

# One internal network per run, so two installs cannot collide.
#
# A single shared network meant every sidecar answered to the same alias, which
# made resolution a coin toss the moment two runs overlapped: requests could be
# enforced by the wrong policy and logged to the wrong file. Refusing the second
# run made that safe but left concurrency impossible, which is fatal in CI where
# parallel jobs are the normal case.
#
# Isolating the network removes the collision structurally rather than guarding
# against it. The external network stays shared: nothing is aliased there, so
# there is nothing to collide over.
INTERNAL_NETWORK_PREFIX = "blastgate-internal"
INTERNAL_NETWORK = INTERNAL_NETWORK_PREFIX          # the unscoped default
EXTERNAL_NETWORK = "blastgate-external"

RUN_LABEL = "blastgate.run"
PID_LABEL = "blastgate.pid"


def internal_network_name(run_id: Optional[str] = None) -> str:
    """The internal network for one run, or the shared default for none."""
    if not run_id:
        return INTERNAL_NETWORK_PREFIX
    return f"{INTERNAL_NETWORK_PREFIX}-{run_id[:8]}"

SANDBOX_WORKDIR = "/workspace"


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str


def _run(argv, timeout: int = 120) -> "subprocess.CompletedProcess":
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def network_exists(name: str, runtime: str = "docker") -> bool:
    result = _run([runtime, "network", "inspect", name])
    return result.returncode == 0


def ensure_networks(runtime: str = "docker", run_id: Optional[str] = None) -> str:
    """Create this run's networks if absent. Returns the internal network name.

    The internal network is created with --internal, which is what removes the
    route out. Without that flag this whole design is decoration, so its
    absence is treated as a failure rather than a warning.

    Creation races are tolerated: two runs starting together may both try to
    create the shared external network, and losing that race is not an error so
    long as the network exists afterwards.
    """
    internal = internal_network_name(run_id)
    for name, extra in ((internal, ["--internal"]), (EXTERNAL_NETWORK, [])):
        if network_exists(name, runtime):
            continue
        result = _run([runtime, "network", "create", *extra, name])
        if result.returncode != 0 and not network_exists(name, runtime):
            raise RunnerError(f"failed to create {name}: {result.stderr.strip()}")

    assert_network_is_internal(internal, runtime)
    return internal


def assert_network_is_internal(name: str, runtime: str = "docker") -> None:
    """Verify the internal network really is internal.

    A network that already existed might have been created without --internal,
    by an earlier version of this tool or by hand. Trusting the name would mean
    running an install on a network with a route out while reporting isolation.
    """
    result = _run([runtime, "network", "inspect", "--format", "{{.Internal}}", name])
    if result.returncode != 0:
        raise RunnerError(f"cannot inspect network {name}: {result.stderr.strip()}")
    if result.stdout.strip().lower() != "true":
        raise RunnerError(
            f"network {name} exists but is not internal. Refusing to run: an "
            f"install on this network would have a route out. Remove it with "
            f"`{runtime} network rm {name}` and try again."
        )


def remove_networks(runtime: str = "docker", run_id: Optional[str] = None) -> None:
    for name in (internal_network_name(run_id), EXTERNAL_NETWORK):
        _run([runtime, "network", "rm", name])


def remove_run_network(runtime: str, run_id: str) -> None:
    """Drop one run's internal network. Safe when it is already gone."""
    _run([runtime, "network", "rm", internal_network_name(run_id)])


def run_sandboxed(
    command: Sequence[str],
    project_dir: "Path",
    image: str,
    runtime: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    network: str = INTERNAL_NETWORK,
    extra_mounts: Sequence[Tuple[Path, str, bool]] = (),
    entrypoint: Optional[str] = None,
    timeout: int = 300,
) -> SandboxResult:
    """Run a command in the sandbox.

    The project directory is the only mount. The environment is whatever the
    caller passes and nothing more - callers are expected to pass the output of
    strip_environment, and passing os.environ directly would defeat the point.
    """
    from pathlib import Path as _Path

    runtime = runtime or detect_runtime()
    project_dir = _Path(project_dir).resolve()
    if not project_dir.is_dir():
        raise RunnerError(f"project directory does not exist: {project_dir}")

    if network.startswith(INTERNAL_NETWORK_PREFIX):
        assert_network_is_internal(network, runtime)

    argv = [
        runtime, "run", "--rm",
        "--network", network,
        # The project directory is the only thing from the host that the
        # install can see.
        "--mount", f"type=bind,source={project_dir},target={SANDBOX_WORKDIR}",
        "--workdir", SANDBOX_WORKDIR,
        # Reduce what a container escape has to work with. Neither of these is
        # the isolation boundary; the boundary is the runtime itself.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]

    if entrypoint is not None:
        argv += ["--entrypoint", entrypoint]

    for source, target, readonly in extra_mounts:
        source = Path(source).resolve()
        mount = f"type=bind,source={source},target={target}"
        if readonly:
            mount += ",readonly"
        argv += ["--mount", mount]

    for name, value in (env or {}).items():
        argv += ["--env", f"{name}={value}"]

    argv += [image]
    argv += list(command)

    try:
        result = _run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RunnerError(f"sandboxed command timed out after {timeout}s")

    return SandboxResult(
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


# --- The enforcement point as a sidecar -----------------------------------
#
# The proxy runs in its own container joined to both networks. That container
# is the only member of the internal network with a route out, which is what
# makes it the only route out for the install. The install container reaches it
# by name over the internal network and cannot reach anything else.

PROXY_IMAGE_REPO = "blastgate-proxy"
PROXY_ALIAS = "blastgate-proxy"
PROXY_PORT = 3128

DEFAULT_IMAGES = {
    "npm": "node:20-alpine",
    "pypi": "python:3.12-alpine",
    "cargo": "rust:1-alpine",
}


GIT_IMAGE_REPO_PREFIX = "blastgate"


def default_image_for(ecosystem: str) -> str:
    try:
        return DEFAULT_IMAGES[ecosystem]
    except KeyError:
        raise RunnerError(
            f"no default image for ecosystem '{ecosystem}'; pass --image explicitly"
        )


def install_dockerfile_for(ecosystem: str, context: Optional[Path] = None) -> Path:
    context = Path(context) if context else _repo_root()
    return context / "docker" / f"{ecosystem}-git.Dockerfile"


def install_image_tag(ecosystem: str = "npm", context: Optional[Path] = None) -> str:
    dockerfile = install_dockerfile_for(ecosystem, context)
    digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:12]
    return f"{GIT_IMAGE_REPO_PREFIX}-{ecosystem}-git:{digest}"


def ensure_install_image(
    runtime: str, ecosystem: str = "npm", context: Optional[Path] = None
) -> str:
    """Build the git-capable image for an ecosystem if it is not already built.

    Only used when a project declares git dependencies. A project without them
    installs in the plain image and never gets a git binary it has no use for.
    """
    context = Path(context) if context else _repo_root()
    dockerfile = install_dockerfile_for(ecosystem, context)
    if not dockerfile.is_file():
        raise RunnerError(f"install Dockerfile not found at {dockerfile}")
    image = install_image_tag(ecosystem, context)
    if _run([runtime, "image", "inspect", image]).returncode == 0:
        return image
    result = _run(
        [runtime, "build", "-q", "-t", image, "-f", str(dockerfile), str(context)],
        timeout=600,
    )
    if result.returncode != 0:
        raise RunnerError(f"failed to build install image: {result.stderr.strip()}")
    return image


def assert_audit_log_unreachable(audit_path: Path, project_dir: Path) -> None:
    """Refuse to write the audit log anywhere the payload can reach.

    The project directory is mounted writable into the install container, so a
    log inside it is a log the payload can rewrite or delete. A tamper-evident
    chain is worth nothing if the attacker can simply replace the whole file,
    and a log that only survives well-behaved installs is not an audit log.
    """
    audit_path = Path(audit_path).resolve()
    project_dir = Path(project_dir).resolve()
    try:
        audit_path.relative_to(project_dir)
    except ValueError:
        return
    raise RunnerError(
        f"audit log {audit_path} is inside the project directory, which is "
        f"mounted writable into the sandbox. The payload could rewrite it. "
        f"Choose a path outside {project_dir}."
    )


def default_anchor_path(project_dir: Path) -> Path:
    """A per-project anchor store, in its own directory.

    Deliberately not beside the audit log. The audit log's directory is bind
    mounted into the proxy container, so anything in it is reachable by the
    process that writes the log. The anchor has to be somewhere that process
    cannot see, or it anchors nothing.
    """
    project_dir = Path(project_dir).resolve()
    digest = hashlib.sha256(str(project_dir).encode("utf-8")).hexdigest()[:12]
    return Path.home() / ".blastgate" / "anchors" / f"{project_dir.name}-{digest}.anchors"


def anchor_path_for_audit(audit_path: Path) -> Path:
    """The anchor store that corresponds to an audit log by convention.

    Both defaults are keyed by the same project digest, so the log's filename
    determines its anchor's filename. Used by `blast audit` to find an anchor
    without being told where it is.
    """
    return Path.home() / ".blastgate" / "anchors" / (Path(audit_path).stem + ".anchors")


def assert_anchor_store_unreachable(
    anchor_path: Path, audit_path: Path, project_dir: Path
) -> None:
    """Refuse an anchor the log's own writer could reach.

    Two ways that happens: the anchor sits in the audit directory, which is
    mounted into the proxy container, or it sits in the project directory,
    which is mounted into the install container. Either makes the anchor
    forgeable by the thing it exists to check.
    """
    anchor_path = Path(anchor_path).resolve()
    audit_dir = Path(audit_path).resolve().parent
    project_dir = Path(project_dir).resolve()

    if anchor_path.parent == audit_dir:
        raise RunnerError(
            f"anchor store {anchor_path} is in the audit directory, which is "
            f"mounted into the proxy container. The process that writes the log "
            f"could rewrite its own anchor. Choose a path outside {audit_dir}."
        )
    try:
        anchor_path.relative_to(project_dir)
    except ValueError:
        return
    raise RunnerError(
        f"anchor store {anchor_path} is inside the project directory, which is "
        f"mounted writable into the sandbox. Choose a path outside {project_dir}."
    )


def default_audit_path(project_dir: Path) -> Path:
    """A per-project log outside the project, so the sandbox cannot reach it."""
    project_dir = Path(project_dir).resolve()
    digest = hashlib.sha256(str(project_dir).encode("utf-8")).hexdigest()[:12]
    return Path.home() / ".blastgate" / "audit" / f"{project_dir.name}-{digest}.log"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def proxy_image_tag(context: Optional[Path] = None) -> str:
    """Tag the proxy image by the content that goes into it.

    A fixed tag lets the image go stale. That is not a build annoyance, it is a
    security bug: the sidecar would keep enforcing whatever allowlist it was
    built with while the files on disk say something else, and the mismatch is
    invisible. Deriving the tag from the sources means changing a policy
    changes the tag, and a tag that does not exist gets built.
    """
    context = Path(context) if context else _repo_root()
    digest = hashlib.sha256()
    sources = sorted(
        list((context / "blastgate").glob("*.py"))
        + list((context / "allowlists").glob("*.yaml"))
        + [context / "docker" / "proxy.Dockerfile"]
    )
    for path in sources:
        if path.is_file():
            digest.update(path.name.encode("utf-8"))
            digest.update(path.read_bytes())
    return f"{PROXY_IMAGE_REPO}:{digest.hexdigest()[:12]}"


def proxy_image_exists(runtime: str, image: Optional[str] = None) -> bool:
    return _run([runtime, "image", "inspect", image or proxy_image_tag()]).returncode == 0


def build_proxy_image(runtime: str, context: Optional[Path] = None) -> str:
    context = Path(context) if context else _repo_root()
    dockerfile = context / "docker" / "proxy.Dockerfile"
    if not dockerfile.is_file():
        raise RunnerError(f"proxy Dockerfile not found at {dockerfile}")
    image = proxy_image_tag(context)
    result = _run(
        [runtime, "build", "-q", "-t", image, "-f", str(dockerfile), str(context)],
        timeout=600,
    )
    if result.returncode != 0:
        raise RunnerError(f"failed to build proxy image: {result.stderr.strip()}")
    return image


def ensure_proxy_image(runtime: str, context: Optional[Path] = None) -> str:
    """Build the proxy image if the current sources have not been built yet."""
    image = proxy_image_tag(context)
    if not proxy_image_exists(runtime, image):
        return build_proxy_image(runtime, context)
    return image


def existing_proxy_containers(runtime: str, network: Optional[str] = None) -> List[str]:
    """Proxy containers attached to one internal network."""
    result = _run([
        runtime, "network", "inspect", network or INTERNAL_NETWORK,
        "--format", "{{range .Containers}}{{.Name}} {{end}}",
    ])
    if result.returncode != 0:
        return []
    return sorted(n for n in result.stdout.split() if n.startswith(f"{PROXY_IMAGE_REPO}-"))


def assert_no_stale_proxy(runtime: str, network: Optional[str] = None) -> None:
    """Refuse to start a second sidecar on the internal network.

    Every sidecar answers to the same network alias, so two of them make
    resolution a coin toss. That is not a cosmetic clash. The other container
    enforces whatever policy it was started with, and writes its decisions to
    whatever audit path it was given - which may be a directory that no longer
    exists. An install could then be refused by a policy nobody chose, or worse,
    allowed by one, with the decision recorded somewhere the user never reads.

    This happens after a run is killed rather than exiting: the container is
    started with --rm but nothing removes it if the process supervising it dies
    first.

    Refusing rather than removing it. A running sidecar may belong to another
    install in progress, and killing that one would drop its enforcement
    mid-flight.
    """
    network = network or INTERNAL_NETWORK
    existing = existing_proxy_containers(runtime, network)
    if not existing:
        return
    names = " ".join(existing)
    raise RunnerError(
        f"a blastgate proxy is already attached to {network}: {names}. "
        f"Two sidecars share one network alias, so requests would be routed to "
        f"either one and decisions could be enforced by the wrong policy and "
        f"logged to the wrong file. If another install is running, wait for it. "
        f"If one was left behind by a killed run, remove it with: "
        f"{runtime} rm -f {names}"
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # alive, owned by someone else, not ours to reap
    return True


def orphaned_sidecars(runtime: str) -> List[Tuple[str, str]]:
    """Sidecars whose supervising process is gone. Returns (container, run_id).

    A sidecar is started with --rm, which does nothing when the process
    supervising it is killed rather than allowed to exit. One survived a
    cancelled run here for two hours. Recording the supervising pid on the
    container is what makes that detectable afterwards.

    A reused pid can only leave a dead sidecar looking alive, never make a live
    one look dead, so the failure mode is leaking rather than killing someone
    else's install.
    """
    fmt = '{{.ID}}\t{{.Label "' + PID_LABEL + '"}}\t{{.Label "' + RUN_LABEL + '"}}'
    result = _run([runtime, "ps", "-a", "--filter", f"label={PID_LABEL}", "--format", fmt])
    if result.returncode != 0:
        return []
    orphans: List[Tuple[str, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        container, raw_pid, run_id = parts
        try:
            pid = int(raw_pid)
        except ValueError:
            continue
        if not _pid_alive(pid):
            orphans.append((container, run_id))
    return orphans


def reap_orphaned_sidecars(runtime: str) -> List[str]:
    """Remove sidecars left by killed runs, and the networks they held."""
    removed = []
    for container, run_id in orphaned_sidecars(runtime):
        _run([runtime, "rm", "-f", container], timeout=30)
        if run_id:
            remove_run_network(runtime, run_id)
        removed.append(container)
    return removed


def lock_path(project_dir: Path) -> Path:
    project_dir = Path(project_dir).resolve()
    digest = hashlib.sha256(str(project_dir).encode("utf-8")).hexdigest()[:12]
    return Path.home() / ".blastgate" / "locks" / f"{project_dir.name}-{digest}.lock"


@contextmanager
def project_lock(project_dir: Path):
    """Refuse a second concurrent run against the same project.

    Different projects run in parallel freely; this is not about the network.
    It is about the audit log. Appending reads the whole chain, verifies it and
    writes a new tail, so two runs sharing one log interleave and produce a
    chain that no longer verifies - turning a tamper-evident record into a
    false alarm.

    flock is released by the kernel when the process dies, so a killed run
    frees its own lock rather than wedging the next one.
    """
    path = lock_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "w")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise RunnerError(
            f"another blastgate run is already active for "
            f"{Path(project_dir).resolve()}. Runs against different projects are "
            f"fine in parallel; two against the same one would interleave writes "
            f"to a single audit log and break its chain. Wait for the other run."
        )
    try:
        yield path
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class ProxySidecar:
    """The proxy container, joined to both networks.

    Started on the internal network and then connected to the external one, so
    that at no point is the install container's network able to reach anything
    except this container.
    """

    def __init__(
        self,
        ecosystem: str,
        audit_path: Path,
        runtime: str,
        enabled_conditions: Optional[Set[str]] = None,
        name: Optional[str] = None,
        image: Optional[str] = None,
        network: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> None:
        self.run_id = run_id or uuid.uuid4().hex
        self.network = network or INTERNAL_NETWORK
        self.image = image or proxy_image_tag()
        self.ecosystem = ecosystem
        self.audit_path = Path(audit_path).resolve()
        self.runtime = runtime
        self.enabled_conditions = set(enabled_conditions or ())
        self.name = name or f"blastgate-proxy-{uuid.uuid4().hex[:8]}"
        self._started = False

    def start(self) -> "ProxySidecar":
        assert_no_stale_proxy(self.runtime, self.network)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        argv = [
            self.runtime, "run", "-d", "--rm",
            "--name", self.name,
            "--network", self.network,
            "--network-alias", PROXY_ALIAS,
            # The supervising pid is what makes an abandoned sidecar
            # identifiable later. --rm does not fire when this process is
            # killed rather than allowed to exit.
            "--label", f"{RUN_LABEL}={self.run_id}",
            "--label", f"{PID_LABEL}={os.getpid()}",
            # The audit directory is mounted here and nowhere else. The install
            # container has no path to it.
            "--mount", f"type=bind,source={self.audit_path.parent},target=/audit",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            self.image,
            "proxy", self.ecosystem,
            "--port", str(PROXY_PORT),
            "--bind", "0.0.0.0",
            "--audit", f"/audit/{self.audit_path.name}",
        ]
        for condition in sorted(self.enabled_conditions):
            argv += ["--allow", condition]

        result = _run(argv)
        if result.returncode != 0:
            raise RunnerError(f"could not start proxy sidecar: {result.stderr.strip()}")
        self._started = True

        # Join the external network only after the container exists, so the
        # order of operations never leaves the install container on a network
        # with a route out.
        result = _run([self.runtime, "network", "connect", EXTERNAL_NETWORK, self.name])
        if result.returncode != 0:
            self.stop()
            raise RunnerError(
                f"could not join proxy to {EXTERNAL_NETWORK}: {result.stderr.strip()}"
            )

        self._wait_until_listening()
        return self

    def _wait_until_listening(self, attempts: int = 40, delay: float = 0.25) -> None:
        probe = (
            "import socket,sys\n"
            f"s=socket.socket()\ns.settimeout(1)\n"
            f"sys.exit(s.connect_ex(('127.0.0.1',{PROXY_PORT})))\n"
        )
        for _ in range(attempts):
            result = _run(
                [self.runtime, "exec", self.name, "python", "-c", probe], timeout=10
            )
            if result.returncode == 0:
                return
            time.sleep(delay)
        logs = _run([self.runtime, "logs", self.name]).stdout
        self.stop()
        raise RunnerError(
            f"proxy sidecar did not start listening on port {PROXY_PORT}. "
            f"Refusing to run an install without an enforcement point. "
            f"Container output: {logs.strip() or '(none)'}"
        )

    def logs(self) -> str:
        result = _run([self.runtime, "logs", self.name])
        return result.stdout + result.stderr

    def stop(self) -> None:
        if self._started:
            _run([self.runtime, "kill", self.name], timeout=30)
            self._started = False

    def __enter__(self) -> "ProxySidecar":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


PROXY_URL = f"http://{PROXY_ALIAS}:{PROXY_PORT}"

PROXY_ENV = {
    "HTTP_PROXY": PROXY_URL,
    "HTTPS_PROXY": PROXY_URL,
    "http_proxy": PROXY_URL,
    "https_proxy": PROXY_URL,
    "npm_config_proxy": PROXY_URL,
    "npm_config_https_proxy": PROXY_URL,
    "PIP_PROXY": PROXY_URL,
    # No exemptions. A populated NO_PROXY would be a hole in the allowlist that
    # policy never sees.
    "NO_PROXY": "",
    "no_proxy": "",
}


def run_install(
    policy,
    command: Sequence[str],
    project_dir: Path,
    image: Optional[str] = None,
    audit_path: Optional[Path] = None,
    anchor_path: Optional[Path] = None,
    enabled_conditions: Optional[Set[str]] = None,
    runtime: Optional[str] = None,
    host_env: Optional[Mapping[str, str]] = None,
    git_cache_dir: Optional[Path] = None,
    timeout: int = 600,
) -> SandboxResult:
    """Run an install in the sandbox with the proxy as its only route out.

    Every failure path raises rather than falling back. There is no branch here
    that runs the command without the enforcement point in place.
    """
    runtime = runtime or detect_runtime()
    project_dir = Path(project_dir).resolve()
    audit_path = Path(audit_path) if audit_path else default_audit_path(project_dir)
    anchor_path = Path(anchor_path) if anchor_path else default_anchor_path(project_dir)

    assert_audit_log_unreachable(audit_path, project_dir)
    assert_anchor_store_unreachable(anchor_path, audit_path, project_dir)

    explicit_image = image is not None
    enabled_conditions = set(enabled_conditions or ())

    run_id = uuid.uuid4().hex

    # Everything below runs under a per-project lock, on a network of this
    # run's own. Different projects run in parallel; the same project does not,
    # because both runs would append to one audit log and interleave its chain
    # into something that no longer verifies.
    with project_lock(project_dir):
        # A sidecar from a killed run can no longer serve this one, now that
        # networks are per-run, but it is still a leaked container holding a
        # leaked network. Clear those before adding more.
        reap_orphaned_sidecars(runtime)
        network = ensure_networks(runtime, run_id)
        try:
            # Resolve phase. Anything declared is fetched now, while no project code is
            # running, and served locally during the install.
            dependencies = parse_git_dependencies(project_dir, policy.ecosystem)
            cache_dir = Path(git_cache_dir or GIT_CACHE_DIR).resolve()
            if dependencies:
                if not (enabled_conditions & RESOLVE_ONLY_CONDITIONS):
                    names = ", ".join(sorted({d.name for d in dependencies}))
                    raise UnresolvableDependencyError(
                        f"this project declares git dependencies ({names}) and the "
                        f"resolve phase is not enabled. Re-run with "
                        f"--allow git-dependencies, which fetches them before the "
                        f"install starts rather than opening a forge to it."
                    )
                resolve_git_dependencies(
                    dependencies, audit_path=audit_path, ecosystem=policy.ecosystem,
                    runtime=runtime, cache_dir=cache_dir, network=network,
                    run_id=run_id, timeout=timeout,
                )

            if explicit_image:
                pass
            elif dependencies:
                # Every one of these package managers shells out to git even when the
                # repository is already local, and none of the base images ships it.
                image = ensure_install_image(runtime, policy.ecosystem)
            else:
                image = default_image_for(policy.ecosystem)

            # For npm the forge is not reachable from the install, whatever the user
            # enabled: git-dependencies permits the resolve phase and grants the install
            # nothing. Other ecosystems have no resolve phase yet, so the condition
            # keeps its older meaning there and the forge gap stays open for them.
            install_conditions = install_phase_conditions(policy.ecosystem, enabled_conditions)
            if install_conditions & RESOLVE_ONLY_CONDITIONS:
                sys.stderr.write(
                    f"blast: warning: {policy.ecosystem} has no resolve phase, so code "
                    f"forges stay reachable for the whole install. A payload that "
                    f"reaches one can exfiltrate through it. See threat-model 8.1.\n"
                )

            image_tag = ensure_proxy_image(runtime)

            env = dict(strip_environment(host_env if host_env is not None else os.environ).passed)
            env.update(PROXY_ENV)

            extra_mounts: List[Tuple[Path, str, bool]] = []
            if dependencies:
                # Read-only. A writable cache would be a channel from the install back
                # into the phase that has forge access.
                extra_mounts.append((cache_dir, CACHE_MOUNT, True))
                env["GIT_CONFIG_GLOBAL"] = f"{CACHE_MOUNT}/{GITCONFIG_NAME}"
                env["GIT_TERMINAL_PROMPT"] = "0"
                # cargo fetches with libgit2 by default, which ignores url.insteadOf.
                # Without this the rewrite is silently skipped and cargo dials the
                # forge it is not allowed to reach.
                env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"

            with ProxySidecar(
                policy.ecosystem,
                audit_path=audit_path,
                runtime=runtime,
                enabled_conditions=install_conditions,
                image=image_tag,
                network=network,
                run_id=run_id,
            ):
                result = run_sandboxed(
                    command,
                    project_dir,
                    image,
                    runtime=runtime,
                    env=env,
                    network=network,
                    extra_mounts=extra_mounts,
                    timeout=timeout,
                )

            # Anchored here, on the host, after the sidecar is gone. A different
            # process from the one that wrote the log, writing to a store that process
            # never had mounted.
            AnchorStore(anchor_path).append(run_id, audit_path, AuditLog(audit_path).read_all())
            return result
        finally:
            # This network belongs to this run; nothing else can be using it.
            remove_run_network(runtime, run_id)



def resolve_git_dependencies(
    dependencies: Sequence[GitDependency],
    audit_path: Path,
    ecosystem: str = "npm",
    runtime: Optional[str] = None,
    cache_dir: Path = GIT_CACHE_DIR,
    image: str = GIT_IMAGE,
    network: Optional[str] = None,
    run_id: Optional[str] = None,
    timeout: int = 600,
) -> SandboxResult:
    """Fetch declared git dependencies with no project code present.

    Runs under allowlists/npm-resolve.yaml, where forges are reachable and the
    registry is not. The project directory is deliberately NOT mounted: this
    phase needs the manifest's conclusions, not its contents, and mounting it
    would put attacker-influenced files next to the one process in the design
    that can reach a forge.
    """
    from blastgate.policy import load_policy

    runtime = runtime or detect_runtime()
    cache_dir = Path(cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)

    network = network or ensure_networks(runtime, run_id)
    image_tag = ensure_proxy_image(runtime)

    policy = load_policy(resolve_policy_for(ecosystem))
    env = dict(PROXY_ENV)
    # Nothing to authenticate with. Any credential prompt is a hang, not a
    # login, so fail instead of waiting.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/true"

    with ProxySidecar(
        policy.ecosystem, audit_path=audit_path, runtime=runtime, image=image_tag,
        network=network, run_id=run_id,
    ):
        result = run_sandboxed(
            ["-c", clone_script(dependencies)],
            cache_dir, image, runtime=runtime, env=env,
            network=network, entrypoint="sh", timeout=timeout,
        )

    if result.exit_code != 0 or "RESOLVE_OK" not in result.stdout:
        raise UnresolvableDependencyError(
            "resolve phase failed, so the install would need a forge it cannot "
            "reach. Refusing to run.\n"
            + (result.stderr.strip() or result.stdout.strip())[-800:]
        )

    link_bare_aliases(cache_dir, dependencies)
    write_git_redirect_config(cache_dir, (d.host for d in dependencies))
    return result
