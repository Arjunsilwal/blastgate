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

The proxy environment variables handed to the install are configuration, and a
payload has no reason to honour them. What stops it is that there is no route to
find. See tests/test_end_to_end.py.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
import uuid
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from bulkhead.audit import AnchorStore, AuditLog


class RunnerError(Exception):
    """Base error for sandbox construction failures."""


class RuntimeUnavailableError(RunnerError):
    """Raised when no container runtime is available.

    Bulkhead never falls back to unsandboxed execution. An absent runtime is a
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
#   HTTP_PROXY et al - set by bulkhead to point at the enforcement point.
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
        + "). Bulkhead will not run an install outside a sandbox."
    )


# --- Topology -------------------------------------------------------------
#
# Two networks. The install container is joined only to the internal one, which
# has no gateway, so there is no route to the internet for a payload to find.
# The proxy is the only host reachable from it, and the proxy is the only thing
# joined to both. This is a property of the topology, not a configuration
# preference: a payload cannot opt out of policy because there is nothing to
# opt out to.

INTERNAL_NETWORK = "bulkhead-internal"
EXTERNAL_NETWORK = "bulkhead-external"

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


def ensure_networks(runtime: str = "docker") -> None:
    """Create the two networks if they do not exist.

    The internal network is created with --internal, which is what removes the
    route out. Without that flag this whole design is decoration, so its
    absence is treated as a failure rather than a warning.
    """
    if not network_exists(INTERNAL_NETWORK, runtime):
        result = _run([runtime, "network", "create", "--internal", INTERNAL_NETWORK])
        if result.returncode != 0:
            raise RunnerError(f"failed to create {INTERNAL_NETWORK}: {result.stderr.strip()}")

    if not network_exists(EXTERNAL_NETWORK, runtime):
        result = _run([runtime, "network", "create", EXTERNAL_NETWORK])
        if result.returncode != 0:
            raise RunnerError(f"failed to create {EXTERNAL_NETWORK}: {result.stderr.strip()}")

    assert_network_is_internal(INTERNAL_NETWORK, runtime)


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


def remove_networks(runtime: str = "docker") -> None:
    for name in (INTERNAL_NETWORK, EXTERNAL_NETWORK):
        _run([runtime, "network", "rm", name])


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

    if network == INTERNAL_NETWORK:
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

PROXY_IMAGE_REPO = "bulkhead-proxy"
PROXY_ALIAS = "bulkhead-proxy"
PROXY_PORT = 3128

DEFAULT_IMAGES = {
    "npm": "node:20-alpine",
    "pypi": "python:3.12-alpine",
    "cargo": "rust:1-alpine",
}


NPM_GIT_IMAGE_REPO = "bulkhead-npm-git"


def default_image_for(ecosystem: str) -> str:
    try:
        return DEFAULT_IMAGES[ecosystem]
    except KeyError:
        raise RunnerError(
            f"no default image for ecosystem '{ecosystem}'; pass --image explicitly"
        )


def install_image_tag(context: Optional[Path] = None) -> str:
    context = Path(context) if context else _repo_root()
    dockerfile = context / "docker" / "npm-git.Dockerfile"
    digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:12]
    return f"{NPM_GIT_IMAGE_REPO}:{digest}"


def ensure_install_image(runtime: str, context: Optional[Path] = None) -> str:
    """Build the git-capable npm image if it is not already built.

    Only used when a project declares git dependencies. A project without them
    installs in the plain image and never gets a git binary it has no use for.
    """
    context = Path(context) if context else _repo_root()
    dockerfile = context / "docker" / "npm-git.Dockerfile"
    if not dockerfile.is_file():
        raise RunnerError(f"install Dockerfile not found at {dockerfile}")
    image = install_image_tag(context)
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
    return Path.home() / ".bulkhead" / "anchors" / f"{project_dir.name}-{digest}.anchors"


def anchor_path_for_audit(audit_path: Path) -> Path:
    """The anchor store that corresponds to an audit log by convention.

    Both defaults are keyed by the same project digest, so the log's filename
    determines its anchor's filename. Used by `bh audit` to find an anchor
    without being told where it is.
    """
    return Path.home() / ".bulkhead" / "anchors" / (Path(audit_path).stem + ".anchors")


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
    return Path.home() / ".bulkhead" / "audit" / f"{project_dir.name}-{digest}.log"


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
        list((context / "bulkhead").glob("*.py"))
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
    ) -> None:
        self.image = image or proxy_image_tag()
        self.ecosystem = ecosystem
        self.audit_path = Path(audit_path).resolve()
        self.runtime = runtime
        self.enabled_conditions = set(enabled_conditions or ())
        self.name = name or f"bulkhead-proxy-{uuid.uuid4().hex[:8]}"
        self._started = False

    def start(self) -> "ProxySidecar":
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        argv = [
            self.runtime, "run", "-d", "--rm",
            "--name", self.name,
            "--network", INTERNAL_NETWORK,
            "--network-alias", PROXY_ALIAS,
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

    # Resolve phase. Anything declared is fetched now, while no project code is
    # running, and served locally during the install.
    dependencies = parse_git_dependencies(project_dir)
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
            dependencies, audit_path=audit_path, runtime=runtime,
            cache_dir=cache_dir, timeout=timeout,
        )

    if explicit_image:
        pass
    elif dependencies and policy.ecosystem == "npm":
        # npm shells out to git even for an already-local repository.
        image = ensure_install_image(runtime)
    else:
        image = default_image_for(policy.ecosystem)

    # The forge is not reachable from the install, whatever the user enabled.
    # git-dependencies permits the resolve phase; it does not open a host to
    # code that is about to execute.
    install_conditions = enabled_conditions - RESOLVE_ONLY_CONDITIONS

    ensure_networks(runtime)
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

    run_id = uuid.uuid4().hex

    with ProxySidecar(
        policy.ecosystem,
        audit_path=audit_path,
        runtime=runtime,
        enabled_conditions=install_conditions,
        image=image_tag,
    ):
        result = run_sandboxed(
            command,
            project_dir,
            image,
            runtime=runtime,
            env=env,
            network=INTERNAL_NETWORK,
            extra_mounts=extra_mounts,
            timeout=timeout,
        )

    # Anchored here, on the host, after the sidecar is gone. A different
    # process from the one that wrote the log, writing to a store that process
    # never had mounted.
    AnchorStore(anchor_path).append(run_id, audit_path, AuditLog(audit_path).read_all())
    return result


# --- Resolve phase: what to fetch -----------------------------------------
#
# Git dependencies are needed during resolution. The payload runs during
# install. Those are only the same phase because nothing separates them, so
# this separates them.
#
# Everything below decides WHAT to fetch by reading files. It executes nothing
# and it runs before any container exists. Anything it cannot parse with
# confidence is refused rather than guessed at, because a guess here turns into
# either a missing dependency or an unexpected host.

GIT_CACHE_DIR = Path.home() / ".bulkhead" / "git-cache"

# Hosts a declared dependency may be fetched from during resolution. Kept in
# step with allowlists/npm-resolve.yaml; policy is still the decider, this is
# only used to reject a spec early with a clearer message.
RESOLVABLE_FORGES = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

FORGE_PREFIXES = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}

# The condition that no longer opens a forge to the install. It permits the
# resolve phase to run instead.
RESOLVE_ONLY_CONDITIONS = frozenset({"git-dependencies"})

_GIT_HTTPS_RE = re.compile(
    r"^(?:git\+)?https://(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
# npm writes ssh forms into lockfiles as a matter of course. Fetching is done
# over https regardless: the repository is the same, the transport is one the
# proxy can enforce, and no key is present to authenticate with anyway.
_GIT_SSH_RE = re.compile(
    r"^(?:git\+)?ssh://git@(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_GIT_SCP_RE = re.compile(
    r"^git@(?P<host>[A-Za-z0-9.-]+):(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_SHORTHAND_RE = re.compile(
    r"^(?:(?P<forge>github|gitlab|bitbucket):)?"
    r"(?P<path>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_UNENCRYPTED_RE = re.compile(r"^(?:git\+)?git://")


class UnresolvableDependencyError(RunnerError):
    """A declared git dependency cannot be fetched safely.

    Raised rather than skipped. Skipping would leave the install to discover
    the dependency itself, at which point it needs a forge that is deliberately
    unreachable, and the failure would surface as something less clear.
    """


@dataclass(frozen=True)
class GitDependency:
    name: str
    host: str
    path: str          # owner/repo, no .git suffix
    ref: Optional[str]
    origin: str        # the spec exactly as it was declared

    @property
    def fetch_url(self) -> str:
        return f"https://{self.host}/{self.path}.git"

    @property
    def cache_subpath(self) -> str:
        return f"{self.host}/{self.path}.git"


def parse_git_spec(name: str, spec: str) -> Optional[GitDependency]:
    """Interpret one dependency spec. None if it is not a git dependency.

    Raises UnresolvableDependencyError for a spec that is recognisably a git
    dependency but cannot be fetched under this design.
    """
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    if not spec:
        return None

    if _UNENCRYPTED_RE.match(spec):
        raise UnresolvableDependencyError(
            f"dependency {name!r} uses the unencrypted git:// protocol ({spec!r}). "
            f"Bulkhead only tunnels TLS, so this cannot be fetched or enforced. "
            f"Change it to https:// in your manifest."
        )

    # An https URL is only a git dependency when it says so. Lockfiles are full
    # of registry tarball URLs, and reading one of those as a repository would
    # send the resolve phase after a package that was never on a forge - or
    # refuse the install outright, which is what this check exists to prevent.
    url_part = spec.split("#", 1)[0]
    looks_like_git_url = spec.startswith("git+") or url_part.endswith(".git")

    for pattern, always_git in (
        (_GIT_HTTPS_RE, False), (_GIT_SSH_RE, True), (_GIT_SCP_RE, True),
    ):
        match = pattern.match(spec)
        if match:
            if not always_git and not looks_like_git_url:
                return None
            host = match.group("host")
            if host not in RESOLVABLE_FORGES:
                raise UnresolvableDependencyError(
                    f"dependency {name!r} points at {host}, which is not a "
                    f"resolvable forge. Add it to allowlists/npm-resolve.yaml "
                    f"deliberately, or vendor the dependency."
                )
            return GitDependency(
                name=name, host=host, path=match.group("path").rstrip("/"),
                ref=match.group("ref"), origin=spec,
            )

    # Shorthand is only a git dependency when it is unambiguous. A version
    # range, a file: path, an npm: alias and a tag all reach here and must not
    # be mistaken for owner/repo.
    if "/" in spec and not spec[0].isdigit() and spec[0] not in "^~<>=*":
        match = _SHORTHAND_RE.match(spec)
        if match:
            forge = match.group("forge")
            host = FORGE_PREFIXES[forge] if forge else "github.com"
            return GitDependency(
                name=name, host=host, path=match.group("path"),
                ref=match.group("ref"), origin=spec,
            )
    return None


DEPENDENCY_SECTIONS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)


def parse_git_dependencies(project_dir: Path) -> List[GitDependency]:
    """Every git dependency declared by the project's manifest and lockfile.

    Reads only. The lockfile matters as much as the manifest: transitive git
    dependencies appear there and nowhere else, and one this misses is one the
    install will try to fetch itself from a forge it cannot reach.
    """
    project_dir = Path(project_dir)
    found: Dict[str, GitDependency] = {}

    manifest = project_dir / "package.json"
    if manifest.is_file():
        data = _read_json(manifest)
        for section in DEPENDENCY_SECTIONS:
            for name, spec in (data.get(section) or {}).items():
                dependency = parse_git_spec(name, spec)
                if dependency:
                    found[dependency.cache_subpath] = dependency

    lockfile = project_dir / "package-lock.json"
    if lockfile.is_file():
        data = _read_json(lockfile)
        for key, entry in (data.get("packages") or {}).items():
            if not isinstance(entry, dict):
                continue
            resolved = entry.get("resolved")
            if not isinstance(resolved, str):
                continue
            dependency = parse_git_spec(entry.get("name") or key or "?", resolved)
            if dependency:
                found.setdefault(dependency.cache_subpath, dependency)

    return sorted(found.values(), key=lambda d: d.cache_subpath)


def _read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as e:
        raise RunnerError(
            f"cannot read {path}: {e}. Refusing to run rather than proceed with "
            f"an unknown set of dependencies."
        )
    if not isinstance(data, dict):
        raise RunnerError(f"{path} does not contain a JSON object")
    return data


# --- Resolve phase: fetching ----------------------------------------------

GIT_IMAGE = "alpine/git:latest"
CACHE_MOUNT = "/bulkhead-git"
GITCONFIG_NAME = "gitconfig"


def _clone_script(dependencies: Sequence[GitDependency]) -> str:
    """A shell script that mirrors each declared repository into the cache.

    --mirror rather than a ref-specific fetch, so the install can resolve any
    ref the manifest names without this phase having to interpret npm's
    resolution rules. Getting that interpretation wrong would mean a missing
    ref at install time, and by then the forge is unreachable by design.
    """
    lines = ["set -e"]
    for dependency in dependencies:
        url = shlex.quote(dependency.fetch_url)
        target = shlex.quote(f"/workspace/{dependency.cache_subpath}")
        lines += [
            f"if [ -d {target} ]; then",
            f"  echo 'update {dependency.cache_subpath}'",
            f"  git --git-dir={target} fetch --prune --quiet origin '+refs/*:refs/*'",
            "else",
            f"  echo 'clone {dependency.cache_subpath}'",
            f"  mkdir -p $(dirname {target})",
            f"  git clone --mirror --quiet {url} {target}",
            "fi",
        ]
    lines.append("echo RESOLVE_OK")
    return "\n".join(lines)


def write_git_redirect_config(cache_dir: Path, hosts: Iterable[str]) -> Path:
    """Point every forge URL form at the local cache.

    Written on the host and mounted read-only, so the install never runs a
    command to configure this and cannot rewrite it. If a repository was not
    fetched, its URL rewrites to a path that does not exist and git fails
    locally. It does not fall back to the network, because there is no network
    to fall back to.
    """
    lines = []
    for host in sorted(set(hosts)):
        local = f"{CACHE_MOUNT}/{host}/"
        lines.append(f'[url "{local}"]')
        for form in (
            f"https://{host}/",
            f"git+https://{host}/",
            f"ssh://git@{host}/",
            f"git+ssh://git@{host}/",
            f"git@{host}:",
        ):
            lines.append(f"\tinsteadOf = {form}")
    path = cache_dir / GITCONFIG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _link_bare_aliases(cache_dir: Path, dependencies: Sequence[GitDependency]) -> None:
    """Make owner/repo resolve as well as owner/repo.git.

    npm asks for both forms depending on how the dependency was declared, and a
    rewrite that only covers one of them fails for the other.
    """
    for dependency in dependencies:
        bare = cache_dir / dependency.cache_subpath
        alias = bare.with_suffix("")
        if bare.is_dir() and not alias.exists():
            try:
                alias.symlink_to(bare.name)
            except OSError:
                pass


def resolve_git_dependencies(
    dependencies: Sequence[GitDependency],
    audit_path: Path,
    runtime: Optional[str] = None,
    cache_dir: Path = GIT_CACHE_DIR,
    image: str = GIT_IMAGE,
    timeout: int = 600,
) -> SandboxResult:
    """Fetch declared git dependencies with no project code present.

    Runs under allowlists/npm-resolve.yaml, where forges are reachable and the
    registry is not. The project directory is deliberately NOT mounted: this
    phase needs the manifest's conclusions, not its contents, and mounting it
    would put attacker-influenced files next to the one process in the design
    that can reach a forge.
    """
    from bulkhead.policy import load_policy

    runtime = runtime or detect_runtime()
    cache_dir = Path(cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)

    ensure_networks(runtime)
    image_tag = ensure_proxy_image(runtime)

    policy = load_policy("npm-resolve")
    env = dict(PROXY_ENV)
    # Nothing to authenticate with. Any credential prompt is a hang, not a
    # login, so fail instead of waiting.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/true"

    with ProxySidecar(
        policy.ecosystem, audit_path=audit_path, runtime=runtime, image=image_tag,
    ):
        result = run_sandboxed(
            ["-c", _clone_script(dependencies)],
            cache_dir, image, runtime=runtime, env=env,
            network=INTERNAL_NETWORK, entrypoint="sh", timeout=timeout,
        )

    if result.exit_code != 0 or "RESOLVE_OK" not in result.stdout:
        raise UnresolvableDependencyError(
            "resolve phase failed, so the install would need a forge it cannot "
            "reach. Refusing to run.\n"
            + (result.stderr.strip() or result.stdout.strip())[-800:]
        )

    _link_bare_aliases(cache_dir, dependencies)
    write_git_redirect_config(cache_dir, (d.host for d in dependencies))
    return result
