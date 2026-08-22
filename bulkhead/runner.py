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

Still missing: running the proxy as a sidecar on both networks, so the sandbox
has an allowed route rather than no route. `bh run` therefore still refuses. A
sandbox with no network at all is a valid security state and the correct
intermediate one, but it is not yet a working install.
"""

from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple


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
