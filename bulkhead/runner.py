"""Container lifecycle and the boundary the install runs behind.

This module owns the topology, which is the actual security property. It is
being built in two parts, and only the first exists today:

1. What crosses the boundary. Environment filtering and runtime detection are
   pure functions with no I/O, testable exhaustively without a container
   runtime. That is this file.

2. The topology itself. Creating the two networks, joining the containers, and
   mounting the project directory. Not written. It requires a container runtime
   to build against and, more importantly, to demonstrate, and a control nobody
   has watched work is a claim rather than a protection.

Until part 2 exists, `bh run` refuses. See docs/threat-model.md section 7.
"""

from dataclasses import dataclass
import re
import shutil
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
