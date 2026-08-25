"""Registry credentials, held where the sandbox cannot reach them.

The point of this module is not to get a token into the sandbox safely. It is
to run an authenticated install with no token in the sandbox at all.

Today, installing from a private registry means a token sits in ~/.npmrc,
readable by every postinstall script that runs. That is not a hypothetical
weakness: it is what the Shai-Hulud worm harvested, from that exact file,
across several hundred packages. So the credential stays on the host, the proxy
adds it on the upstream leg, and a payload that reads every file and every
variable in the sandbox finds nothing.

The store is a file rather than an OS keychain. A keychain would defend against
another process on the host reading it; this defends against the install, which
is the threat this project is about. The difference is written down in
docs/threat-model.md rather than papered over.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Dict, Iterator, List, Optional

DEFAULT_STORE = Path.home() / ".blastgate" / "credentials.json"

# Owner read/write only. Anything wider and the file is refused rather than
# read: a credential store the group can read is not a credential store.
REQUIRED_MODE = 0o600


class CredentialError(Exception):
    """The credential store is unusable, or the request makes no sense."""


@dataclass(frozen=True)
class Credential:
    """One registry credential.

    `header` is what gets added to the upstream request. Storing the whole
    header rather than just a token keeps this indifferent to whether a
    registry wants Bearer, Basic, or something else of its own.
    """

    host: str
    scheme: str          # "Bearer" | "Basic" | "token"
    secret: str

    @property
    def header(self) -> str:
        return f"{self.scheme} {self.secret}"

    def redacted(self) -> dict:
        """Everything except the part that matters. For display and logs."""
        return {"host": self.host, "scheme": self.scheme, "secret": "<redacted>"}


class CredentialStore:
    """A file of credentials, keyed by host.

    Never mounted into any container. The proxy sidecar receives only the
    credentials for hosts it is brokering, and receives them as arguments to
    its own process rather than as a file it could be made to re-read.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else DEFAULT_STORE

    # --- reading ---------------------------------------------------------
    def _load(self) -> Dict[str, dict]:
        if not self.path.is_file():
            return {}
        self._assert_permissions()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError as e:
            raise CredentialError(f"{self.path} is not valid JSON: {e}")
        if not isinstance(data, dict):
            raise CredentialError(f"{self.path} does not contain an object")
        return data

    def _assert_permissions(self) -> None:
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            raise CredentialError(
                f"{self.path} is readable by others (mode {mode:04o}). Refusing "
                f"to read a credential store anyone else can open. Fix it with: "
                f"chmod 600 {self.path}"
            )

    def get(self, host: str) -> Optional[Credential]:
        entry = self._load().get(normalise_host(host))
        if not entry:
            return None
        return Credential(
            host=normalise_host(host),
            scheme=entry.get("scheme", "Bearer"),
            secret=entry["secret"],
        )

    def hosts(self) -> List[str]:
        return sorted(self._load())

    def __iter__(self) -> Iterator[Credential]:
        for host in self.hosts():
            credential = self.get(host)
            if credential:
                yield credential

    # --- writing ---------------------------------------------------------
    def put(self, host: str, secret: str, scheme: str = "Bearer") -> Credential:
        if not secret or not secret.strip():
            raise CredentialError("refusing to store an empty secret")
        host = normalise_host(host)
        data = self._load()
        data[host] = {"scheme": scheme, "secret": secret.strip()}
        self._write(data)
        return Credential(host=host, scheme=scheme, secret=secret.strip())

    def remove(self, host: str) -> bool:
        host = normalise_host(host)
        data = self._load()
        if host not in data:
            return False
        del data[host]
        self._write(data)
        return True

    def _write(self, data: Dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Created with the right mode from the start. Writing then chmod-ing
        # leaves a window where the secret is on disk world-readable.
        descriptor = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, REQUIRED_MODE
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(self.path, REQUIRED_MODE)


def normalise_host(host: str) -> str:
    """Hosts are compared exactly, so they have to be spelled consistently."""
    host = (host or "").strip().lower()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    return host.rstrip("/").split("/")[0]
