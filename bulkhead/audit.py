"""Append-only, hash-chained log of egress decisions.

Each entry carries the hash of the entry before it, so altering or removing an
entry breaks every hash after it. This makes edits detectable. It does not make
them impossible, and the difference matters — see the limits below and
docs/threat-model.md section 8.2.

What the chain detects:
  - a modified entry
  - a removed entry from anywhere but the end
  - reordered entries
  - a forged entry spliced into the middle

What it does not detect on its own:
  - truncation of the most recent entries. Removing the tail leaves a shorter
    chain that still verifies. Detecting this requires anchoring the head
    somewhere the writer cannot reach, which bulkhead does not do.
  - wholesale replacement of the log with a valid chain the attacker built.
    The chain proves internal consistency, not provenance.

Neither limit is closed by writing more code here. Both are closed by the log
living somewhere the install container cannot reach, which is a property of the
topology: the audit directory is mounted into the proxy container and nowhere
else, so the sandbox can neither read nor delete it.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Iterator, List, Optional, Sequence


GENESIS_HASH = "0" * 64


class AuditError(Exception):
    """Base error for audit log failures."""


class TamperError(AuditError):
    """Raised when the chain does not verify.

    Carries the sequence number of the first entry that failed, which is the
    entry at or before the alteration.
    """

    def __init__(self, message: str, seq: Optional[int] = None) -> None:
        super().__init__(message)
        self.seq = seq


@dataclass(frozen=True)
class AuditEntry:
    """One egress decision.

    Records the destination hostname and the rule that decided it. It does not
    record request contents, because bulkhead does not intercept TLS and has
    none to record.
    """
    seq: int
    timestamp: str
    ecosystem: str
    host: str
    allowed: bool
    rule: Optional[str]
    reason: str
    prev_hash: str
    entry_hash: str

    def payload(self) -> dict:
        """The fields the hash covers. Everything except the hash itself."""
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "ecosystem": self.ecosystem,
            "host": self.host,
            "allowed": self.allowed,
            "rule": self.rule,
            "reason": self.reason,
            "prev_hash": self.prev_hash,
        }


def compute_hash(payload: dict) -> str:
    """Hash an entry payload.

    Serialisation is canonical - sorted keys, no insignificant whitespace - so
    the same logical entry always produces the same hash.
    """
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class AuditLog:
    """A hash-chained decision log backed by a JSON Lines file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(
        self,
        ecosystem: str,
        host: str,
        allowed: bool,
        rule: Optional[str],
        reason: str,
        timestamp: Optional[str] = None,
    ) -> AuditEntry:
        """Append a decision and return the entry written.

        The chain is extended from the current tail, which is read and verified
        first: appending to a log that does not verify would launder a tampered
        chain into a valid-looking one.
        """
        entries = self.read_all()
        if entries:
            self.verify(entries)
            prev = entries[-1]
            seq = prev.seq + 1
            prev_hash = prev.entry_hash
        else:
            seq = 0
            prev_hash = GENESIS_HASH

        payload = {
            "seq": seq,
            "timestamp": timestamp or _now(),
            "ecosystem": ecosystem,
            "host": host,
            "allowed": allowed,
            "rule": rule,
            "reason": reason,
            "prev_hash": prev_hash,
        }
        entry = AuditEntry(**payload, entry_hash=compute_hash(payload))

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def read_all(self) -> List[AuditEntry]:
        """Read every entry. Does not verify - call verify() for that."""
        if not self.path.is_file():
            return []
        entries: List[AuditEntry] = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as e:
                    raise TamperError(f"line {lineno} is not valid JSON: {e}") from e
                try:
                    entries.append(AuditEntry(**data))
                except TypeError as e:
                    raise TamperError(f"line {lineno} has unexpected fields: {e}") from e
        return entries

    def verify(self, entries: Optional[Sequence[AuditEntry]] = None) -> bool:
        """Verify the chain. Returns True or raises TamperError.

        Deliberately raises rather than returning False. A caller that ignores
        a boolean is the failure mode this whole module exists to prevent.
        """
        if entries is None:
            entries = self.read_all()
        if not entries:
            return True

        expected_prev = GENESIS_HASH
        for index, entry in enumerate(entries):
            if entry.seq != index:
                raise TamperError(
                    f"sequence break: entry at position {index} claims seq {entry.seq}",
                    seq=entry.seq,
                )
            if entry.prev_hash != expected_prev:
                raise TamperError(
                    f"chain break at seq {entry.seq}: prev_hash does not match the "
                    f"preceding entry",
                    seq=entry.seq,
                )
            recomputed = compute_hash(entry.payload())
            if recomputed != entry.entry_hash:
                raise TamperError(
                    f"entry {entry.seq} was altered: recorded hash does not match "
                    f"its contents",
                    seq=entry.seq,
                )
            expected_prev = entry.entry_hash
        return True

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self.read_all())
