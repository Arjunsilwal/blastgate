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

What the chain does not detect on its own:
  - truncation of the most recent entries. Removing the tail leaves a shorter
    chain that still verifies.
  - wholesale replacement of the log with a valid chain the attacker built.
    The chain proves internal consistency, not provenance.

Truncation is closed by the anchor store below. After each run the host-side
runner - a different process from the proxy that writes the log, with no shared
mount - records the head hash and entry count. A truncated log no longer matches
its anchor. Anchors are themselves chained, so dropping a whole run is as
visible as dropping an entry.

Wholesale replacement remains open and remains disclosed. Anchoring raises the
bar from "write one file" to "write two files consistently in two locations",
which is a real improvement and is not provenance. An attacker with write access
to both stores can forge both. Genuine provenance needs an anchor this machine
cannot alter, which blastgate does not have. See docs/threat-model.md section 8.2.
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
    record request contents, because blastgate does not intercept TLS and has
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


def format_entry_count(count: int) -> str:
    """'1 entry', '2 entries'. Audit output is read when something is wrong;
    it should not also read as sloppy."""
    return f"{count} entry" if count == 1 else f"{count} entries"


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

    def verify_against_anchor(
        self,
        anchor: "Anchor",
        entries: Optional[Sequence[AuditEntry]] = None,
    ) -> bool:
        """Verify the chain and check it still matches its anchor.

        A log may legitimately be longer than its last anchor: entries are
        appended during a run and the anchor is written when that run ends. So
        the check is not equality of length. It is that the entry the anchor
        pointed at is still there, still in that position, and still has the
        hash the anchor recorded.

        Shorter than the anchor means entries were removed from the end, which
        is the case a hash chain alone cannot see.
        """
        if entries is None:
            entries = self.read_all()
        self.verify(entries)

        if len(entries) < anchor.entry_count:
            raise TamperError(
                f"log is truncated: anchor recorded {format_entry_count(anchor.entry_count)}, "
                f"found {len(entries)}. "
                f"{format_entry_count(anchor.entry_count - len(entries))} "
                f"removed from the end."
            )

        if anchor.entry_count == 0:
            return True

        anchored = entries[anchor.entry_count - 1]
        if anchored.entry_hash != anchor.head_hash:
            raise TamperError(
                f"log does not match its anchor at entry {anchor.entry_count - 1}: "
                f"the log was replaced or rewritten since it was anchored.",
                seq=anchored.seq,
            )
        return True

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self.read_all())


# --- Anchoring -------------------------------------------------------------
#
# The proxy container writes the audit log; it is the only process that can,
# because the audit directory is mounted there and nowhere else. The anchor is
# written by the host-side runner instead: a different process, with a
# different view of the filesystem, that the sandbox cannot reach at all.
#
# Two stores, two writers. Truncating the log now requires tampering with a
# file the log's own writer never sees.


class AnchorError(AuditError):
    """The anchor store is unusable."""


@dataclass(frozen=True)
class Anchor:
    """A record of where an audit log stood at the end of one run."""

    run_id: str
    timestamp: str
    audit_path: str
    entry_count: int
    head_hash: str
    prev_hash: str
    anchor_hash: str

    def payload(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "audit_path": self.audit_path,
            "entry_count": self.entry_count,
            "head_hash": self.head_hash,
            "prev_hash": self.prev_hash,
        }


class AnchorStore:
    """A chained record of audit log heads, one entry per run."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(
        self,
        run_id: str,
        audit_path: Path,
        entries: Sequence[AuditEntry],
        timestamp: Optional[str] = None,
    ) -> Anchor:
        """Record where an audit log stands now.

        The existing anchor chain is verified before extension, for the same
        reason the audit log verifies before appending: extending a broken
        chain would launder it into a valid-looking one.
        """
        existing = self.read_all()
        if existing:
            self.verify(existing)
            prev_hash = existing[-1].anchor_hash
        else:
            prev_hash = GENESIS_HASH

        payload = {
            "run_id": run_id,
            "timestamp": timestamp or _now(),
            "audit_path": str(audit_path),
            "entry_count": len(entries),
            "head_hash": entries[-1].entry_hash if entries else GENESIS_HASH,
            "prev_hash": prev_hash,
        }
        anchor = Anchor(**payload, anchor_hash=compute_hash(payload))

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(anchor), sort_keys=True, separators=(",", ":")) + "\n")
        return anchor

    def read_all(self) -> List[Anchor]:
        if not self.path.is_file():
            return []
        anchors: List[Anchor] = []
        with open(self.path, encoding="utf-8") as f:
            for number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    anchors.append(Anchor(**json.loads(line)))
                except (json.JSONDecodeError, TypeError) as e:
                    raise AnchorError(f"{self.path}:{number} is not a valid anchor: {e}")
        return anchors

    def verify(self, anchors: Optional[Sequence[Anchor]] = None) -> bool:
        """Verify the anchor chain itself. Raises TamperError."""
        if anchors is None:
            anchors = self.read_all()
        if not anchors:
            return True

        expected_prev = GENESIS_HASH
        for index, anchor in enumerate(anchors):
            if anchor.prev_hash != expected_prev:
                raise TamperError(
                    f"anchor chain break at position {index}: a run was removed "
                    f"or replaced"
                )
            if compute_hash(anchor.payload()) != anchor.anchor_hash:
                raise TamperError(f"anchor at position {index} was altered")
            expected_prev = anchor.anchor_hash
        return True

    def latest_for(self, audit_path: Path) -> Optional[Anchor]:
        """The most recent anchor for one log, or None."""
        target = str(Path(audit_path))
        for anchor in reversed(self.read_all()):
            if anchor.audit_path == target:
                return anchor
        return None
