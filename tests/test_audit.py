"""Tests for tamper detection in the audit log.

Each test alters a log the way an attacker would and asserts the chain refuses
to verify. The truncation test asserts the opposite - that the chain does NOT
detect it - because that limit is real, disclosed, and must not be quietly
closed by a test that pretends otherwise.
"""

import json

import pytest

from bulkhead.audit import (
    GENESIS_HASH,
    AuditEntry,
    AuditLog,
    TamperError,
    compute_hash,
)


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def populated(log):
    log.append("npm", "registry.npmjs.org", True, "exact:registry.npmjs.org", "registry")
    log.append("npm", "evil.example.com", False, None, "default deny")
    log.append("npm", "cdn.npmjs.org", True, "wildcard:*.npmjs.org", "cdn")
    log.append("npm", "exfil.attacker.test", False, None, "default deny")
    return log


def rewrite(log, entries):
    """Write raw dicts back to the log file, bypassing append()."""
    with open(log.path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def raw(log):
    return [json.loads(line) for line in open(log.path, encoding="utf-8") if line.strip()]


class TestChainIntegrity:
    def test_empty_log_verifies(self, log):
        assert log.verify() is True

    def test_intact_chain_verifies(self, populated):
        assert populated.verify() is True

    def test_first_entry_links_to_genesis(self, populated):
        assert populated.read_all()[0].prev_hash == GENESIS_HASH

    def test_each_entry_links_to_its_predecessor(self, populated):
        entries = populated.read_all()
        for prev, current in zip(entries, entries[1:]):
            assert current.prev_hash == prev.entry_hash

    def test_sequence_numbers_are_contiguous(self, populated):
        assert [e.seq for e in populated.read_all()] == [0, 1, 2, 3]


class TestTamperDetection:
    def test_flipping_a_denial_to_an_allow_is_detected(self, populated):
        # The attack that matters: making a blocked exfiltration look permitted.
        entries = raw(populated)
        entries[3]["allowed"] = True
        rewrite(populated, entries)
        with pytest.raises(TamperError) as exc:
            populated.verify()
        assert exc.value.seq == 3

    def test_changing_a_hostname_is_detected(self, populated):
        entries = raw(populated)
        entries[3]["host"] = "registry.npmjs.org"
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_removing_a_middle_entry_is_detected(self, populated):
        entries = raw(populated)
        del entries[2]
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_removing_the_first_entry_is_detected(self, populated):
        entries = raw(populated)
        del entries[0]
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_reordering_entries_is_detected(self, populated):
        entries = raw(populated)
        entries[1], entries[2] = entries[2], entries[1]
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_recomputing_the_hash_after_editing_is_still_detected(self, populated):
        # A careful attacker edits the entry and fixes its own hash. The chain
        # still breaks, because every later prev_hash points at the old value.
        entries = raw(populated)
        entries[1]["allowed"] = True
        payload = {k: v for k, v in entries[1].items() if k != "entry_hash"}
        entries[1]["entry_hash"] = compute_hash(payload)
        rewrite(populated, entries)
        with pytest.raises(TamperError) as exc:
            populated.verify()
        assert exc.value.seq == 2

    def test_splicing_a_forged_entry_is_detected(self, populated):
        entries = raw(populated)
        forged = dict(entries[0])
        forged["seq"] = 4
        forged["host"] = "attacker.test"
        entries.insert(2, forged)
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_corrupt_json_is_detected(self, populated):
        with open(populated.path, "a", encoding="utf-8") as f:
            f.write("{not json\n")
        with pytest.raises(TamperError):
            populated.verify()

    def test_appending_to_a_tampered_log_is_refused(self, populated):
        # Appending to a broken chain would launder it into a longer chain that
        # verifies from the splice point onward.
        entries = raw(populated)
        entries[1]["host"] = "attacker.test"
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.append("npm", "registry.npmjs.org", True, "exact", "ok")


class TestDisclosedLimits:
    def test_truncating_the_tail_is_NOT_detected(self, populated):
        # Disclosed limit, asserted so it cannot be silently believed closed.
        # A shorter chain is still internally consistent. Detecting this needs
        # the head anchored where the writer cannot reach it, which bulkhead
        # does not do. See docs/threat-model.md section 8.2.
        entries = raw(populated)
        rewrite(populated, entries[:2])
        assert populated.verify() is True

    def test_wholesale_replacement_is_NOT_detected(self, populated):
        # The chain proves internal consistency, not provenance. An attacker
        # who can write the file can build a valid chain of their own.
        forged = AuditLog(populated.path.parent / "forged.log")
        forged.append("npm", "registry.npmjs.org", True, "exact", "innocent")
        rewrite(populated, raw(forged))
        assert populated.verify() is True


class TestVerifyContract:
    def test_verify_raises_rather_than_returning_false(self, populated):
        # A caller that ignores a boolean is the failure this module exists to
        # prevent, so there is no boolean to ignore.
        entries = raw(populated)
        entries[0]["host"] = "attacker.test"
        rewrite(populated, entries)
        with pytest.raises(TamperError):
            populated.verify()

    def test_no_request_contents_are_recorded(self, populated):
        # Bulkhead does not intercept TLS and has no contents to record. The
        # log must not become a place data accumulates.
        for entry in populated.read_all():
            assert set(entry.payload()) == {
                "seq", "timestamp", "ecosystem", "host",
                "allowed", "rule", "reason", "prev_hash",
            }


class TestCliAudit:
    def test_audit_verifies_intact_log(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(populated.path)]) == 0
        out = capsys.readouterr().out
        assert "OK: chain verified, 4 entries" in out
        assert "exfil.attacker.test" in out

    def test_audit_reports_tampering_loudly(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        entries = raw(populated)
        entries[3]["allowed"] = True
        rewrite(populated, entries)
        assert cli_main(["audit", str(populated.path)]) == 1
        assert "TAMPERED" in capsys.readouterr().err

    def test_audit_verify_only_prints_no_entries(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(populated.path), "--verify-only"]) == 0
        out = capsys.readouterr().out
        assert "OK: chain verified" in out
        assert "npmjs.org" not in out

    def test_audit_of_missing_log_is_an_empty_verified_chain(self, tmp_path, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(tmp_path / "nope.log")]) == 0
        assert "0 entries" in capsys.readouterr().out
