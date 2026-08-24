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
    def test_truncating_the_tail_is_not_detected_by_the_chain_alone(self, populated):
        # Still true, and still worth asserting: the chain by itself cannot see
        # this. What changed is that the chain is no longer by itself. The
        # anchored case is the test below.
        entries = raw(populated)
        rewrite(populated, entries[:2])
        assert populated.verify() is True

    def test_truncating_the_tail_IS_detected_against_an_anchor(self, populated, tmp_path):
        # Was a disclosed limit in threat model 8.2. Closed by the anchor
        # store, which is written by the host runner rather than by the process
        # that writes the log.
        from bulkhead.audit import AnchorStore

        store = AnchorStore(tmp_path / "anchors")
        anchor = store.append("run-1", populated.path, populated.read_all())
        rewrite(populated, raw(populated)[:2])

        assert populated.verify() is True  # chain alone: no idea
        with pytest.raises(TamperError, match="truncated"):
            populated.verify_against_anchor(anchor)

    def test_wholesale_replacement_is_NOT_detected_by_the_chain(self, populated):
        # The chain proves internal consistency, not provenance. An attacker
        # who can write the file can build a valid chain of their own.
        forged = AuditLog(populated.path.parent / "forged.log")
        forged.append("npm", "registry.npmjs.org", True, "exact", "innocent")
        rewrite(populated, raw(forged))
        assert populated.verify() is True

    def test_replacement_is_caught_by_an_anchor_the_attacker_did_not_rewrite(
        self, populated, tmp_path
    ):
        from bulkhead.audit import AnchorStore

        store = AnchorStore(tmp_path / "anchors")
        anchor = store.append("run-1", populated.path, populated.read_all())

        forged = AuditLog(populated.path.parent / "forged.log")
        for host in ("registry.npmjs.org",) * 4:
            forged.append("npm", host, True, "exact", "innocent")
        rewrite(populated, raw(forged))

        with pytest.raises(TamperError, match="replaced or rewritten"):
            populated.verify_against_anchor(anchor)

    def test_replacement_is_NOT_detected_if_both_stores_are_rewritten(
        self, populated, tmp_path
    ):
        # The disclosed limit that survives this stage, asserted so it cannot
        # be quietly believed closed. Anchoring raises the bar from writing one
        # file to writing two consistently. It is not provenance: an attacker
        # with write access to both stores forges both. Closing this needs an
        # anchor this machine cannot alter. See docs/threat-model.md 8.2.
        from bulkhead.audit import AnchorStore

        forged = AuditLog(populated.path.parent / "forged.log")
        for host in ("registry.npmjs.org",) * 4:
            forged.append("npm", host, True, "exact", "innocent")
        rewrite(populated, raw(forged))

        store = AnchorStore(tmp_path / "anchors")
        anchor = store.append("run-1", populated.path, populated.read_all())

        assert populated.verify_against_anchor(anchor) is True


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
    def test_an_unanchored_log_does_not_report_as_verified(self, populated, capsys):
        # An internally consistent chain says nothing about entries removed
        # from the end. Reporting that identically to a verified log would hide
        # exactly the limit anchoring exists to close.
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(populated.path), "--no-anchor"]) == 0
        out = capsys.readouterr().out
        assert "UNANCHORED" in out
        assert "truncation cannot be detected" in out
        assert "OK:" not in out
        assert "exfil.attacker.test" in out

    def test_require_anchor_fails_when_there_is_none(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(
            ["audit", str(populated.path), "--no-anchor", "--require-anchor"]
        ) == 1

    def test_an_anchored_log_reports_as_verified(self, populated, tmp_path, capsys):
        from bulkhead.audit import AnchorStore
        from bulkhead.cli import main as cli_main

        store = AnchorStore(tmp_path / "anchors")
        store.append("run-1", populated.path, populated.read_all())
        assert cli_main(
            ["audit", str(populated.path), "--anchor", str(tmp_path / "anchors")]
        ) == 0
        out = capsys.readouterr().out
        assert "OK: chain verified against anchor" in out

    def test_truncating_an_anchored_log_is_caught_by_the_cli(self, populated, tmp_path, capsys):
        from bulkhead.audit import AnchorStore
        from bulkhead.cli import main as cli_main

        store = AnchorStore(tmp_path / "anchors")
        store.append("run-1", populated.path, populated.read_all())
        rewrite(populated, raw(populated)[:2])

        assert cli_main(
            ["audit", str(populated.path), "--anchor", str(tmp_path / "anchors")]
        ) == 1
        assert "TAMPERED" in capsys.readouterr().err

    def test_audit_reports_tampering_loudly(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        entries = raw(populated)
        entries[3]["allowed"] = True
        rewrite(populated, entries)
        assert cli_main(["audit", str(populated.path)]) == 1
        assert "TAMPERED" in capsys.readouterr().err

    def test_audit_verify_only_prints_no_entries(self, populated, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(populated.path), "--verify-only", "--no-anchor"]) == 0
        out = capsys.readouterr().out
        assert "UNANCHORED" in out
        assert "npmjs.org" not in out

    def test_audit_of_missing_log_is_an_empty_verified_chain(self, tmp_path, capsys):
        from bulkhead.cli import main as cli_main
        assert cli_main(["audit", str(tmp_path / "nope.log"), "--no-anchor"]) == 0
        assert "0 entries" in capsys.readouterr().out


class TestAnchorStore:
    """The anchor chain, which is what makes a missing run visible."""

    def test_anchors_chain_across_runs(self, tmp_path):
        from bulkhead.audit import AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        store = AnchorStore(tmp_path / "anchors")
        first = store.append("run-1", log.path, log.read_all())

        log.append("npm", "a.test", False, None, "denied")
        second = store.append("run-2", log.path, log.read_all())

        assert second.prev_hash == first.anchor_hash
        assert store.verify() is True

    def test_removing_a_whole_run_breaks_the_anchor_chain(self, tmp_path):
        # Truncating the audit log is one attack; removing the anchor that
        # would reveal it is the follow-up. The anchors are chained for that
        # reason.
        from bulkhead.audit import AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        store = AnchorStore(tmp_path / "anchors")
        for index in range(3):
            log.append("npm", f"h{index}.test", False, None, "denied")
            store.append(f"run-{index}", log.path, log.read_all())

        lines = store.path.read_text().splitlines()
        store.path.write_text("\n".join([lines[0], lines[2]]) + "\n")

        with pytest.raises(TamperError, match="anchor chain break"):
            store.verify()

    def test_altering_an_anchor_is_detected(self, tmp_path):
        from bulkhead.audit import AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        log.append("npm", "a.test", False, None, "denied")
        store = AnchorStore(tmp_path / "anchors")
        store.append("run-1", log.path, log.read_all())

        record = json.loads(store.path.read_text().strip())
        record["entry_count"] = 0
        store.path.write_text(json.dumps(record) + "\n")

        with pytest.raises(TamperError, match="was altered"):
            store.verify()

    def test_extending_a_broken_anchor_chain_is_refused(self, tmp_path):
        # Same rule as the audit log: appending to a broken chain would launder
        # it into a valid-looking one.
        from bulkhead.audit import AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        store = AnchorStore(tmp_path / "anchors")
        store.append("run-1", log.path, log.read_all())

        record = json.loads(store.path.read_text().strip())
        record["run_id"] = "tampered"
        store.path.write_text(json.dumps(record) + "\n")

        with pytest.raises(TamperError):
            store.append("run-2", log.path, log.read_all())

    def test_latest_for_selects_the_right_log(self, tmp_path):
        from bulkhead.audit import AnchorStore

        one = AuditLog(tmp_path / "one.log")
        two = AuditLog(tmp_path / "two.log")
        one.append("npm", "a.test", False, None, "denied")
        store = AnchorStore(tmp_path / "anchors")
        store.append("run-1", one.path, one.read_all())
        store.append("run-2", two.path, two.read_all())

        assert store.latest_for(one.path).entry_count == 1
        assert store.latest_for(two.path).entry_count == 0
        assert store.latest_for(tmp_path / "absent.log") is None

    def test_an_empty_log_anchors_cleanly(self, tmp_path):
        from bulkhead.audit import GENESIS_HASH, AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        store = AnchorStore(tmp_path / "anchors")
        anchor = store.append("run-1", log.path, log.read_all())
        assert anchor.entry_count == 0
        assert anchor.head_hash == GENESIS_HASH
        assert log.verify_against_anchor(anchor) is True

    def test_a_log_longer_than_its_anchor_still_verifies(self, tmp_path):
        # Entries are appended during a run; the anchor is written when the run
        # ends. A log ahead of its last anchor is the normal in-progress state,
        # not tampering.
        from bulkhead.audit import AnchorStore

        log = AuditLog(tmp_path / "audit.log")
        for host in ("a.test", "b.test"):
            log.append("npm", host, False, None, "denied")
        store = AnchorStore(tmp_path / "anchors")
        anchor = store.append("run-1", log.path, log.read_all())

        log.append("npm", "c.test", False, None, "denied")
        assert log.verify_against_anchor(anchor) is True
