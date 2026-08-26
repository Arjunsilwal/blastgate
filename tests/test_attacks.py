"""Tests for the attack corpus: its schema, its scoring, and its results.

The scoring tests are pure and run everywhere. The corpus run needs a container
runtime and is skipped without one.
"""

from pathlib import Path
import textwrap

import pytest
import yaml

from attacks.corpus import (
    CORPUS_DIR,
    Scenario,
    ScenarioError,
    Target,
    load_corpus,
    parse_scenario,
)
from attacks.executor import (
    EXPECTED_ALLOWED,
    FALSE_POSITIVE,
    GAP_CLOSED,
    KNOWN_GAP,
    NOT_RUNNABLE,
    PREVENTED,
    REGRESSION,
    Outcome,
    Report,
    _classify,
    run_corpus,
)

try:
    from blastgate.runner import detect_runtime
    RUNTIME = detect_runtime()
except Exception:
    RUNTIME = None


def scenario(**kw) -> Scenario:
    base = dict(
        id="x", title="t", chain_link=5, ecosystem="npm", source="constructed",
        expect="denied", requires="policy",
    )
    base.update(kw)
    return Scenario(**base)


class TestSchema:
    def test_every_scenario_in_the_corpus_parses(self):
        assert len(load_corpus()) >= 8

    def test_ids_are_unique(self):
        ids = [s.id for s in load_corpus()]
        assert len(ids) == len(set(ids))

    def test_id_must_match_filename(self, tmp_path):
        path = tmp_path / "some-name.yaml"
        path.write_text(yaml.safe_dump({
            "id": "a-different-name", "title": "t", "chain_link": 5,
            "ecosystem": "npm", "source": "constructed", "expect": "denied",
            "requires": "policy", "target": {"host": "x.test"},
        }))
        with pytest.raises(ScenarioError, match="does not match the filename"):
            parse_scenario(yaml.safe_load(path.read_text()), path)

    @pytest.mark.parametrize("field", [
        "id", "title", "chain_link", "ecosystem", "source", "expect", "requires",
    ])
    def test_missing_required_field_is_refused(self, field, tmp_path):
        data = {
            "id": "s", "title": "t", "chain_link": 5, "ecosystem": "npm",
            "source": "constructed", "expect": "denied", "requires": "policy",
            "target": {"host": "x.test"},
        }
        del data[field]
        with pytest.raises(ScenarioError):
            parse_scenario(data, tmp_path / "s.yaml")

    @pytest.mark.parametrize("value", ["blocked", "pass", "fail", "", None])
    def test_unknown_expect_value_is_refused(self, value, tmp_path):
        data = {
            "id": "s", "title": "t", "chain_link": 5, "ecosystem": "npm",
            "source": "constructed", "expect": value, "requires": "policy",
            "target": {"host": "x.test"},
        }
        with pytest.raises(ScenarioError):
            parse_scenario(data, tmp_path / "s.yaml")

    def test_egress_scenario_without_a_target_is_refused(self, tmp_path):
        data = {
            "id": "s", "title": "t", "chain_link": 5, "ecosystem": "npm",
            "source": "constructed", "expect": "denied", "requires": "policy",
        }
        with pytest.raises(ScenarioError, match="target.host"):
            parse_scenario(data, tmp_path / "s.yaml")

    def test_filesystem_scenario_without_paths_is_refused(self, tmp_path):
        data = {
            "id": "s", "title": "t", "chain_link": 4, "ecosystem": "npm",
            "source": "constructed", "expect": "denied", "requires": "sandbox",
            "check": "filesystem",
        }
        with pytest.raises(ScenarioError, match="paths"):
            parse_scenario(data, tmp_path / "s.yaml")

    def test_install_scenario_needs_a_manifest_and_command(self, tmp_path):
        base = {
            "id": "s", "title": "t", "chain_link": 0, "ecosystem": "npm",
            "source": "constructed", "expect": "allowed", "requires": "sandbox",
            "check": "install",
        }
        with pytest.raises(ScenarioError, match="manifest"):
            parse_scenario(dict(base), tmp_path / "s.yaml")
        with pytest.raises(ScenarioError, match="command"):
            parse_scenario(
                dict(base, manifest={"dependencies": {"a": "github:o/r"}}),
                tmp_path / "s.yaml",
            )

    def test_image_scenario_needs_an_image_and_absent_paths(self, tmp_path):
        base = {
            "id": "s", "title": "t", "chain_link": 3, "ecosystem": "npm",
            "source": "constructed", "expect": "denied", "requires": "sandbox",
            "check": "image",
        }
        with pytest.raises(ScenarioError, match="image"):
            parse_scenario(dict(base), tmp_path / "s.yaml")
        with pytest.raises(ScenarioError, match="absent"):
            parse_scenario(dict(base, image="alpine"), tmp_path / "s.yaml")

    @pytest.mark.parametrize("tamper", [None, "", "delete-everything", "truncat"])
    def test_audit_scenario_needs_a_known_tamper_mode(self, tamper, tmp_path):
        # An unknown mode would otherwise report not-runnable, which counts as
        # a failure and would look like a regression rather than a typo.
        data = {
            "id": "s", "title": "t", "chain_link": 6, "ecosystem": "npm",
            "source": "constructed", "expect": "denied", "requires": "sandbox",
            "check": "audit", "tamper": tamper,
        }
        with pytest.raises(ScenarioError, match="tamper"):
            parse_scenario(data, tmp_path / "s.yaml")

    def test_a_malformed_scenario_is_loud_not_skipped(self, tmp_path):
        # Silently dropping an unparseable scenario would report a better
        # number than the corpus earned.
        (tmp_path / "broken.yaml").write_text("this: [is, not, a, scenario\n")
        with pytest.raises(Exception):
            load_corpus(tmp_path)


class TestScoring:
    def test_denied_and_blocked_passes(self):
        assert _classify(scenario(expect="denied"), reached=False, detail="").status == PREVENTED

    def test_denied_but_reached_is_a_regression(self):
        assert _classify(scenario(expect="denied"), reached=True, detail="").status == REGRESSION

    def test_allowed_and_reached_passes(self):
        assert _classify(scenario(expect="allowed"), reached=True, detail="").status == EXPECTED_ALLOWED

    def test_allowed_but_blocked_is_a_false_positive(self):
        # The false-positive budget is near zero. Breaking a legitimate install
        # is a failure, not a conservative default.
        assert _classify(scenario(expect="allowed"), reached=False, detail="").status == FALSE_POSITIVE

    def test_a_disclosed_gap_that_still_reproduces_counts_against_the_rate(self):
        outcome = _classify(scenario(expect="not_prevented"), reached=True, detail="")
        assert outcome.status == KNOWN_GAP
        assert outcome.passed is False

    def test_a_disclosed_gap_that_stops_reproducing_is_news(self):
        outcome = _classify(scenario(expect="not_prevented"), reached=False, detail="")
        assert outcome.status == GAP_CLOSED
        assert outcome.passed is True

    def test_not_runnable_counts_against_the_rate(self):
        # A scenario that cannot run is not a scenario that passed.
        outcome = Outcome(scenario(), NOT_RUNNABLE, "no runtime")
        assert outcome.passed is False

    def test_adding_an_honest_gap_lowers_the_rate(self):
        # The corpus growing more honest should be able to move the number
        # down. A rate that can only rise is a curated one.
        before = Report([
            Outcome(scenario(id="a"), PREVENTED, ""),
            Outcome(scenario(id="b"), PREVENTED, ""),
        ])
        after = Report(list(before.outcomes) + [Outcome(scenario(id="c"), KNOWN_GAP, "")])
        assert before.rate == 100.0
        assert after.rate < before.rate

    def test_the_rate_counts_gaps_and_unrunnable_scenarios(self):
        report = Report([
            Outcome(scenario(id="a"), PREVENTED, ""),
            Outcome(scenario(id="b"), PREVENTED, ""),
            Outcome(scenario(id="c"), KNOWN_GAP, ""),
            Outcome(scenario(id="d"), NOT_RUNNABLE, ""),
        ])
        assert report.total == 4
        assert report.passed == 2
        assert report.rate == 50.0


@pytest.fixture(scope="module")
def report():
    return Report(run_corpus())


@pytest.mark.skipif(RUNTIME is None, reason="no container runtime available")
class TestCorpusResults:
    def test_no_scenario_failed_to_run(self, report):
        unrunnable = report.by_status(NOT_RUNNABLE)
        assert not unrunnable, [
            f"{o.scenario.id}: {o.detail}" for o in unrunnable
        ]

    def test_no_regressions(self, report):
        # A denied scenario that gets through is the failure this corpus exists
        # to catch.
        regressions = report.by_status(REGRESSION)
        assert not regressions, [
            f"{o.scenario.id}: {o.detail}" for o in regressions
        ]

    def test_no_false_positives(self, report):
        breakages = report.by_status(FALSE_POSITIVE)
        assert not breakages, [
            f"{o.scenario.id}: {o.detail}" for o in breakages
        ]

    def test_disclosed_gaps_still_reproduce(self, report):
        # If one stops reproducing, the threat model is out of date and the
        # scenario needs rewriting. That is a real event, so it fails loudly.
        for outcome in report.outcomes:
            if outcome.scenario.documents_a_gap:
                assert outcome.status in (KNOWN_GAP, GAP_CLOSED)
                if outcome.status == GAP_CLOSED:
                    pytest.fail(
                        f"{outcome.scenario.id} no longer reproduces. Update "
                        f"docs/threat-model.md section 8 and this scenario."
                    )

    def test_scenario_provenance_is_reported(self, report):
        # A corpus written entirely from its own threat model is weaker
        # evidence than one drawn from incidents, and the published output
        # should say so rather than leaving a reader to count YAML files.
        assert report.sourced >= 1
        assert f"{report.sourced} of {report.total} are derived" in report.to_markdown()

    def test_a_constructed_scenario_is_not_counted_as_sourced(self):
        outcomes = [
            Outcome(scenario(id="a", source="constructed"), PREVENTED, ""),
            Outcome(scenario(id="b", source="https://example.test/writeup"), PREVENTED, ""),
        ]
        assert Report(outcomes).sourced == 1

    def test_the_published_number_matches_the_corpus(self, report):
        # The README cannot drift away from what the corpus actually scores.
        readme = Path(__file__).resolve().parent.parent / "README.md"
        text = readme.read_text()
        claim = f"{report.passed} of {report.total} scenarios prevented"
        assert claim in text, (
            f"README does not carry the current result ({claim}). "
            f"Regenerate it with: python scripts/attack_report.py --write"
        )
