"""Loader for the executable attack corpus.

Test infrastructure, deliberately not a sixth module under bulkhead/. Nothing
here is part of the tool; it exists to run scenarios against the tool and count
the results honestly.

The counting is the point. A scenario that documents a gap is expected to
succeed for the attacker, and it still counts against the published number. A
scenario that cannot run because a component is missing counts against it too.
A pass rate that quietly omits the awkward cases is a marketing figure.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import yaml

CORPUS_DIR = Path(__file__).resolve().parent

EXPECT_VALUES = frozenset({"denied", "allowed", "not_prevented"})
REQUIRES_VALUES = frozenset({"policy", "proxy", "sandbox"})
CHECK_VALUES = frozenset({"egress", "filesystem"})

REQUIRED_FIELDS = ("id", "title", "chain_link", "ecosystem", "source", "expect", "requires")


class ScenarioError(Exception):
    """A scenario file is malformed. Loud, because a corpus that silently drops
    a malformed scenario reports a better number than it earned."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 443


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    chain_link: int
    ecosystem: str
    source: str
    expect: str
    requires: str
    note: str = ""
    check: str = "egress"
    target: Optional[Target] = None
    paths: Sequence[str] = field(default_factory=tuple)
    enable: Sequence[str] = field(default_factory=tuple)
    path: Optional[Path] = None

    @property
    def documents_a_gap(self) -> bool:
        return self.expect == "not_prevented"


def _require(data: dict, name: str, source: Path):
    if name not in data:
        raise ScenarioError(f"{source.name}: missing required field '{name}'")
    return data[name]


def parse_scenario(data: dict, source: Path) -> Scenario:
    if not isinstance(data, dict):
        raise ScenarioError(f"{source.name}: expected a mapping at the top level")

    for name in REQUIRED_FIELDS:
        _require(data, name, source)

    expect = data["expect"]
    if expect not in EXPECT_VALUES:
        raise ScenarioError(
            f"{source.name}: expect must be one of {sorted(EXPECT_VALUES)}, got {expect!r}"
        )

    requires = data["requires"]
    if requires not in REQUIRES_VALUES:
        raise ScenarioError(
            f"{source.name}: requires must be one of {sorted(REQUIRES_VALUES)}, got {requires!r}"
        )

    check = data.get("check", "egress")
    if check not in CHECK_VALUES:
        raise ScenarioError(
            f"{source.name}: check must be one of {sorted(CHECK_VALUES)}, got {check!r}"
        )

    target = None
    if check == "egress":
        raw = data.get("target")
        if not isinstance(raw, dict) or "host" not in raw:
            raise ScenarioError(f"{source.name}: an egress scenario needs target.host")
        target = Target(host=str(raw["host"]), port=int(raw.get("port", 443)))

    paths = tuple(data.get("paths", ()))
    if check == "filesystem" and not paths:
        raise ScenarioError(f"{source.name}: a filesystem scenario needs a non-empty 'paths'")

    if data["id"] != source.stem:
        raise ScenarioError(
            f"{source.name}: id {data['id']!r} does not match the filename"
        )

    return Scenario(
        id=data["id"],
        title=data["title"],
        chain_link=int(data["chain_link"]),
        ecosystem=data["ecosystem"],
        source=data["source"],
        expect=expect,
        requires=requires,
        note=data.get("note", "").strip(),
        check=check,
        target=target,
        paths=paths,
        enable=tuple(data.get("enable", ())),
        path=source,
    )


def load_scenario(path: Path) -> Scenario:
    with open(path) as handle:
        return parse_scenario(yaml.safe_load(handle), path)


def load_corpus(directory: Optional[Path] = None) -> List[Scenario]:
    directory = directory or CORPUS_DIR
    scenarios = [load_scenario(p) for p in sorted(directory.glob("*.yaml"))]
    seen: Dict[str, Path] = {}
    for scenario in scenarios:
        if scenario.id in seen:
            raise ScenarioError(f"duplicate scenario id {scenario.id!r}")
        seen[scenario.id] = scenario.path
    return scenarios
