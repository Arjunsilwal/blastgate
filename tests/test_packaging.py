"""Tests that an installed copy is a working copy.

The first wheel this project built contained the Python modules and nothing
else: no allowlists, no Dockerfiles. It imported cleanly and failed on the
first real command, because policy loading and image building both read files
that were never packaged. None of that was visible from a source checkout,
where the missing files happen to sit one directory up.
"""

from pathlib import Path
import subprocess
import sys

import pytest

from blastgate.policy import load_policy
from blastgate.runner import (
    DEFAULT_IMAGES,
    install_dockerfile_for,
    package_dir,
)

ECOSYSTEMS = sorted(DEFAULT_IMAGES)


class TestDataShipsWithTheCode:
    @pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
    def test_every_ecosystem_allowlist_is_inside_the_package(self, ecosystem):
        path = package_dir() / "allowlists" / f"{ecosystem}.yaml"
        assert path.is_file(), f"{path} would not be installed"

    @pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
    def test_every_resolve_allowlist_is_inside_the_package(self, ecosystem):
        path = package_dir() / "allowlists" / f"{ecosystem}-resolve.yaml"
        assert path.is_file(), f"{path} would not be installed"

    @pytest.mark.parametrize("ecosystem", ECOSYSTEMS)
    def test_every_install_dockerfile_is_inside_the_package(self, ecosystem):
        assert install_dockerfile_for(ecosystem).is_file()

    def test_the_proxy_dockerfile_is_inside_the_package(self):
        assert (package_dir() / "docker" / "proxy.Dockerfile").is_file()

    def test_nothing_resolves_above_the_package(self):
        # A repo-root heuristic worked in a checkout and resolved to
        # site-packages once installed, which would have handed Docker the
        # whole environment as a build context.
        source = (package_dir() / "runner.py").read_text()
        assert "parent.parent" not in source
        assert "_repo_root" not in source

    def test_policies_load_without_a_source_tree(self):
        for ecosystem in ECOSYSTEMS:
            assert load_policy(ecosystem).ecosystem == ecosystem


class TestUserFacingNames:
    def test_no_output_still_uses_the_old_command_name(self):
        # `bh: egress decisions recorded` survived the rename because the
        # source read "\nbh:", so the n of the escape sat against bh and the
        # word boundary never matched. It was only visible by running the
        # command.
        offenders = []
        for path in sorted(package_dir().glob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if "bh:" in line or '"bh"' in line:
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
        assert not offenders, offenders

    def test_the_console_script_is_named_blast(self):
        root = package_dir().parent
        pyproject = root / "pyproject.toml"
        if not pyproject.is_file():
            pytest.skip("not running from a source checkout")
        assert 'blast = "blastgate.cli:main"' in pyproject.read_text()


@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    root = package_dir().parent
    if not (root / "pyproject.toml").is_file():
        pytest.skip("not running from a source checkout")
    out = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "-o", str(out), str(root)],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        pytest.skip(f"build unavailable: {result.stderr[-200:]}")
    wheels = list(out.glob("*.whl"))
    assert wheels, "no wheel produced"
    return wheels[0]


class TestBuiltDistribution:
    """Build a wheel and look inside it. Slow, and the only check that would
    have caught the empty wheel before it was published."""

    def test_the_wheel_contains_every_allowlist(self, wheel):
        import zipfile

        names = set(zipfile.ZipFile(wheel).namelist())
        for ecosystem in ECOSYSTEMS:
            for suffix in ("", "-resolve"):
                entry = f"blastgate/allowlists/{ecosystem}{suffix}.yaml"
                assert entry in names, f"{entry} missing from the wheel"

    def test_the_wheel_contains_every_dockerfile(self, wheel):
        import zipfile

        names = set(zipfile.ZipFile(wheel).namelist())
        assert "blastgate/docker/proxy.Dockerfile" in names
        for ecosystem in ECOSYSTEMS:
            assert f"blastgate/docker/{ecosystem}-git.Dockerfile" in names
