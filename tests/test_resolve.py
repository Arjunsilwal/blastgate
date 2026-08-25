"""Tests for resolve.py: deciding what a project declares.

Pure, so all of it runs without a container runtime. The costly mistakes here
are quiet ones. A version range read as a repository sends the resolve phase to
a forge for something that was never there; a repository read as a version
leaves the install to find a forge it cannot reach, which fails late and
confusingly.
"""

import json

import pytest

from blastgate.resolve import (
    CACHE_MOUNT,
    ResolveError,
    UnresolvableDependencyError,
    parse_git_dependencies,
    parse_git_spec,
    write_git_redirect_config,
)


class TestGitSpecParsing:
    """What counts as a git dependency, decided by reading and nothing else."""

    @pytest.mark.parametrize("spec,host,path,ref", [
        ("git+https://github.com/o/r.git#v1", "github.com", "o/r", "v1"),
        ("https://gitlab.com/o/r.git", "gitlab.com", "o/r", None),
        ("github:o/r#main", "github.com", "o/r", "main"),
        ("gitlab:o/r", "gitlab.com", "o/r", None),
        ("bitbucket:o/r", "bitbucket.org", "o/r", None),
        ("o/r", "github.com", "o/r", None),
        # npm writes ssh forms into lockfiles as a matter of course. Fetching
        # happens over https regardless: same repository, a transport the proxy
        # can enforce, and no key present to authenticate with anyway.
        ("git+ssh://git@github.com/o/r.git", "github.com", "o/r", None),
        ("git@github.com:o/r.git", "github.com", "o/r", None),
    ])
    def test_recognised_git_specs(self, spec, host, path, ref):
        dependency = parse_git_spec("pkg", spec)
        assert dependency is not None
        assert (dependency.host, dependency.path, dependency.ref) == (host, path, ref)
        assert dependency.fetch_url.startswith("https://")

    @pytest.mark.parametrize("spec", [
        "^1.0.0", "~2.3.4", ">=1.0.0 <2.0.0", "1.2.3", "latest", "*",
        "file:../local", "npm:other@1.0", "workspace:*", "",
    ])
    def test_version_specs_are_not_git_dependencies(self, spec):
        # A false positive here sends the resolve phase to a forge for
        # something that was never a repository.
        assert parse_git_spec("pkg", spec) is None

    def test_unencrypted_git_protocol_is_refused(self):
        with pytest.raises(UnresolvableDependencyError, match="unencrypted"):
            parse_git_spec("pkg", "git://github.com/o/r.git")

    def test_an_unknown_forge_is_refused_not_fetched(self):
        with pytest.raises(UnresolvableDependencyError, match="not a resolvable forge"):
            parse_git_spec("pkg", "https://forge.attacker.test/o/r.git")

    def test_dependencies_come_from_the_lockfile_too(self, tmp_path):
        # Transitive git dependencies appear only in the lockfile. One missed
        # here is one the install tries to fetch itself, from a forge it cannot
        # reach.
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"direct": "github:o/direct"},
        }))
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "packages": {
                "node_modules/transitive": {
                    "name": "transitive",
                    "resolved": "git+ssh://git@github.com/o/transitive.git",
                },
                "node_modules/normal": {
                    "name": "normal",
                    "resolved": "https://registry.npmjs.org/normal/-/normal-1.0.0.tgz",
                },
            },
        }))
        found = {d.path for d in parse_git_dependencies(tmp_path)}
        assert found == {"o/direct", "o/transitive"}

    def test_an_unparseable_manifest_refuses_rather_than_guesses(self, tmp_path):
        (tmp_path / "package.json").write_text("{ this is not json")
        with pytest.raises(ResolveError, match="Refusing to run"):
            parse_git_dependencies(tmp_path)

    def test_a_project_with_no_manifest_has_no_git_dependencies(self, tmp_path):
        assert parse_git_dependencies(tmp_path) == []


class TestGitRedirectConfig:
    def test_every_url_form_for_a_host_is_rewritten(self, tmp_path):
        # npm uses whichever form the dependency was declared in. A rewrite
        # covering only one of them sends the rest to a forge that is denied.
        text = write_git_redirect_config(tmp_path, ["github.com"]).read_text()
        assert f'[url "{CACHE_MOUNT}/github.com/"]' in text
        for form in (
            "https://github.com/",
            "git+https://github.com/",
            "ssh://git@github.com/",
            "git@github.com:",
        ):
            assert f"insteadOf = {form}" in text


class TestCloneScript:
    """The script the resolve phase runs. Pure text, so it is cheap to check.

    It went untested when this lived in runner.py and a missing import in it
    only surfaced through a container test. That is the wrong place to find out.
    """

    def test_each_dependency_is_cloned_into_the_cache(self):
        from blastgate.resolve import clone_script

        deps = [
            parse_git_spec("a", "github:o/a"),
            parse_git_spec("b", "gitlab:o/b"),
        ]
        script = clone_script(deps)
        assert "https://github.com/o/a.git" in script
        assert "https://gitlab.com/o/b.git" in script
        assert "/workspace/github.com/o/a.git" in script
        assert "/workspace/gitlab.com/o/b.git" in script

    def test_the_script_stops_on_the_first_failure(self):
        # Without set -e a failed clone would be reported as success and the
        # install would go looking for the missing repository itself.
        from blastgate.resolve import clone_script

        assert clone_script([parse_git_spec("a", "github:o/a")]).startswith("set -e")

    def test_success_is_signalled_explicitly(self):
        from blastgate.resolve import clone_script

        assert clone_script([parse_git_spec("a", "github:o/a")]).rstrip().endswith("echo RESOLVE_OK")

    def test_an_existing_mirror_is_updated_rather_than_recloned(self):
        from blastgate.resolve import clone_script

        script = clone_script([parse_git_spec("a", "github:o/a")])
        assert "fetch --prune" in script
        assert "git clone --mirror" in script

    def test_shell_metacharacters_cannot_escape_the_script(self):
        # The parser's charset already rejects these, so this is the second
        # layer. It is tested by constructing the dependency directly, because
        # the point is that quoting holds even if the parser one day does not.
        from blastgate.resolve import GitDependency, clone_script

        hostile = GitDependency(
            name="evil", host="github.com",
            path="o/r; touch /tmp/pwned; echo", ref=None, origin="constructed",
        )
        script = clone_script([hostile])
        assert "'https://github.com/o/r; touch /tmp/pwned; echo.git'" in script
        # Never as a bare command.
        assert "\n  touch /tmp/pwned" not in script

    def test_no_dependencies_produces_a_script_that_still_succeeds(self):
        from blastgate.resolve import clone_script

        assert clone_script([]).strip() == "set -e\necho RESOLVE_OK"


class TestInstallPhaseConditions:
    """Which conditions survive into the install phase, per ecosystem.

    This exists because stripping git-dependencies everywhere was a regression.
    npm gained a resolve phase to replace the grant; pypi and cargo did not, so
    for them the flag silently granted nothing and every project with a git
    dependency failed. It was caught by running the compatibility check against
    cargo, not by any test, which is why there is one now.
    """

    def test_npm_moves_forge_access_into_the_resolve_phase(self):
        from blastgate.resolve import install_phase_conditions

        assert install_phase_conditions("npm", {"git-dependencies"}) == set()

    @pytest.mark.parametrize("ecosystem", ["pypi", "cargo"])
    def test_pypi_and_cargo_also_move_forge_access_into_the_resolve_phase(self, ecosystem):
        from blastgate.resolve import install_phase_conditions

        assert install_phase_conditions(ecosystem, {"git-dependencies"}) == set()

    def test_an_ecosystem_without_a_parser_keeps_the_old_grant(self):
        # Weaker, and deliberately so: removing the grant without providing the
        # phase that replaces it breaks the install instead of protecting it.
        from blastgate.resolve import install_phase_conditions

        assert install_phase_conditions("golang", {"git-dependencies"}) == {"git-dependencies"}

    def test_unrelated_conditions_are_never_stripped(self):
        from blastgate.resolve import install_phase_conditions

        assert install_phase_conditions("npm", {"something-else"}) == {"something-else"}

    def test_nothing_enabled_stays_nothing(self):
        from blastgate.resolve import install_phase_conditions

        for ecosystem in ("npm", "pypi", "cargo"):
            assert install_phase_conditions(ecosystem, set()) == set()

    def test_every_resolve_capable_ecosystem_can_actually_parse_manifests(self, tmp_path):
        # A name added to RESOLVE_CAPABLE_ECOSYSTEMS without a parser to match
        # would reintroduce the exact regression this class exists for.
        from blastgate.resolve import RESOLVE_CAPABLE_ECOSYSTEMS

        assert RESOLVE_CAPABLE_ECOSYSTEMS == {"npm", "pypi", "cargo"}, (
            "adding an ecosystem here requires parse_git_dependencies to read "
            "its manifests, or --allow git-dependencies grants nothing there"
        )


class TestPipRequirements:
    """pip spells a git dependency differently from npm: @ref, not #ref."""

    @pytest.mark.parametrize("line,host,path,ref,name", [
        ("git+https://github.com/o/r.git@v1#egg=pkg", "github.com", "o/r", "v1", "pkg"),
        ("pkg @ git+https://github.com/o/r@main", "github.com", "o/r", "main", "pkg"),
        ("-e git+https://github.com/o/r#egg=pkg", "github.com", "o/r", None, "pkg"),
        ("git+ssh://git@gitlab.com/o/r.git", "gitlab.com", "o/r", None, "r"),
    ])
    def test_recognised_requirements(self, line, host, path, ref, name):
        from blastgate.resolve import parse_pip_requirement

        dependency = parse_pip_requirement(line)
        assert dependency is not None
        assert (dependency.host, dependency.path, dependency.ref) == (host, path, ref)
        assert dependency.name == name

    @pytest.mark.parametrize("line", [
        "requests==2.32.3", "flask>=2.0,<3", "# a comment", "",
        "-r other-requirements.txt", "./local-package", "https://example.test/x.whl",
    ])
    def test_ordinary_requirements_are_not_git_dependencies(self, line):
        from blastgate.resolve import parse_pip_requirement

        assert parse_pip_requirement(line) is None

    def test_unencrypted_git_is_refused(self):
        from blastgate.resolve import parse_pip_requirement

        with pytest.raises(UnresolvableDependencyError, match="unencrypted"):
            parse_pip_requirement("git+git://github.com/o/r")

    def test_requirements_and_pyproject_are_both_read(self, tmp_path):
        from blastgate.resolve import parse_git_dependencies

        (tmp_path / "requirements.txt").write_text(
            "requests==2.32.3\ngit+https://github.com/o/from-requirements#egg=a\n"
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "1"\n'
            'dependencies = ["b @ git+https://github.com/o/from-pyproject"]\n'
        )
        found = {d.path for d in parse_git_dependencies(tmp_path, "pypi")}
        assert found == {"o/from-requirements", "o/from-pyproject"}


class TestCargoSources:
    def test_a_git_dependency_in_the_manifest(self, tmp_path):
        from blastgate.resolve import parse_git_dependencies

        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n'
            'anyhow = { git = "https://github.com/dtolnay/anyhow", tag = "1.0.93" }\n'
            'serde = "1.0"\n'
        )
        found = parse_git_dependencies(tmp_path, "cargo")
        assert [d.path for d in found] == ["dtolnay/anyhow"]
        assert found[0].ref == "1.0.93"

    def test_the_crates_registry_is_not_a_git_dependency(self, tmp_path):
        # Cargo.lock spells the registry as a GitHub URL. Reading it as a git
        # dependency would send the resolve phase after the whole index.
        from blastgate.resolve import parse_cargo_source

        assert parse_cargo_source(
            "serde", "registry+https://github.com/rust-lang/crates.io-index"
        ) is None

    def test_git_sources_come_from_the_lockfile_too(self, tmp_path):
        from blastgate.resolve import parse_git_dependencies

        (tmp_path / "Cargo.lock").write_text(
            '[[package]]\nname = "anyhow"\nversion = "1.0.93"\n'
            'source = "git+https://github.com/dtolnay/anyhow?tag=1.0.93#abc123"\n\n'
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        found = parse_git_dependencies(tmp_path, "cargo")
        assert [d.path for d in found] == ["dtolnay/anyhow"]
        assert found[0].ref == "1.0.93"

    def test_dev_and_build_dependencies_are_read(self, tmp_path):
        from blastgate.resolve import parse_git_dependencies

        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "0.1.0"\n\n[dev-dependencies]\n'
            'a = { git = "https://github.com/o/dev" }\n\n[build-dependencies]\n'
            'b = { git = "https://github.com/o/build" }\n'
        )
        found = {d.path for d in parse_git_dependencies(tmp_path, "cargo")}
        assert found == {"o/dev", "o/build"}

    def test_an_unparseable_manifest_refuses(self, tmp_path):
        from blastgate.resolve import parse_git_dependencies

        (tmp_path / "Cargo.toml").write_text("[package\nthis is not toml")
        with pytest.raises(ResolveError, match="Refusing to run"):
            parse_git_dependencies(tmp_path, "cargo")


class TestEveryCapableEcosystemHasAParser:
    def test_no_ecosystem_is_listed_without_a_parser(self, tmp_path):
        # The regression this guards was exactly this mismatch: an ecosystem
        # whose grant was removed with nothing to replace it.
        from blastgate.resolve import RESOLVE_CAPABLE_ECOSYSTEMS, parse_git_dependencies

        for ecosystem in RESOLVE_CAPABLE_ECOSYSTEMS:
            assert parse_git_dependencies(tmp_path, ecosystem) == []

    def test_each_capable_ecosystem_has_a_resolve_allowlist(self):
        from blastgate.policy import load_policy
        from blastgate.resolve import RESOLVE_CAPABLE_ECOSYSTEMS, resolve_policy_for

        for ecosystem in RESOLVE_CAPABLE_ECOSYSTEMS:
            policy = load_policy(resolve_policy_for(ecosystem))
            assert policy.evaluate("github.com").allowed is True

    @pytest.mark.parametrize("ecosystem,registry", [
        ("npm", "registry.npmjs.org"), ("pypi", "pypi.org"), ("cargo", "crates.io"),
    ])
    def test_a_resolve_policy_denies_its_own_registry(self, ecosystem, registry):
        # Resolution fetches git refs. Anything reaching for a package index
        # under a resolve policy is not resolution.
        from blastgate.policy import load_policy
        from blastgate.resolve import resolve_policy_for

        policy = load_policy(resolve_policy_for(ecosystem))
        assert policy.evaluate(registry).allowed is False

    def test_each_capable_ecosystem_has_a_git_capable_image(self):
        from blastgate.resolve import RESOLVE_CAPABLE_ECOSYSTEMS
        from blastgate.runner import install_dockerfile_for

        for ecosystem in RESOLVE_CAPABLE_ECOSYSTEMS:
            assert install_dockerfile_for(ecosystem).is_file()
