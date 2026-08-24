"""Tests for resolve.py: deciding what a project declares.

Pure, so all of it runs without a container runtime. The costly mistakes here
are quiet ones. A version range read as a repository sends the resolve phase to
a forge for something that was never there; a repository read as a version
leaves the install to find a forge it cannot reach, which fails late and
confusingly.
"""

import json

import pytest

from bulkhead.resolve import (
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
        from bulkhead.resolve import clone_script

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
        from bulkhead.resolve import clone_script

        assert clone_script([parse_git_spec("a", "github:o/a")]).startswith("set -e")

    def test_success_is_signalled_explicitly(self):
        from bulkhead.resolve import clone_script

        assert clone_script([parse_git_spec("a", "github:o/a")]).rstrip().endswith("echo RESOLVE_OK")

    def test_an_existing_mirror_is_updated_rather_than_recloned(self):
        from bulkhead.resolve import clone_script

        script = clone_script([parse_git_spec("a", "github:o/a")])
        assert "fetch --prune" in script
        assert "git clone --mirror" in script

    def test_shell_metacharacters_cannot_escape_the_script(self):
        # The parser's charset already rejects these, so this is the second
        # layer. It is tested by constructing the dependency directly, because
        # the point is that quoting holds even if the parser one day does not.
        from bulkhead.resolve import GitDependency, clone_script

        hostile = GitDependency(
            name="evil", host="github.com",
            path="o/r; touch /tmp/pwned; echo", ref=None, origin="constructed",
        )
        script = clone_script([hostile])
        assert "'https://github.com/o/r; touch /tmp/pwned; echo.git'" in script
        # Never as a bare command.
        assert "\n  touch /tmp/pwned" not in script

    def test_no_dependencies_produces_a_script_that_still_succeeds(self):
        from bulkhead.resolve import clone_script

        assert clone_script([]).strip() == "set -e\necho RESOLVE_OK"
