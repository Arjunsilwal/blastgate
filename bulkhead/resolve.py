"""What to fetch before an install runs, and where it goes.

Deliberately pure, for the same reason policy.py is: it executes nothing,
touches no container and starts no process, so it can be tested exhaustively
without a runtime. Everything here is a decision made by reading files.

The split from runner.py follows that line. Deciding what a project declares is
reading and parsing; fetching it is topology, and topology is runner's job.
This is the layer where a mistake is quietest. A version range misread as a
repository sends the resolve phase somewhere nobody asked it to go, and a
repository misread as a version leaves the install to find a forge that is
deliberately unreachable.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
from typing import Dict, Iterable, List, Optional, Sequence

try:                                  # Python 3.11+
    import tomllib
except ModuleNotFoundError:           # 3.10, via the backport
    import tomli as tomllib

from bulkhead import BulkheadError


class ResolveError(BulkheadError):
    """A project's dependency set cannot be determined."""


#
# Git dependencies are needed during resolution. The payload runs during
# install. Those are only the same phase because nothing separates them, so
# this separates them.
#
# Everything below decides WHAT to fetch by reading files. It executes nothing
# and it runs before any container exists. Anything it cannot parse with
# confidence is refused rather than guessed at, because a guess here turns into
# either a missing dependency or an unexpected host.

GIT_CACHE_DIR = Path.home() / ".bulkhead" / "git-cache"

# Hosts a declared dependency may be fetched from during resolution. Kept in
# step with allowlists/npm-resolve.yaml; policy is still the decider, this is
# only used to reject a spec early with a clearer message.
RESOLVABLE_FORGES = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

FORGE_PREFIXES = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}

# The condition that no longer opens a forge to the install. It permits the
# resolve phase to run instead.
RESOLVE_ONLY_CONDITIONS = frozenset({"git-dependencies"})

# ...but only where a resolve phase exists to do the fetching. Reading git
# dependencies is manifest-specific, so each ecosystem needs a parser before it
# can be listed here.
#
# Stripping the condition without a parser to match is a regression, not a
# hardening: it removes the grant while providing nothing to replace it, so
# --allow git-dependencies silently grants nothing and every project with a git
# dependency fails. That shipped once, for pypi and cargo, and was caught by the
# compatibility check rather than by a test. The test now exists.
RESOLVE_CAPABLE_ECOSYSTEMS = frozenset({"npm", "pypi", "cargo"})


def resolve_policy_for(ecosystem: str) -> str:
    """The allowlist the resolve phase runs under, per ecosystem.

    Separate files rather than one shared policy. They are near-identical
    today, and each one has to be able to deny its own registry independently:
    resolution fetches git refs, so anything reaching for a package index under
    a resolve policy is not resolution.
    """
    return f"{ecosystem}-resolve"


def install_phase_conditions(ecosystem: str, enabled: set) -> set:
    """Which conditions the install phase is allowed to see.

    Where a resolve phase exists, forge access moves entirely into it. Where
    one does not, the condition keeps its older, weaker meaning rather than
    being removed and breaking the install.
    """
    if ecosystem in RESOLVE_CAPABLE_ECOSYSTEMS:
        return set(enabled) - RESOLVE_ONLY_CONDITIONS
    return set(enabled)

_GIT_HTTPS_RE = re.compile(
    r"^(?:git\+)?https://(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
# npm writes ssh forms into lockfiles as a matter of course. Fetching is done
# over https regardless: the repository is the same, the transport is one the
# proxy can enforce, and no key is present to authenticate with anyway.
_GIT_SSH_RE = re.compile(
    r"^(?:git\+)?ssh://git@(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_GIT_SCP_RE = re.compile(
    r"^git@(?P<host>[A-Za-z0-9.-]+):(?P<path>[A-Za-z0-9._/-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_SHORTHAND_RE = re.compile(
    r"^(?:(?P<forge>github|gitlab|bitbucket):)?"
    r"(?P<path>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s#]+))?$"
)
_UNENCRYPTED_RE = re.compile(r"^(?:git\+)?git://")


class UnresolvableDependencyError(ResolveError):
    """A declared git dependency cannot be fetched safely.

    Raised rather than skipped. Skipping would leave the install to discover
    the dependency itself, at which point it needs a forge that is deliberately
    unreachable, and the failure would surface as something less clear.
    """


@dataclass(frozen=True)
class GitDependency:
    name: str
    host: str
    path: str          # owner/repo, no .git suffix
    ref: Optional[str]
    origin: str        # the spec exactly as it was declared

    @property
    def fetch_url(self) -> str:
        return f"https://{self.host}/{self.path}.git"

    @property
    def cache_subpath(self) -> str:
        return f"{self.host}/{self.path}.git"


def parse_git_spec(name: str, spec: str) -> Optional[GitDependency]:
    """Interpret one dependency spec. None if it is not a git dependency.

    Raises UnresolvableDependencyError for a spec that is recognisably a git
    dependency but cannot be fetched under this design.
    """
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    if not spec:
        return None

    if _UNENCRYPTED_RE.match(spec):
        raise UnresolvableDependencyError(
            f"dependency {name!r} uses the unencrypted git:// protocol ({spec!r}). "
            f"Bulkhead only tunnels TLS, so this cannot be fetched or enforced. "
            f"Change it to https:// in your manifest."
        )

    # An https URL is only a git dependency when it says so. Lockfiles are full
    # of registry tarball URLs, and reading one of those as a repository would
    # send the resolve phase after a package that was never on a forge - or
    # refuse the install outright, which is what this check exists to prevent.
    url_part = spec.split("#", 1)[0]
    looks_like_git_url = spec.startswith("git+") or url_part.endswith(".git")

    for pattern, always_git in (
        (_GIT_HTTPS_RE, False), (_GIT_SSH_RE, True), (_GIT_SCP_RE, True),
    ):
        match = pattern.match(spec)
        if match:
            if not always_git and not looks_like_git_url:
                return None
            host = match.group("host")
            if host not in RESOLVABLE_FORGES:
                raise UnresolvableDependencyError(
                    f"dependency {name!r} points at {host}, which is not a "
                    f"resolvable forge. Add it to allowlists/npm-resolve.yaml "
                    f"deliberately, or vendor the dependency."
                )
            return GitDependency(
                name=name, host=host, path=match.group("path").rstrip("/"),
                ref=match.group("ref"), origin=spec,
            )

    # Shorthand is only a git dependency when it is unambiguous. A version
    # range, a file: path, an npm: alias and a tag all reach here and must not
    # be mistaken for owner/repo.
    if "/" in spec and not spec[0].isdigit() and spec[0] not in "^~<>=*":
        match = _SHORTHAND_RE.match(spec)
        if match:
            forge = match.group("forge")
            host = FORGE_PREFIXES[forge] if forge else "github.com"
            return GitDependency(
                name=name, host=host, path=match.group("path"),
                ref=match.group("ref"), origin=spec,
            )
    return None


DEPENDENCY_SECTIONS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)


def parse_git_dependencies(
    project_dir: Path, ecosystem: str = "npm"
) -> List[GitDependency]:
    """Every git dependency the project declares, for one ecosystem.

    Reads only. The lockfile matters as much as the manifest: transitive git
    dependencies appear there and nowhere else, and one this misses is one the
    install will try to fetch itself from a forge it cannot reach.

    An ecosystem with no parser returns nothing, which is why
    RESOLVE_CAPABLE_ECOSYSTEMS must never name one that is missing here.
    """
    project_dir = Path(project_dir)
    parsers = {
        "npm": _npm_dependencies,
        "pypi": _pypi_dependencies,
        "cargo": _cargo_dependencies,
    }
    parser = parsers.get(ecosystem)
    if parser is None:
        return []
    return sorted(parser(project_dir).values(), key=lambda d: d.cache_subpath)


def _npm_dependencies(project_dir: Path) -> Dict[str, GitDependency]:
    found: Dict[str, GitDependency] = {}

    manifest = project_dir / "package.json"
    if manifest.is_file():
        data = _read_json(manifest)
        for section in DEPENDENCY_SECTIONS:
            for name, spec in (data.get(section) or {}).items():
                dependency = parse_git_spec(name, spec)
                if dependency:
                    found[dependency.cache_subpath] = dependency

    lockfile = project_dir / "package-lock.json"
    if lockfile.is_file():
        data = _read_json(lockfile)
        for key, entry in (data.get("packages") or {}).items():
            if not isinstance(entry, dict):
                continue
            resolved = entry.get("resolved")
            if not isinstance(resolved, str):
                continue
            dependency = parse_git_spec(entry.get("name") or key or "?", resolved)
            if dependency:
                found.setdefault(dependency.cache_subpath, dependency)

    return found


def _read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as e:
        raise ResolveError(
            f"cannot read {path}: {e}. Refusing to run rather than proceed with "
            f"an unknown set of dependencies."
        )
    if not isinstance(data, dict):
        raise ResolveError(f"{path} does not contain a JSON object")
    return data



GIT_IMAGE = "alpine/git:latest"
CACHE_MOUNT = "/bulkhead-git"
GITCONFIG_NAME = "gitconfig"


def clone_script(dependencies: Sequence[GitDependency]) -> str:
    """A shell script that mirrors each declared repository into the cache.

    --mirror rather than a ref-specific fetch, so the install can resolve any
    ref the manifest names without this phase having to interpret npm's
    resolution rules. Getting that interpretation wrong would mean a missing
    ref at install time, and by then the forge is unreachable by design.
    """
    lines = ["set -e"]
    for dependency in dependencies:
        url = shlex.quote(dependency.fetch_url)
        target = shlex.quote(f"/workspace/{dependency.cache_subpath}")
        lines += [
            f"if [ -d {target} ]; then",
            f"  echo 'update {dependency.cache_subpath}'",
            f"  git --git-dir={target} fetch --prune --quiet origin '+refs/*:refs/*'",
            "else",
            f"  echo 'clone {dependency.cache_subpath}'",
            f"  mkdir -p $(dirname {target})",
            f"  git clone --mirror --quiet {url} {target}",
            "fi",
        ]
    lines.append("echo RESOLVE_OK")
    return "\n".join(lines)


def write_git_redirect_config(cache_dir: Path, hosts: Iterable[str]) -> Path:
    """Point every forge URL form at the local cache.

    Written on the host and mounted read-only, so the install never runs a
    command to configure this and cannot rewrite it. If a repository was not
    fetched, its URL rewrites to a path that does not exist and git fails
    locally. It does not fall back to the network, because there is no network
    to fall back to.
    """
    lines = []
    for host in sorted(set(hosts)):
        local = f"{CACHE_MOUNT}/{host}/"
        lines.append(f'[url "{local}"]')
        for form in (
            f"https://{host}/",
            f"git+https://{host}/",
            f"ssh://git@{host}/",
            f"git+ssh://git@{host}/",
            f"git@{host}:",
        ):
            lines.append(f"\tinsteadOf = {form}")
    path = cache_dir / GITCONFIG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def link_bare_aliases(cache_dir: Path, dependencies: Sequence[GitDependency]) -> None:
    """Make owner/repo resolve as well as owner/repo.git.

    npm asks for both forms depending on how the dependency was declared, and a
    rewrite that only covers one of them fails for the other.
    """
    for dependency in dependencies:
        bare = cache_dir / dependency.cache_subpath
        alias = bare.with_suffix("")
        if bare.is_dir() and not alias.exists():
            try:
                alias.symlink_to(bare.name)
            except OSError:
                pass




# --- pypi -------------------------------------------------------------------
#
# pip shells out to the git CLI, so the same cache and the same insteadOf
# rewriting work here unchanged. Only the spelling of a dependency differs.

_PIP_GIT_RE = re.compile(
    r"^git\+(?:https://|ssh://git@)"
    r"(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)(?:\.git)?"
    r"(?:@(?P<ref>[^\s#]+))?(?:#(?P<fragment>\S*))?$"
)


def parse_pip_requirement(line: str) -> Optional[GitDependency]:
    """One requirement line. None if it is not a git dependency.

    pip writes the ref with @ where npm uses #, and carries the package name in
    an #egg= fragment or a 'name @ url' prefix rather than in a key.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-e ", "--editable ")):
        line = line.split(" ", 1)[1].strip()

    name = ""
    if " @ " in line:
        name, _, line = line.partition(" @ ")
        name, line = name.strip(), line.strip()

    if _UNENCRYPTED_RE.match(line) or line.startswith("git://"):
        raise UnresolvableDependencyError(
            f"requirement {line!r} uses the unencrypted git:// protocol. "
            f"Bulkhead only tunnels TLS. Change it to https://."
        )

    match = _PIP_GIT_RE.match(line)
    if not match:
        return None

    host = match.group("host")
    if host not in RESOLVABLE_FORGES:
        raise UnresolvableDependencyError(
            f"requirement {line!r} points at {host}, which is not a resolvable "
            f"forge. Add it to allowlists/pypi-resolve.yaml deliberately, or "
            f"vendor the dependency."
        )

    fragment = match.group("fragment") or ""
    if not name and fragment.startswith("egg="):
        name = fragment[4:].split("&")[0]
    return GitDependency(
        name=name or match.group("path").rsplit("/", 1)[-1],
        host=host, path=match.group("path").rstrip("/"),
        ref=match.group("ref"), origin=line,
    )


def _pypi_dependencies(project_dir: Path) -> Dict[str, GitDependency]:
    found: Dict[str, GitDependency] = {}

    for name in ("requirements.txt", "requirements-dev.txt", "constraints.txt"):
        path = project_dir / name
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                dependency = parse_pip_requirement(line)
                if dependency:
                    found.setdefault(dependency.cache_subpath, dependency)

    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        data = _read_toml(pyproject)
        project = data.get("project") or {}
        specs = list(project.get("dependencies") or [])
        for group in (project.get("optional-dependencies") or {}).values():
            specs.extend(group or [])
        for spec in specs:
            if isinstance(spec, str):
                dependency = parse_pip_requirement(spec)
                if dependency:
                    found.setdefault(dependency.cache_subpath, dependency)
    return found


# --- cargo ------------------------------------------------------------------
#
# cargo fetches git dependencies with libgit2, which does not honour
# url.insteadOf. CARGO_NET_GIT_FETCH_WITH_CLI makes it shell out to git
# instead, which does. That variable is set by the runner for the install
# phase; without it the rewriting here would be silently ignored and cargo
# would try to reach the forge directly.

_CARGO_SOURCE_RE = re.compile(
    r"^git\+(?:https://|ssh://git@)"
    r"(?P<host>[A-Za-z0-9.-]+)/(?P<path>[A-Za-z0-9._/-]+?)(?:\.git)?"
    r"(?:\?(?P<query>[^#]*))?(?:#(?P<rev>\S*))?$"
)


def parse_cargo_source(name: str, source: str) -> Optional[GitDependency]:
    """A Cargo.lock `source` string, or a [dependencies] git URL."""
    source = source.strip()
    if not source:
        return None
    if source.startswith("git://") or _UNENCRYPTED_RE.match(source):
        raise UnresolvableDependencyError(
            f"dependency {name!r} uses the unencrypted git:// protocol. "
            f"Bulkhead only tunnels TLS. Change it to https://."
        )
    if not source.startswith("git+"):
        # registry sources look like "registry+https://github.com/rust-lang/
        # crates.io-index" and are not git dependencies, however much the URL
        # looks like one.
        return None

    match = _CARGO_SOURCE_RE.match(source)
    if not match:
        return None
    host = match.group("host")
    if host not in RESOLVABLE_FORGES:
        raise UnresolvableDependencyError(
            f"dependency {name!r} points at {host}, which is not a resolvable "
            f"forge. Add it to allowlists/cargo-resolve.yaml deliberately, or "
            f"vendor the dependency."
        )

    ref = None
    query = match.group("query") or ""
    for key in ("tag", "branch", "rev"):
        marker = f"{key}="
        if marker in query:
            ref = query.split(marker, 1)[1].split("&")[0]
            break
    return GitDependency(
        name=name, host=host, path=match.group("path").rstrip("/"),
        ref=ref or (match.group("rev") or None), origin=source,
    )


def _cargo_dependencies(project_dir: Path) -> Dict[str, GitDependency]:
    found: Dict[str, GitDependency] = {}

    manifest = project_dir / "Cargo.toml"
    if manifest.is_file():
        data = _read_toml(manifest)
        sections = [data.get("dependencies") or {}, data.get("dev-dependencies") or {},
                    data.get("build-dependencies") or {}]
        for target in (data.get("target") or {}).values():
            if isinstance(target, dict):
                sections.append(target.get("dependencies") or {})
        for section in sections:
            for name, spec in section.items():
                if not isinstance(spec, dict) or "git" not in spec:
                    continue
                url = str(spec["git"])
                if not url.startswith("git+"):
                    url = "git+" + url
                dependency = parse_cargo_source(name, url)
                if dependency:
                    ref = spec.get("tag") or spec.get("branch") or spec.get("rev")
                    if ref:
                        dependency = GitDependency(
                            name=dependency.name, host=dependency.host,
                            path=dependency.path, ref=str(ref),
                            origin=dependency.origin,
                        )
                    found.setdefault(dependency.cache_subpath, dependency)

    lockfile = project_dir / "Cargo.lock"
    if lockfile.is_file():
        data = _read_toml(lockfile)
        for package in data.get("package") or []:
            if not isinstance(package, dict):
                continue
            source = package.get("source")
            if isinstance(source, str):
                dependency = parse_cargo_source(package.get("name", "?"), source)
                if dependency:
                    found.setdefault(dependency.cache_subpath, dependency)
    return found


def _read_toml(path: Path) -> dict:
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ResolveError(
            f"cannot read {path}: {e}. Refusing to run rather than proceed with "
            f"an unknown set of dependencies."
        )
