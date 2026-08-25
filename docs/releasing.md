# Releasing

A release is: a version bump, a changelog entry, a tag, and a workflow that
refuses to publish anything broken. Nothing here needs a maintainer's laptop.

## One-time setup on PyPI

Publishing uses **trusted publishing**, so no API token is stored in this
repository. A token in a repository secret is a long-lived credential that can
be stolen, which is the subject of this project; OIDC avoids having one.

Someone with the PyPI account has to configure it once, at
<https://pypi.org/manage/account/publishing/>:

| Field | Value |
| --- | --- |
| PyPI project name | `blastgate` |
| Owner | `Arjunsilwal` |
| Repository | `blastgate` |
| Workflow | `release.yml` |
| Environment | `pypi` |

Then create a GitHub environment named `pypi` in the repository settings. Adding
required reviewers to it means a human approves each publish.

Until that is configured the release workflow builds and verifies but the
publish step fails. That is the correct order: it is better to discover the
setup is missing than to discover a token is.

## Cutting a release

1. Update `version` in `pyproject.toml`.
2. Move the `Unreleased` entries in `CHANGELOG.md` under the new version.
3. Commit, then tag: `git tag v0.1.0 && git push origin v0.1.0`.

The workflow then builds, and refuses to publish if:

- `twine check` fails,
- the wheel is missing any allowlist or the proxy Dockerfile,
- the tag does not match the version in `pyproject.toml`.

The wheel-contents check exists because the first wheel this project built
contained the modules and nothing else. It imported perfectly and could not
load a single policy.

## Verifying a release by hand

```bash
python -m venv /tmp/probe
/tmp/probe/bin/pip install blastgate
cd /tmp
PYTHONSAFEPATH=1 /tmp/probe/bin/blast check npm registry.npmjs.org
```

`PYTHONSAFEPATH=1` keeps the current directory off `sys.path`. Without it a
checkout in the working directory shadows the installed package, and the check
passes while proving nothing — which is exactly what happened the first time
this was tested.
