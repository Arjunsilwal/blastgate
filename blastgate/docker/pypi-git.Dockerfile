# Install image for Python projects that declare git dependencies.
#
# python:3.12-alpine ships without git, and pip shells out to git to install a
# git+https requirement even when the repository is already local.
#
# git here never reaches a forge. By the time this image runs the forge is not
# in the allowlist and there is no route to one; git reads from the read-only
# mirror the resolve phase produced.
FROM python:3.12-alpine

RUN apk add --no-cache git

ENV GIT_TERMINAL_PROMPT=0
