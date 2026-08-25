# Install image for npm projects that declare git dependencies.
#
# node:20-alpine ships without git, and npm shells out to git to resolve a
# github: dependency even when the repository is already local. Rather than
# pull the 1.1GB Debian node image for one binary, add the binary.
#
# git here never reaches a forge. By the time this image runs, the forge is not
# in the allowlist and there is no route to one; git reads from the read-only
# mirror the resolve phase produced.
FROM node:20-alpine

# Not version-pinned. Alpine's repository is rolling, so a pin here breaks the
# build the moment upstream moves rather than pinning anything useful. The
# reproducibility that matters comes from the base image tag.
RUN apk add --no-cache git

# npm invokes git non-interactively. A credential prompt would be a hang, and
# there is nothing to authenticate with in any case.
ENV GIT_TERMINAL_PROMPT=0
