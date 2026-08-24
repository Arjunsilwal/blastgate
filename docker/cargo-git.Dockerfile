# Install image for Rust projects that declare git dependencies.
#
# cargo fetches git dependencies with libgit2, which does not honour
# url.insteadOf. CARGO_NET_GIT_FETCH_WITH_CLI makes it shell out to the git
# CLI, which does - so the rewriting that points dependencies at the local
# mirror actually takes effect. Without it cargo would ignore the rewrite and
# try to reach the forge directly, and be denied.
FROM rust:1-alpine

RUN apk add --no-cache git

ENV GIT_TERMINAL_PROMPT=0
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
