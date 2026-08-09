# Builds and runs crates/api -- the only workspace member with a real,
# runnable production entry point (see README.md's "Known limitations").
#
# Two stages: build in a full Rust toolchain image (needs cmake/clang/perl
# for aws-lc-sys, pulled in transitively via alloy's TLS stack -- verified
# via `cargo tree -p api -e normal | grep -E '\-sys '`, the only *-sys
# crate api's dependency graph actually needs), then copy just the
# compiled binary into a minimal Debian runtime image. `cargo build -p api`
# only builds api's own dependency graph, not the whole workspace -- so
# unrelated heavy crates (wasmtime-based sandbox, rdma) never enter this
# build at all (confirmed: neither appears in `cargo tree -p api`).
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    perl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

RUN cargo build --release -p api

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin mex

COPY --from=builder --chown=mex:mex /build/target/release/api /usr/local/bin/api

# crates/prover's default trusted-setup path is resolved from
# CARGO_MANIFEST_DIR, a compile-time constant baked into the binary at
# the BUILDER stage's path (/build/crates/prover/trusted_setup.bin) --
# meaningless in this runtime stage's filesystem. Without pointing
# MEX_TRUSTED_SETUP_PATH somewhere real, the binary would silently
# regenerate a fresh, insecure, single-party proving key on every
# container start (see prover::bn254::trusted_setup_path's own docs) --
# a correctness footgun that's easy to miss since it never actually
# fails, just silently produces a key incompatible with any BatchVerifier
# already deployed against the checked-in one. Same dev-only placeholder
# this repo already ships (see README.md's "Known limitations"), just
# copied to a path that exists in THIS image.
COPY --from=builder --chown=mex:mex /build/crates/prover/trusted_setup.bin /app/trusted_setup.bin
ENV MEX_TRUSTED_SETUP_PATH=/app/trusted_setup.bin

USER mex
EXPOSE 8080

# Liveness/readiness: GET /health (added specifically for this, see
# server.rs -- unauthenticated, unlike every other route). No HEALTHCHECK
# instruction here since orchestrators (k8s, etc.) almost always define
# their own probe against this same endpoint instead of relying on
# Docker's built-in one; left to the deployment manifest, not baked in.
ENTRYPOINT ["/usr/local/bin/api"]
