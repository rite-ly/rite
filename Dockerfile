# syntax=docker/dockerfile:1.23@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
# See docs/docker.md for usage, build targets, and hardened runtime examples.

# Builder: compiles from source for TARGETPLATFORM.
# Cross-arch builds (e.g. arm64 host -> linux/amd64 image) work via buildx/qemu
# without manually wiring Rust target triples.
FROM --platform=$TARGETPLATFORM rust:1.95-trixie@sha256:5b1e3484ddcd22a3738c0ec34a5e98bf19382eb295fb6db54295e62379119040 AS builder
WORKDIR /src

# Override at build time for custom feature combinations.
# Default is vendored OpenSSL so the resulting binary has no runtime dependency on the system library.
# NOTE: this produces a glibc-linked binary (aarch64-unknown-linux-gnu / x86_64-unknown-linux-gnu).
# That is fine for the Debian runtime targets, but the `binaries` export will not run on Alpine,
# scratch, or the bootable ISO. A musl builder stage is needed for those — deferred to the
# cross-compilation rework.
ARG CARGO_BUILD_ARGS="--features openssl-vendored"

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    sh -euxc 'cargo build --locked --release -p rite-cli ${CARGO_BUILD_ARGS}' && \
    install -D -m 0755 target/release/rite /out/rite

# Prebuilt selector: used by CI/release to avoid rebuilding from source.
# Expects release artifacts copied into dist/ in the build context.
FROM --platform=$TARGETPLATFORM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a AS prebuilt
ARG TARGETARCH

COPY dist/ /dist/

RUN install -D -m 0755 "/dist/rite-linux-${TARGETARCH}-musl/rite" /out/rite

# Runtime base: minimal hardened environment. Runs as non-root.
FROM --platform=$TARGETPLATFORM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 rite \
    && useradd --system --uid 1001 --gid 1001 --create-home --home-dir /home/rite rite \
    && mkdir -p /workspace \
    && chown -R rite:rite /workspace /home/rite

WORKDIR /workspace
ENV HOME=/home/rite

ENTRYPOINT ["rite"]
CMD ["--help"]

# CI/release target: binary sourced from dist/ artifacts.
FROM runtime-base AS release
COPY --from=prebuilt /out/rite /usr/local/bin/rite
USER rite

# Binary export target: extract the compiled binary to the host via --output.
FROM scratch AS binaries
COPY --from=builder /out/rite /rite

# Default target: compiled from source, runs in hardened runtime.
FROM runtime-base AS local
COPY --from=builder /out/rite /usr/local/bin/rite
USER rite
