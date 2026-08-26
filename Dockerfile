# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# See docs/docker.md for usage, build targets, and hardened runtime examples.

# Per-target builder stages using rust-cross/rust-musl-cross base images.
# Each image ships a pre-built musl cross toolchain, Rust with
# CARGO_BUILD_TARGET pre-set to its triple, and a configured linker, so
# `cargo build` produces a static binary for that target. No QEMU emulation
# when the host arch matches the image arch.
#
# These images are linux/amd64. On amd64 build hosts (CI's ubuntu-latest)
# they run natively. On arm64 build hosts (Apple Silicon) Docker falls back
# to QEMU emulation for the C compile steps.
ARG TOOLCHAIN_PLATFORM=linux/amd64

# Build context has no .git/, so the rite crate's build.rs records "unknown" for the
# commit unless these are injected. Defaults make local `docker build` work
# without ceremony; CI passes the real SHA and date via bake.
ARG RITE_BUILD_COMMIT=unknown
ARG RITE_BUILD_COMMIT_DATE=unknown

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:x86_64-musl@sha256:ce75e9174325d4fbb3de85c309e2d7ca29f7500169bc4b5d2c611ff7e86d549a AS builder-amd64
WORKDIR /src
ARG CARGO_BUILD_ARGS="--features openssl-vendored"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Commit ARGs declared at the RUN to keep the COPY layer cache-stable across
# commits; only the cargo build layer invalidates (and cargo's target cache
# mount keeps the incremental rebuild tiny, just the rite crate's final link).
# Per-target cache IDs so the two builder stages can run in parallel under bake without racing.
ARG RITE_BUILD_COMMIT
ARG RITE_BUILD_COMMIT_DATE
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-amd64 \
    --mount=type=cache,target=/src/target,id=cargo-target-amd64 \
    RITE_BUILD_COMMIT="$RITE_BUILD_COMMIT" \
    RITE_BUILD_COMMIT_DATE="$RITE_BUILD_COMMIT_DATE" \
    cargo build --locked --release -p rite $CARGO_BUILD_ARGS && \
    cargo build --locked --release -p rite-ls && \
    install -D -m 0755 target/x86_64-unknown-linux-musl/release/rite    /out/rite && \
    install -D -m 0755 target/x86_64-unknown-linux-musl/release/rite-ls /out/rite-ls

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:aarch64-musl@sha256:ecae5dd62d1c938c14f8071d36c16fa699860aace03bfb5284fb1216474d2643 AS builder-arm64
WORKDIR /src
ARG CARGO_BUILD_ARGS="--features openssl-vendored"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ARG RITE_BUILD_COMMIT
ARG RITE_BUILD_COMMIT_DATE
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-arm64 \
    --mount=type=cache,target=/src/target,id=cargo-target-arm64 \
    RITE_BUILD_COMMIT="$RITE_BUILD_COMMIT" \
    RITE_BUILD_COMMIT_DATE="$RITE_BUILD_COMMIT_DATE" \
    cargo build --locked --release -p rite $CARGO_BUILD_ARGS && \
    cargo build --locked --release -p rite-ls && \
    install -D -m 0755 target/aarch64-unknown-linux-musl/release/rite    /out/rite && \
    install -D -m 0755 target/aarch64-unknown-linux-musl/release/rite-ls /out/rite-ls

FROM scratch AS binaries-amd64
COPY --from=builder-amd64 /out/rite    /rite
COPY --from=builder-amd64 /out/rite-ls /rite-ls

FROM scratch AS binaries-arm64
COPY --from=builder-arm64 /out/rite    /rite
COPY --from=builder-arm64 /out/rite-ls /rite-ls

# glibc builder for the published image. Unlike the musl cross stages above
# (which feed the static, software-only release tarballs and pin `--platform` to
# the toolchain arch), this stage sets no `--platform`, so buildx builds it once
# per target arch under the `image` target: amd64 natively, arm64 emulated via
# QEMU. It dynamically links libpcsclite and
# system OpenSSL, so the image binary can carry the piv/yubikey smart-card
# backends the static musl build cannot. It builds only `rite`; `rite-ls` is a
# release-tarball artifact, not part of the image.
FROM rust:1.97.1-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c AS builder-image
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
# Default feature set (which includes system OpenSSL) plus the hardware backends.
ARG CARGO_BUILD_ARGS="--features piv,yubikey"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# TARGETARCH keeps the cache mounts per-arch so the two platform builds never
# share a target dir. Commit ARGs at the RUN to keep the COPY layer cache-stable.
ARG TARGETARCH
ARG RITE_BUILD_COMMIT
ARG RITE_BUILD_COMMIT_DATE
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-image-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=cargo-target-image-${TARGETARCH} \
    RITE_BUILD_COMMIT="$RITE_BUILD_COMMIT" \
    RITE_BUILD_COMMIT_DATE="$RITE_BUILD_COMMIT_DATE" \
    cargo build --locked --release -p rite $CARGO_BUILD_ARGS && \
    install -D -m 0755 target/release/rite /out/rite

FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS runtime-base

# libssl3 and libpcsclite1 are the shared libraries the glibc image binary links
# (system OpenSSL + PC/SC). The pcscd daemon and CCID driver are not installed:
# they are only needed to open a real card, which the container does by mounting
# the host's PC/SC socket. See docs/docker.md.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
    libssl3 \
    libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 rite \
    && useradd --system --uid 1001 --gid 1001 --create-home --home-dir /home/rite rite \
    && mkdir -p /workspace \
    && chown -R rite:rite /workspace /home/rite

WORKDIR /workspace
ENV HOME=/home/rite

ENTRYPOINT ["rite"]
CMD ["--help"]

FROM runtime-base AS release
COPY --from=builder-image /out/rite /usr/local/bin/rite
USER rite
