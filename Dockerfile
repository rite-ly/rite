# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
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

# This stage builds the glibc binary for the Docker image, the Live systems and
# the linux-<arch>-glibc release tarballs. It sets no --platform, so buildx
# builds it for each target arch, natively on matching hosts and under QEMU
# otherwise. It links glibc and libpcsclite for the piv/yubikey smart-card
# backends and vendors OpenSSL. Debian bookworm sets the glibc floor at 2.36.
FROM rust:1.99.1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS builder-glibc
WORKDIR /src
# make and perl build the vendored OpenSSL.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite-dev \
    make \
    perl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
# openssl-vendored is enabled for every build; the arg selects other features.
ARG CARGO_BUILD_ARGS="--features piv,yubikey"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# TARGETARCH keeps the cache mounts per-arch so the two platform builds never
# share a target dir. Commit ARGs at the RUN to keep the COPY layer cache-stable.
ARG TARGETARCH
ARG RITE_BUILD_COMMIT
ARG RITE_BUILD_COMMIT_DATE
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-glibc-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=cargo-target-glibc-${TARGETARCH} \
    RITE_BUILD_COMMIT="$RITE_BUILD_COMMIT" \
    RITE_BUILD_COMMIT_DATE="$RITE_BUILD_COMMIT_DATE" \
    cargo build --locked --release -p rite --features openssl-vendored $CARGO_BUILD_ARGS && \
    install -D -m 0755 target/release/rite /out/rite

# Debian bookworm is the oldest supported distribution. Loading the binary
# resolves its required symbols (Rust links with BIND_NOW), so `rite --version`
# fails if it needs a newer glibc or libpcsclite. Every shipped copy comes from
# this stage.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS glibc-floor
RUN apt-get update && apt-get install -y --no-install-recommends libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder-glibc /out/rite /usr/local/bin/rite
RUN rite --version

# The glibc binary on its own, for the Live systems (img/) and the release
# tarballs.
FROM scratch AS binary-glibc
COPY --from=glibc-floor /usr/local/bin/rite /rite

FROM debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31 AS runtime-base

# libpcsclite1 is the shared library the glibc binary links besides glibc. The
# pcscd daemon and CCID driver are not installed: they are only needed to open a
# real card, which the container does by mounting the host's PC/SC socket. See
# docs/docker.md.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
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
COPY --from=glibc-floor /usr/local/bin/rite /usr/local/bin/rite
USER rite
