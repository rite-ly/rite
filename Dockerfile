# syntax=docker/dockerfile:1.25@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12
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

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:x86_64-musl@sha256:6c3c52df33dbd3fa999455c56db5be6fe2a9df5af63e00388194d936fd5cd003 AS builder-amd64
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

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:aarch64-musl@sha256:9ca69b8df8fbf4ea6f8c771b33cb66f80093d1fc1a057893e1c73445e3fa35e1 AS builder-arm64
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

ARG TARGETARCH
FROM builder-${TARGETARCH} AS builder

FROM scratch AS binaries-amd64
COPY --from=builder-amd64 /out/rite    /rite
COPY --from=builder-amd64 /out/rite-ls /rite-ls

FROM scratch AS binaries-arm64
COPY --from=builder-arm64 /out/rite    /rite
COPY --from=builder-arm64 /out/rite-ls /rite-ls

FROM debian:trixie-slim@sha256:f3da28155e2e26086464eba22cd235b22200b7143e8f3e1811bf359e3114bf96 AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
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
COPY --from=builder /out/rite /usr/local/bin/rite
USER rite
