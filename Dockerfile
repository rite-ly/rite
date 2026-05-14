# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
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

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:x86_64-musl@sha256:6c3c52df33dbd3fa999455c56db5be6fe2a9df5af63e00388194d936fd5cd003 AS builder-amd64
WORKDIR /src
ARG CARGO_BUILD_ARGS="--features openssl-vendored"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Per-target cache IDs so the two builder stages can run in parallel under bake without racing.
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-amd64 \
    --mount=type=cache,target=/src/target,id=cargo-target-amd64 \
    cargo build --locked --release -p rite-cli $CARGO_BUILD_ARGS && \
    cargo build --locked --release -p rite-ls && \
    install -D -m 0755 target/x86_64-unknown-linux-musl/release/rite    /out/rite && \
    install -D -m 0755 target/x86_64-unknown-linux-musl/release/rite-ls /out/rite-ls

FROM --platform=${TOOLCHAIN_PLATFORM} ghcr.io/rust-cross/rust-musl-cross:aarch64-musl@sha256:9ca69b8df8fbf4ea6f8c771b33cb66f80093d1fc1a057893e1c73445e3fa35e1 AS builder-arm64
WORKDIR /src
ARG CARGO_BUILD_ARGS="--features openssl-vendored"
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-arm64 \
    --mount=type=cache,target=/src/target,id=cargo-target-arm64 \
    cargo build --locked --release -p rite-cli $CARGO_BUILD_ARGS && \
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

FROM debian:trixie-slim@sha256:109e2c65005bf160609e4ba6acf7783752f8502ad218e298253428690b9eaa4b AS runtime-base

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
