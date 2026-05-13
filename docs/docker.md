# Docker

## Quick start

Build and run from source. The default image ships a musl-static `rite`
binary cross-compiled for the host's platform.

```sh
docker buildx build --load -t rite .
docker run --rm -it --init -v "$PWD:/workspace" rite check ceremony.rite.yaml
```

## Build orchestration: `docker-bake.hcl`

All multi-target builds are declared in [`docker-bake.hcl`](../docker-bake.hcl).
Run all three targets at once:

```sh
docker buildx bake
# produces dist/amd64/{rite,rite-ls}, dist/arm64/{rite,rite-ls}, and a
# multi-arch image in the local buildx cache (push requires `--push`).
```

Run a single target:

```sh
docker buildx bake binaries-amd64    # x86_64 musl binaries → dist/amd64/
docker buildx bake binaries-arm64    # aarch64 musl binaries → dist/arm64/
docker buildx bake image             # multi-arch runtime image (cache only locally)
```

## Build targets

| Bake target | Dockerfile stage | Output |
|---|---|---|
| `binaries-amd64` | `binaries-amd64` | `dist/amd64/{rite, rite-ls}` |
| `binaries-arm64` | `binaries-arm64` | `dist/arm64/{rite, rite-ls}` |
| `image` | `release` | multi-arch runtime image (`linux/amd64,linux/arm64`) with SBOM + provenance attestations |

## Cross-compilation

Linux builds use [`ghcr.io/rust-cross/rust-musl-cross`](https://github.com/rust-cross/rust-musl-cross)
base images (one per target triple). Each image ships a pre-built musl cross
toolchain, Rust with `CARGO_BUILD_TARGET` pre-set, and the correct linker
config. No QEMU emulation when the build host architecture matches the image
(amd64). The Dockerfile dispatches between the two builder stages via
buildx's `TARGETARCH` so a single bake invocation produces the multi-arch
published image.

The base images are linux/amd64. On amd64 build hosts (CI, most workstations)
they run natively. On arm64 build hosts (Apple Silicon) Docker uses QEMU
emulation for the C compile steps.

All `rite` Linux binaries are musl-static (vendored OpenSSL, no libc runtime
dependency). glibc-linked builds are not supported.

## Custom Cargo features

The `CARGO_BUILD_ARGS` build arg flows through to all targets:

```sh
docker buildx bake binaries-amd64 \
  --set "*.args.CARGO_BUILD_ARGS=--no-default-features --features openssl-vendored"
```

## Hardened runtime flags

```sh
docker run --rm -it --init \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=256 \
  --tmpfs /tmp:noexec,nosuid,size=64m \
  -v "$PWD:/workspace" \
  rite check ceremony.rite.yaml
```
