# Docker

## Quick start

Build and run from source. The image ships a glibc `rite` binary built with the
`piv` and `yubikey` hardware backends, so it can drive a smart card as well as
the software backends.

```sh
docker buildx build --load -t rite .
docker run --rm -it --init -v "$PWD:/workspace" rite check ceremony.rite.yaml
```

## Image vs. release tarballs

The image and the downloadable Linux release tarballs are built differently and
serve different needs:

| Artifact                                   | Toolchain          | OpenSSL            | Hardware backends                             |
|--------------------------------------------|--------------------|--------------------|-----------------------------------------------|
| Release tarballs (`rite-*-linux-*.tar.gz`) | musl, fully static | vendored           | no (`piv`/`yubikey` cannot static-link PC/SC) |
| Docker image (`ghcr.io/rite-ly/rite`)      | glibc              | system (`libssl3`) | yes (`piv`, `yubikey`)                        |

The tarballs stay static for portability across distros (Alpine, older glibc,
Remote SSH targets). The image runs on a known Debian base, so it links
`libpcsclite` and ships the smart-card backends.

Driving a real card from the container additionally needs the reader passed
through (`--device`) or the host `pcscd` socket mounted; `check`, `--dry-run`,
and authoring work without any of that.

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

| Bake target      | Dockerfile stage | Output                                                                                                               |
|------------------|------------------|----------------------------------------------------------------------------------------------------------------------|
| `binaries-amd64` | `binaries-amd64` | `dist/amd64/{rite, rite-ls}` (musl static)                                                                           |
| `binaries-arm64` | `binaries-arm64` | `dist/arm64/{rite, rite-ls}` (musl static)                                                                           |
| `image`          | `release`        | multi-arch runtime image (`linux/amd64,linux/arm64`), glibc + hardware backends, with SBOM + provenance attestations |

## Build stages and toolchains

The single `Dockerfile` carries two independent builder chains; a bake target
only triggers the stages it needs:

- **musl chain** (`builder-amd64` / `builder-arm64`) feeds the `binaries-*`
  targets. It uses [`ghcr.io/rust-cross/rust-musl-cross`](https://github.com/rust-cross/rust-musl-cross)
  base images (one per target triple) with a pre-built musl cross toolchain and
  `CARGO_BUILD_TARGET` pre-set, so a single amd64 host cross-compiles both
  arches with no QEMU for the Rust step. Output is fully static (vendored
  OpenSSL, no libc runtime dependency).
- **glibc chain** (`builder-image`) feeds the `image` target. It sets no
  `--platform`, so buildx compiles it once per target platform: amd64 natively,
  arm64 emulated via QEMU. It dynamically links system OpenSSL and `libpcsclite`, which is what
  lets the image carry the `piv`/`yubikey` backends. The emulated arm64 compile
  is the slow part of a release build.

## Custom Cargo features

The `CARGO_BUILD_ARGS` build arg overrides the feature set per target. The
`binaries-*` targets default to `--features openssl-vendored`; the `image`
target defaults to `--features piv,yubikey`. To build the image without the
hardware backends:

```sh
docker buildx bake image \
  --set "image.args.CARGO_BUILD_ARGS=--features openssl"
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
