# Docker

## Quick start

Build and run from source:

```sh
docker build -t rite .
docker run --rm -it --init -v "$PWD:/workspace" rite check ceremony.rite.yaml
```

## Targets

| Target | Description |
|---|---|
| `local` | Compiled from source — **default** |
| `release` | Assembled from pre-compiled binaries in `dist/` (used by CI) |
| `binaries` | Exports the compiled binary to the host filesystem (no runtime layer) |

## Cross-architecture build

```sh
# Example: macOS arm64 host building linux/amd64
docker buildx build --platform linux/amd64 --load -t rite:amd64 .
```

## Custom Cargo features

```sh
docker buildx build \
  --build-arg CARGO_BUILD_ARGS="--no-default-features --features openssl-vendored" \
  --load -t rite:custom .
```

## Extract binary to host

Useful for ISO builds, custom packaging, or embedding in other images:

```sh
docker buildx build --target binaries --output type=local,dest=./dist .
# produces ./dist/rite
```

Cross-architecture:
```sh
docker buildx build --platform linux/amd64 --target binaries --output type=local,dest=./dist .
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
