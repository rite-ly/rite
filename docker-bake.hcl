# Bake spec for the rite Docker build. See docs/docker.md.
#
# Targets:
#   binaries-amd64 / binaries-arm64  — extract per-arch musl-static binaries to dist/<arch>/
#   image                            — multi-arch runtime image (linux/amd64,linux/arm64)
#
# Groups:
#   default   — both binaries + image (local multi-arch build)
#   binaries  — both binaries only
#
# The release workflow bakes the `binaries` group for the musl tarballs and
# builds the `image` per-arch on native runners (not via bake); the `binaries`
# group also backs the CI smoke build. The `image` target and `default` group
# are for local multi-arch builds.
#
# Usage:
#   docker buildx bake                  # default group (both binaries + image)
#   docker buildx bake binaries         # both binaries, no image
#   docker buildx bake binaries-amd64   # one target
#   docker buildx bake image            # multi-arch image only
#
# CI injects cache scopes (and, for local pushes, tags) via `--set`.

# Commit metadata stamped into the binaries via build args. Set RITE_BUILD_COMMIT
# and RITE_BUILD_COMMIT_DATE in the environment (CI does this) or via `--set`.
# Defaults to "unknown" so local `docker buildx bake` works without ceremony.
variable "RITE_BUILD_COMMIT" {
  default = "unknown"
}

variable "RITE_BUILD_COMMIT_DATE" {
  default = "unknown"
}

group "default" {
  targets = ["binaries-amd64", "binaries-arm64", "image"]
}

group "binaries" {
  targets = ["binaries-amd64", "binaries-arm64"]
}

target "binaries-amd64" {
  target = "binaries-amd64"
  output = ["type=local,dest=dist/amd64"]
  args = {
    RITE_BUILD_COMMIT      = RITE_BUILD_COMMIT
    RITE_BUILD_COMMIT_DATE = RITE_BUILD_COMMIT_DATE
  }
}

target "binaries-arm64" {
  target = "binaries-arm64"
  output = ["type=local,dest=dist/arm64"]
  args = {
    RITE_BUILD_COMMIT      = RITE_BUILD_COMMIT
    RITE_BUILD_COMMIT_DATE = RITE_BUILD_COMMIT_DATE
  }
}

target "image" {
  target    = "release"
  platforms = ["linux/amd64", "linux/arm64"]
  # The image uses the glibc `builder-image` stage (not the musl cross stages
  # the binaries targets use) so the binary can dynamically link libpcsclite and
  # carry the hardware backends. CARGO_BUILD_ARGS is overridable to drop them.
  #
  # This multi-arch target is for local builds; on an arm64 host one arch is
  # emulated via QEMU. The release workflow builds each arch natively on its own
  # runner instead, so it does not use this target.
  args = {
    RITE_BUILD_COMMIT      = RITE_BUILD_COMMIT
    RITE_BUILD_COMMIT_DATE = RITE_BUILD_COMMIT_DATE
    CARGO_BUILD_ARGS       = "--features piv,yubikey"
  }
}
