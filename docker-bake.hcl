# Bake spec for the rite Docker build. See docs/docker.md.
#
# Targets:
#   binaries-amd64 / binaries-arm64  — extract per-arch musl-static binaries to dist/<arch>/
#   image                            — multi-arch runtime image (linux/amd64,linux/arm64)
#
# Groups:
#   default   — both binaries + image (release flow)
#   binaries  — both binaries only (CI smoke)
#
# Usage:
#   docker buildx bake                  # default group (release flow)
#   docker buildx bake binaries         # both binaries, no image (CI smoke)
#   docker buildx bake binaries-amd64   # one target
#   docker buildx bake image            # multi-arch image only
#
# CI injects tags and cache scopes via `--set` on the bake-action.

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
  # Provenance is attested in the release workflow via Sigstore (actions/attest),
  # the same mechanism used for the binaries, so no BuildKit in-registry
  # attestations are emitted here.
  #
  # The image uses the glibc `builder-image` stage (not the musl cross stages
  # the binaries targets use) so the binary can dynamically link libpcsclite and
  # carry the hardware backends. CARGO_BUILD_ARGS is overridable to drop them.
  args = {
    RITE_BUILD_COMMIT      = RITE_BUILD_COMMIT
    RITE_BUILD_COMMIT_DATE = RITE_BUILD_COMMIT_DATE
    CARGO_BUILD_ARGS       = "--features piv,yubikey"
  }
  # output / tags injected by CI: `--set image.output=type=registry,push=true`,
  # tags via the bake file produced by docker/metadata-action.
}
