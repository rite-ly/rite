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

group "default" {
  targets = ["binaries-amd64", "binaries-arm64", "image"]
}

group "binaries" {
  targets = ["binaries-amd64", "binaries-arm64"]
}

target "binaries-amd64" {
  target = "binaries-amd64"
  output = ["type=local,dest=dist/amd64"]
}

target "binaries-arm64" {
  target = "binaries-arm64"
  output = ["type=local,dest=dist/arm64"]
}

target "image" {
  target    = "release"
  platforms = ["linux/amd64", "linux/arm64"]
  attest = [
    "type=sbom",
    "type=provenance,mode=max,version=v1",
  ]
  # output / tags injected by CI: `--set image.output=type=registry,push=true`,
  # tags via the bake file produced by docker/metadata-action.
}
