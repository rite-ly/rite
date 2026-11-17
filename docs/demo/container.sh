# shellcheck shell=bash
# Sourced by render-prints.sh and record.sh. A run records the host's platform
# and network interfaces, and the demo outputs are published, so the ceremony
# runs in the release image with no network.

DEMO_IMAGE=rite-demo

# Build the debug binary and the image from this checkout.
build_demo_image() {
  cargo build --quiet -p rite --manifest-path "$REPO/Cargo.toml"
  echo "building $DEMO_IMAGE..." >&2
  docker build --quiet --load --target release -t "$DEMO_IMAGE" "$REPO" >/dev/null
}

# Run `rite "${@:2}"` in the image, in directory `$1`.
rite_in_container() {
  local dir=$1
  shift
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$dir:/workspace" "$DEMO_IMAGE" "$@"
}

# Write `$1/bin/rite`, the same with a terminal, so a recording runs a plain
# `rite` and its cast names no local path.
write_rite_wrapper() {
  local dir=$1
  mkdir -p "$dir/bin"
  {
    echo '#!/usr/bin/env bash'
    printf 'exec docker run --rm -it --network none --user %q -e HOME=/tmp ' "$(id -u):$(id -g)"
    printf -- '-e TERM -e COLORTERM -e LANG=C.UTF-8 -v %q %q "$@"\n' "$dir:/workspace" "$DEMO_IMAGE"
  } >"$dir/bin/rite"
  chmod +x "$dir/bin/rite"
}
