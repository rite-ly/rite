#!/bin/bash
# img/entrypoint.sh
# Docker ENTRYPOINT: dispatches the first argument to the matching script.
set -euo pipefail

usage() {
    cat <<EOF
Usage: docker run [--privileged] rite-img <command> [options]

Commands:
  build-base    Build a base Rite ceremony image (needs --privileged).
  build-img     Add ceremonies to a base image, produce a flashable .img.
  extract       Copy ceremony outputs out of a .img.

Run any command with --help for its own options.
EOF
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 2
fi

cmd="$1"
shift

case "$cmd" in
    build-base) exec /img/build-base.sh "$@" ;;
    build-img)  exec /img/build-img.sh "$@" ;;
    extract)    exec /img/extract-outputs.sh "$@" ;;
    -h|--help|help) usage ;;
    *)
        echo "rite-img: unknown command: $cmd" >&2
        echo "Run 'rite-img --help' for usage." >&2
        exit 2
        ;;
esac
