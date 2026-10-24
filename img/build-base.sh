#!/bin/bash
# img/build-base.sh
# Build the base image: a bootable GPT disk image with Debian, the rite binary
# and the ceremony session, from the mkosi configuration in /img/mkosi.
# Runs inside the rite-img container.
#
# Prints the image's SHA-256 and its root hash on stdout; progress goes to
# stderr.
#
# Example:
#   docker run --rm --privileged -v "$PWD:/work" rite-img build-base \
#       --binary dist/glibc-amd64/rite \
#       --output rite-base.img
set -euo pipefail

PROG=build-base
source /img/lib/utils.sh

usage() {
    cat <<EOF
Usage: build-base [OPTIONS]

Required:
  --binary FILE      Pre-built rite binary (Linux ELF, amd64 or arm64). The
                     image is built for the binary's architecture; another
                     architecture than the container's builds under
                     emulation, as Docker Desktop provides.
  --output FILE      Output base image (.img).

Optional:
  --manifest FILE    Also write the image's Debian packages and their versions,
                     as JSON.
  --verbose          Show the output of mkosi.
  -h, --help         Show this help.

Prints on stdout:
  base  sha256:<hash>  <path>
  root  <root hash>
EOF
}

BINARY=""
OUTPUT=""
MANIFEST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)   need_value "$@"; BINARY="$2"; shift 2 ;;
        --output)   need_value "$@"; OUTPUT="$2"; shift 2 ;;
        --manifest) need_value "$@"; MANIFEST="$2"; shift 2 ;;
        --verbose)  VERBOSE=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          usage_error "unknown option: $1" ;;
    esac
done

[[ -n "$BINARY" ]] || usage_error "--binary is required"
[[ -n "$OUTPUT" ]] || usage_error "--output is required"
[[ -f "$BINARY" ]] || die "binary not found: $BINARY"
# Checked now rather than after a build of several minutes.
for out in "$OUTPUT" ${MANIFEST:+"$MANIFEST"}; do
    [[ ! -d "$out" ]] || die "output is a directory: $out"
    [[ -d "$(dirname "$out")" ]] || die "directory not found: $(dirname "$out")"
done

FILE_OUTPUT=$(file "$BINARY")
case "$FILE_OUTPUT" in
    *"ELF"*"ARM aarch64"*) ARCH=arm64; MKOSI_ARCH=arm64 ;;
    *"ELF"*"x86-64"*)      ARCH=amd64; MKOSI_ARCH=x86-64 ;;
    *"Mach-O"*)            die "$BINARY is a macOS binary; pass a Linux rite binary, such as the one docker buildx bake binary-glibc-<arch> builds" ;;
    *)                     die "$BINARY is not a Linux arm64 or amd64 binary ($FILE_OUTPUT)" ;;
esac

# Work next to the output, so the final mv is a rename on the same filesystem
# and a failed run leaves any previous output untouched. mkosi resolves
# relative paths against its configuration directory, so this one is absolute.
TEMP_DIR=$(mktemp -d -p "$(realpath "$(dirname "$OUTPUT")")" .build-base.XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

# A copy of the configuration with the binary in its mkosi.extra tree, which
# mkosi copies into the image, and not into the initrd, before
# mkosi.postinst.chroot runs.
cp -a /img/mkosi "$TEMP_DIR/mkosi"
install -D -m 0755 "$BINARY" "$TEMP_DIR/mkosi/mkosi.extra/usr/bin/rite"

note "Building the $ARCH base image with mkosi; this downloads the Debian packages and takes a few minutes."
quietly mkosi \
    --directory "$TEMP_DIR/mkosi" \
    --architecture "$MKOSI_ARCH" \
    --output-directory "$TEMP_DIR/out" \
    --output base \
    build

[[ -f "$TEMP_DIR/out/base.raw" ]] || die "mkosi finished without producing an image"
ROOT_HASH=$(cat "$TEMP_DIR/out/base.roothash")
if [[ -n "$MANIFEST" ]]; then
    mv "$TEMP_DIR/out/base.manifest" "$MANIFEST"
fi
mv "$TEMP_DIR/out/base.raw" "$OUTPUT"

echo "base  sha256:$(sha256sum "$OUTPUT" | cut -d' ' -f1)  $OUTPUT"
echo "root  $ROOT_HASH"
