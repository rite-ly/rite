#!/bin/bash
# img/extract-outputs.sh
# Copy the ceremony outputs out of the RITE-OUT partition of an image from
# build-img. Runs inside the rite-img container and needs no privileges: mtools
# reads the FAT32 partition from the image file at its offset, without mounting
# it.
#
# Prints the path of each copied run directory on stdout.
#
# For a written medium, mount the RITE-OUT partition and copy the outputs from
# it.
#
# Example:
#   docker run --rm -v "$PWD:/work" rite-img extract \
#       --image sub_ca.img \
#       --output outputs

set -euo pipefail

PROG=extract
source /img/lib/utils.sh

usage() {
    cat <<EOF
Usage: extract [OPTIONS]

Required:
  --image FILE        Image (.img) produced by build-img.
  --output DIR        Directory to copy the outputs into (created if missing).

Optional:
  -h, --help          Show this help.

Prints the path of each copied run directory on stdout.
EOF
}

IMAGE=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)   need_value "$@"; IMAGE="$2";      shift 2 ;;
        --output)  need_value "$@"; OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *)         usage_error "unknown option: $1" ;;
    esac
done

[[ -n "$IMAGE" ]]      || usage_error "--image is required"
[[ -n "$OUTPUT_DIR" ]] || usage_error "--output is required"
[[ -f "$IMAGE" ]]      || die "image file not found: $IMAGE"

# build-img names the outputs partition RITE-OUT in the partition table.
START=$(partx -g -o START,NAME "$IMAGE" 2>/dev/null | awk '$2 == "RITE-OUT" { print $1; exit }' || true)
[[ -n "$START" ]] || die "$IMAGE has no RITE-OUT partition; was it built with build-img?"
OFFSET=$((START * 512))

# The output directory must be new or empty, so the outputs of two images never
# mix and nothing already there is overwritten.
if [[ -e "$OUTPUT_DIR" && -n "$(ls -A "$OUTPUT_DIR")" ]]; then
    die "$OUTPUT_DIR is not empty; extract into a new directory"
fi

mkdir -p "$OUTPUT_DIR"
mcopy -s -n -m -i "${IMAGE}@@${OFFSET}" ::/ "$OUTPUT_DIR/"
# -m keeps file times, and the FAT root directory has none: without this the
# output directory would get a time far in the future.
touch "$OUTPUT_DIR"

# A run directory holds a transcript. Other entries, such as the ones a desktop
# system adds when it mounts the partition, are copied but not listed.
find "$OUTPUT_DIR" -mindepth 2 -maxdepth 2 -name transcript.jsonl -printf '%h\n' | sort
