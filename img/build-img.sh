#!/bin/bash
# img/build-img.sh
# Add one or more ceremonies to a base image and emit a flashable .img.
# Runs inside the rite-img container.
#
# Needs no privileges: nothing is mounted or attached to a loop device. The
# output is reproducible: the same base image, ceremonies and materials give
# the same image, byte for byte.
#
# Prints the image's hashes on stdout, one per line; progress goes to stderr.
#
# Example:
#   docker run --rm -v "$PWD:/work" rite-img build-img \
#       --base rite-base.img \
#       --ceremony sub_ca.rite.yaml \
#       --material transport_public.pem \
#       --output sub_ca.img

set -euo pipefail

PROG=build-img
source /img/lib/utils.sh

OUTPUTS_PARTITION_SIZE_MB=100

usage() {
    cat <<EOF
Usage: build-img [OPTIONS]

Required:
  --base FILE         Base image (from build-base), as .img or .img.xz.
  --ceremony FILE     Ceremony YAML file (repeatable).
  --output FILE       Output image file (.img).

Optional:
  --material FILE     File a ceremony reads (repeatable).
  --verbose           Show the output of systemd-repart and sfdisk.
  -h, --help          Show this help.

Inputs keep their paths relative to the common ancestor directory of the
ceremony files, so the relative paths a definition uses still resolve. A
material must be in that directory or below it.

Prints one line per hash on stdout:
  image     sha256:<hash>  <output path>
  system    sha256:<hash>  <length in bytes>
  layer     sha256:<hash>
  ceremony  sha256:<hash>  <ceremony path on the stick>
EOF
}

BASE_IMAGE=""
OUTPUT_FILE=""
CEREMONIES=()
MATERIALS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)     need_value "$@"; BASE_IMAGE="$2";    shift 2 ;;
        --ceremony) need_value "$@"; CEREMONIES+=("$2"); shift 2 ;;
        --material) need_value "$@"; MATERIALS+=("$2");  shift 2 ;;
        --output)   need_value "$@"; OUTPUT_FILE="$2";   shift 2 ;;
        --verbose)  VERBOSE=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          usage_error "unknown option: $1" ;;
    esac
done

[[ -n "$BASE_IMAGE" ]]        || usage_error "--base is required"
[[ ${#CEREMONIES[@]} -gt 0 ]] || usage_error "--ceremony is required"
[[ -n "$OUTPUT_FILE" ]]       || usage_error "--output is required"
[[ -f "$BASE_IMAGE" ]]        || die "base image not found: $BASE_IMAGE"
for ceremony in "${CEREMONIES[@]}"; do
    [[ -f "$ceremony" ]] || die "ceremony file not found: $ceremony"
done
for mat in "${MATERIALS[@]}"; do
    [[ -f "$mat" ]] || die "material file not found: $mat"
done
[[ ! -d "$OUTPUT_FILE" ]] || die "--output is a directory: $OUTPUT_FILE"
[[ -d "$(dirname "$OUTPUT_FILE")" ]] || die "directory not found: $(dirname "$OUTPUT_FILE")"

# A definition names its files by paths relative to its own directory
# (path: "test_keys/escrow_public.pem"). Every input keeps its path relative to
# INPUT_ROOT, the common ancestor directory of the ceremony files, so those
# relative paths still resolve in /rite/inputs. With one ceremony, INPUT_ROOT is
# its directory. realpath -s keeps symlinks as they are: a symlinked input sits
# at the path the definition uses, not at its target's.
INPUT_ROOT=$(dirname "$(realpath -s "${CEREMONIES[0]}")")
for ceremony in "${CEREMONIES[@]}"; do
    dir=$(dirname "$(realpath -s "$ceremony")")
    until [[ "$dir/" == "${INPUT_ROOT%/}/"* ]]; do
        INPUT_ROOT=$(dirname "$INPUT_ROOT")
    done
done

CEREMONY_PATHS=()
MATERIAL_PATHS=()
declare -A SEEN=()
add_input() {
    local file=$1 rel
    rel=$(realpath -s --relative-to="$INPUT_ROOT" "$file")
    [[ "$rel" != ../* ]] || die "$file is outside the ceremonies' directory ($INPUT_ROOT)"
    [[ -z "${SEEN[$rel]:-}" ]] || die "input $rel is given twice"
    SEEN[$rel]=1
    INPUT_PATH=$rel
}
for ceremony in "${CEREMONIES[@]}"; do
    add_input "$ceremony"
    CEREMONY_PATHS+=("$INPUT_PATH")
done
for mat in "${MATERIALS[@]}"; do
    add_input "$mat"
    MATERIAL_PATHS+=("$INPUT_PATH")
done

# Work next to the output, so the final mv is a rename on the same filesystem
# and a failed run leaves any previous output untouched.
TEMP_DIR=$(mktemp -d -p "$(dirname "$OUTPUT_FILE")" .build-img.XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

IMG_TMP="$TEMP_DIR/output.img"
case "$BASE_IMAGE" in
    *.xz) note "Decompressing the base image."
          xz -dc "$BASE_IMAGE" > "$IMG_TMP" || die "cannot decompress $BASE_IMAGE" ;;
    *)    cp "$BASE_IMAGE" "$IMG_TMP" ;;
esac

# The base's root partition type names its architecture, which the layer's
# partition type must match for systemd-sysext to use it.
PART_TYPES=$(partx -g -o TYPE "$IMG_TMP" 2>/dev/null || true)
case "$PART_TYPES" in
    *b921b045-1df0-41c3-af44-4c6f280d3fae*) ARCH=arm64 ;;
    *4f68bce3-e8cd-4db1-96e7-fbcaf984b709*) ARCH=x86-64 ;;
    *) die "$BASE_IMAGE is not a base image from build-base (no arm64 or x86-64 root partition)" ;;
esac
if partx -g -o NAME "$IMG_TMP" | grep -qxF -e rite-ceremony -e RITE-OUT; then
    die "$BASE_IMAGE already holds a ceremony; pass the base image from build-base"
fi

# Ceremony layer: a system extension image, which systemd-sysext merges into
# /usr at boot. The inputs go in /usr/share/rite/inputs, and
# /usr/share/rite/ceremonies lists the ceremony files in the order given, for
# the session's start screen; the base links /rite/inputs and /rite/ceremonies
# there. extension-release names the extension "ceremony" and accepts any
# host, since the layer holds data only. Modes, owner and timestamps are fixed,
# so the layer depends only on the file contents and names, and the session
# user can read every file.
note "Building the ceremony layer."
TREE="$TEMP_DIR/tree"
SHARE="$TREE/usr/share/rite"
install -d -m 0755 "$SHARE/inputs" "$TREE/usr/lib/extension-release.d"
for rel in "${CEREMONY_PATHS[@]}" "${MATERIAL_PATHS[@]}"; do
    install -d -m 0755 "$SHARE/inputs/$(dirname "$rel")"
    install -m 0644 "$INPUT_ROOT/$rel" "$SHARE/inputs/$rel"
done
printf '/rite/inputs/%s\n' "${CEREMONY_PATHS[@]}" > "$SHARE/ceremonies"
echo "ID=_any" > "$TREE/usr/lib/extension-release.d/extension-release.ceremony"
# install -d sets the mode of the last directory only; the parents it creates,
# and the mktemp directory itself, take other modes.
chmod -R u=rwX,go=rX "$TREE"
find "$TREE" -exec touch -h -d @0 {} +

# EROFS with dm-verity hashes, in a GPT image of its own. The seed fixes the
# partition UUIDs and the verity salt.
LAYER="$TEMP_DIR/layer.raw"
SOURCE_DATE_EPOCH=0 quietly systemd-repart \
    --empty=create --size=auto --offline=yes \
    --architecture="$ARCH" \
    --seed=7d1c3d0e-2b8f-4a55-9c1e-0f4a6b2d8e31 \
    --definitions=/img/ceremony.repart.d \
    --copy-source="$TREE" \
    "$LAYER"
LAYER_SHA=$(sha256sum "$LAYER" | cut -d' ' -f1)

# A UUID derived from the layer, so the same inputs give the same image and two
# ceremonies give different ones.
uuid_of() {
    sha256sum <<<"$1" | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/\1-\2-\3-\4-\5/'
}

# The partitions. The image grows by the layer and the outputs partition, the
# backup GPT moves to the new end, and both partitions are added after the
# base's, whose contents stay byte for byte as built. The layer partition holds
# a Linux file system type, so nothing mounts it on its own; the outputs
# partition is a Microsoft basic data partition, which Linux, macOS and Windows
# mount. The disk GUID changes too: it is the same in every image of a base, and
# Windows rewrites a disk GUID that clashes with another disk's, which would
# change the system hash below.
note "Writing the image."
LAYER_MB=$(( ($(stat -c %s "$LAYER") + 1048575) / 1048576 ))
truncate -s "+$((LAYER_MB + OUTPUTS_PARTITION_SIZE_MB + 1))M" "$IMG_TMP"
quietly sfdisk --relocate gpt-bak-std "$IMG_TMP"
quietly sfdisk --disk-id "$IMG_TMP" "$(uuid_of "disk:$LAYER_SHA")"
printf 'size=%sMiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=%s, name="rite-ceremony"\n' \
    "$LAYER_MB" "$(uuid_of "ceremony:$LAYER_SHA")" \
    | quietly sfdisk --append "$IMG_TMP"
printf 'size=%sMiB, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=%s, name="RITE-OUT"\n' \
    "$OUTPUTS_PARTITION_SIZE_MB" "$(uuid_of "outputs:$LAYER_SHA")" \
    | quietly sfdisk --append "$IMG_TMP"

# Start and length, in 512-byte sectors, of the partition with the given name.
partition() {
    partx -g -o START,SECTORS,NAME "$IMG_TMP" | awk -v name="$1" '$3 == name { print $1, $2 }'
}
read -r LAYER_START LAYER_SECTORS < <(partition rite-ceremony)
read -r OUTPUTS_START OUTPUTS_SECTORS < <(partition RITE-OUT)

# The layer is padded to its partition, because the system loads and hashes
# the whole partition at boot; the layer hash below is the one it records.
truncate -s $((LAYER_SECTORS * 512)) "$LAYER"
dd if="$LAYER" of="$IMG_TMP" bs=512 seek="$LAYER_START" conv=notrunc status=none

# Outputs partition: FAT32 reads and writes on Linux, macOS and Windows without
# drivers, so the outputs are visible when the stick is plugged into any machine.
# --invariant fixes the volume ID and timestamps mkfs.fat would otherwise take
# from the random generator and the clock.
OUTPUTS_IMG="$TEMP_DIR/outputs.img"
quietly mkfs.fat --invariant -F 32 -n RITE-OUT -C "$OUTPUTS_IMG" $((OUTPUTS_SECTORS / 2))
dd if="$OUTPUTS_IMG" of="$IMG_TMP" bs=512 seek="$OUTPUTS_START" conv=notrunc status=none

# Everything before the outputs partition, the part of a written stick that a
# ceremony leaves unchanged. Plugging the stick into a machine may write to the
# outputs partition (macOS adds .fseventsd), so participants compare this part.
SYSTEM_BYTES=$((OUTPUTS_START * 512))
SYSTEM_HASH=$(head -c "$SYSTEM_BYTES" "$IMG_TMP" | sha256sum | cut -d' ' -f1)

mv "$IMG_TMP" "$OUTPUT_FILE"

echo "image     sha256:$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)  $OUTPUT_FILE"
echo "system    sha256:$SYSTEM_HASH  $SYSTEM_BYTES"
echo "layer     sha256:$(sha256sum "$LAYER" | cut -d' ' -f1)"
for rel in "${CEREMONY_PATHS[@]}"; do
    echo "ceremony  sha256:$(sha256sum "$INPUT_ROOT/$rel" | cut -d' ' -f1)  /rite/inputs/$rel"
done
