#!/bin/bash
# img/build-img.sh
# Layer one or more ceremonies onto a base ISO and emit a flashable .img.
# Runs inside the rite-img container.
#
# Needs no privileges: nothing is mounted or attached to a loop device. The
# output is reproducible: the same base ISO, ceremonies and materials give the
# same image, byte for byte.
#
# Prints the image's hashes on stdout, one per line; progress goes to stderr.
#
# Example:
#   docker run --rm -v "$PWD:/work" rite-img build-img \
#       --iso rite.iso \
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
  --iso FILE          Base ISO (from build-iso).
  --ceremony FILE     Ceremony YAML file (repeatable).
  --output FILE       Output image file (.img).

Optional:
  --material FILE     File a ceremony reads (repeatable).
  --verbose           Show the output of xorriso.
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

ISO_FILE=""
OUTPUT_FILE=""
CEREMONIES=()
MATERIALS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso)      need_value "$@"; ISO_FILE="$2";      shift 2 ;;
        --ceremony) need_value "$@"; CEREMONIES+=("$2"); shift 2 ;;
        --material) need_value "$@"; MATERIALS+=("$2");  shift 2 ;;
        --output)   need_value "$@"; OUTPUT_FILE="$2";   shift 2 ;;
        --verbose)  VERBOSE=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          usage_error "unknown option: $1" ;;
    esac
done

[[ -n "$ISO_FILE" ]]          || usage_error "--iso is required"
[[ ${#CEREMONIES[@]} -gt 0 ]] || usage_error "--ceremony is required"
[[ -n "$OUTPUT_FILE" ]]       || usage_error "--output is required"
[[ -f "$ISO_FILE" ]]          || die "ISO file not found: $ISO_FILE"
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
# BASE, the common ancestor directory of the ceremony files, so those relative
# paths still resolve in /rite/inputs. With one ceremony, BASE is its directory.
# realpath -s keeps symlinks as they are: a symlinked input sits at the path the
# definition uses, not at its target's.
BASE=$(dirname "$(realpath -s "${CEREMONIES[0]}")")
for ceremony in "${CEREMONIES[@]}"; do
    dir=$(dirname "$(realpath -s "$ceremony")")
    until [[ "$dir/" == "${BASE%/}/"* ]]; do
        BASE=$(dirname "$BASE")
    done
done

CEREMONY_PATHS=()
MATERIAL_PATHS=()
declare -A SEEN=()
add_input() {
    local file=$1 rel
    rel=$(realpath -s --relative-to="$BASE" "$file")
    [[ "$rel" != ../* ]] || die "$file is outside the ceremonies' directory ($BASE)"
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

# Ceremony layer. The inputs go in /rite/inputs, and /rite/ceremonies lists
# the ceremony files in the order given, for the session's start screen.
# Modes, owner, timestamps and xattrs are fixed, so the layer depends only on
# the file contents and names, and the session user can read every file.
note "Building the ceremony layer."
LAYER="$TEMP_DIR/layer"
install -d -m 0755 "$LAYER/rite" "$LAYER/rite/inputs"
for rel in "${CEREMONY_PATHS[@]}" "${MATERIAL_PATHS[@]}"; do
    install -d -m 0755 "$LAYER/rite/inputs/$(dirname "$rel")"
    install -m 0644 "$BASE/$rel" "$LAYER/rite/inputs/$rel"
done
printf '/rite/inputs/%s\n' "${CEREMONY_PATHS[@]}" > "$LAYER/rite/ceremonies"
# install -d sets the mode of the last directory only; the parents it creates,
# and the mktemp directory itself, take other modes.
chmod -R u=rwX,go=rX "$LAYER"

CEREMONY_SQUASHFS="$TEMP_DIR/ceremony.squashfs"
quietly mksquashfs "$LAYER" "$CEREMONY_SQUASHFS" \
    -comp xz -all-root -no-xattrs -mkfs-time 0 -all-time 0 -no-progress

# live-boot stacks the images listed here, bottom first. Entries are bare file
# names; live-boot prepends the live medium's /live/ directory.
FILESYSTEM_MODULE="$TEMP_DIR/filesystem.module"
printf '%s\n' filesystem.squashfs ceremony.squashfs > "$FILESYSTEM_MODULE"

# EFI system partition. The ISO boots through its El Torito EFI image, which
# firmware finds on optical media and on some USB disks. A copy of that image as
# an MBR partition of type 0xef is what other firmware looks for on a USB disk.
quietly xorriso -osirrox on -indev "$ISO_FILE" -extract /boot/grub/efi.img "$TEMP_DIR/efi.img"

# Outputs partition: FAT32 reads and writes on Linux, macOS and Windows without
# drivers, so the outputs are visible when the stick is plugged into any machine.
# --invariant fixes the volume ID and timestamps mkfs.fat would otherwise take
# from the random generator and the clock.
OUTPUTS_IMG="$TEMP_DIR/outputs.img"
truncate -s "${OUTPUTS_PARTITION_SIZE_MB}M" "$OUTPUTS_IMG"
quietly mkfs.fat --invariant -F 32 -n "RITE-OUT" "$OUTPUTS_IMG"

# Repack the ISO. Order follows https://wiki.debian.org/RepackBootableISO:
# -map adds the files, -boot_image any replay keeps the boot records, and
# -append_partition adds partitions after the ISO data in an MBR partition
# table: 2 is the EFI system partition, 3 the outputs partition (type 0x0c,
# FAT32 LBA). SOURCE_DATE_EPOCH fixes the ISO's own timestamps, and the added
# files get a fixed mode and mtime because xorriso records them.
note "Writing the image."
chmod 0644 "$CEREMONY_SQUASHFS" "$FILESYSTEM_MODULE"
touch -d @0 "$CEREMONY_SQUASHFS" "$FILESYSTEM_MODULE"
IMG_TMP="$TEMP_DIR/output.img"
SOURCE_DATE_EPOCH=0 quietly xorriso -indev "$ISO_FILE" \
    -outdev "$IMG_TMP" \
    -map "$CEREMONY_SQUASHFS" /live/ceremony.squashfs \
    -map "$FILESYSTEM_MODULE" /live/filesystem.module \
    -boot_image any replay \
    -append_partition 2 0xef "$TEMP_DIR/efi.img" \
    -append_partition 3 0x0c "$OUTPUTS_IMG" \
    -end

# Disk signature. xorriso leaves the MBR's 32-bit disk signature at zero, and
# Windows may write one of its own into a disk that has none, which would change
# the system hash below. The first bytes of the layer hash keep the image
# reproducible and differ between ceremonies.
SIG=$(sha256sum "$CEREMONY_SQUASHFS" | cut -c1-8)
printf '%b' "\\x${SIG:0:2}\\x${SIG:2:2}\\x${SIG:4:2}\\x${SIG:6:2}" \
    | dd of="$IMG_TMP" bs=1 seek=440 conv=notrunc status=none

# Everything before the outputs partition, the part of a written stick that a
# ceremony leaves unchanged. Plugging the stick into a machine may write to the
# outputs partition (macOS adds .fseventsd), so participants compare this part.
SYSTEM_SECTORS=$(partx -g -o START -n 3 "$IMG_TMP" | tr -d ' ')
SYSTEM_BYTES=$((SYSTEM_SECTORS * 512))
SYSTEM_HASH=$(head -c "$SYSTEM_BYTES" "$IMG_TMP" | sha256sum | cut -d' ' -f1)

mv "$IMG_TMP" "$OUTPUT_FILE"

echo "image     sha256:$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)  $OUTPUT_FILE"
echo "system    sha256:$SYSTEM_HASH  $SYSTEM_BYTES"
echo "layer     sha256:$(sha256sum "$CEREMONY_SQUASHFS" | cut -d' ' -f1)"
for rel in "${CEREMONY_PATHS[@]}"; do
    echo "ceremony  sha256:$(sha256sum "$BASE/$rel" | cut -d' ' -f1)  /rite/inputs/$rel"
done
