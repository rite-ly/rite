#!/bin/bash
# img/build-iso.sh
# Build a bootable Debian Live ISO containing the rite binary.
# Runs inside the rite-img container.
#
# Prints the ISO's SHA-256 and path on stdout; progress goes to stderr.
#
# Example:
#   docker run --rm --privileged -v "$PWD:/work" rite-img build-iso \
#       --binary rite-linux-amd64 \
#       --output rite.iso
set -euo pipefail

PROG=build-iso
source /img/lib/utils.sh

usage() {
    cat <<EOF
Usage: build-iso [OPTIONS]

Required:
  --binary FILE      Pre-built rite binary (Linux ELF, amd64 or arm64). The
                     ISO is built for the binary's architecture, which must be
                     the container's (docker run --platform linux/<arch>).
  --output FILE      Output .iso path.

Optional:
  --verbose          Show the output of live-build.
  -h, --help         Show this help.

Prints "iso  sha256:<hash>  <path>" on stdout.
EOF
}

BINARY=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)  need_value "$@"; BINARY="$2"; shift 2 ;;
        --output)  need_value "$@"; OUTPUT="$2"; shift 2 ;;
        --verbose) VERBOSE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *)         usage_error "unknown option: $1" ;;
    esac
done

[[ -n "$BINARY" ]] || usage_error "--binary is required"
[[ -n "$OUTPUT" ]] || usage_error "--output is required"
[[ -f "$BINARY" ]] || die "binary not found: $BINARY"
# Checked now rather than after a build of several minutes.
[[ ! -d "$OUTPUT" ]] || die "--output is a directory: $OUTPUT"
[[ -d "$(dirname "$OUTPUT")" ]] || die "directory not found: $(dirname "$OUTPUT")"

FILE_OUTPUT=$(file "$BINARY")
case "$FILE_OUTPUT" in
    *"Mach-O"*)
        die "$BINARY is a macOS binary; pass the Linux rite binary from a rite-<version>-linux-<arch> release archive"
        ;;
esac

case "$FILE_OUTPUT" in
    *"ELF"*"ARM aarch64"*) LB_ARCH="arm64" ;;
    *"ELF"*"x86-64"*)      LB_ARCH="amd64" ;;
    *)                     die "$BINARY is not a Linux arm64 or amd64 binary ($FILE_OUTPUT)" ;;
esac
export LB_ARCH

# live-build runs the target's programs inside its chroot, and so does the
# setup hook, so the container must run the binary's architecture. Without this
# check a mismatch fails minutes into the build, or under emulation builds an
# ISO for one architecture around a binary for the other.
case "$(uname -m)" in
    aarch64) HOST_ARCH="arm64" ;;
    x86_64)  HOST_ARCH="amd64" ;;
    *)       HOST_ARCH="$(uname -m)" ;;
esac
[[ "$LB_ARCH" == "$HOST_ARCH" ]] \
    || die "$BINARY is an $LB_ARCH binary but this container runs $HOST_ARCH; use a rite-img image built with docker build --platform linux/$LB_ARCH, and run it with docker run --platform linux/$LB_ARCH"

# live-build works in /iso-build. Paths are resolved first, so relative ones
# keep pointing where the operator meant; the output is printed as given.
BINARY=$(realpath "$BINARY")
OUTPUT_PATH=$(realpath -m "$OUTPUT")
cd /iso-build

# Clears a previous build; fails harmlessly when there is none.
lb clean --purge >/dev/null 2>&1 || true

# live-build configuration, copied into the locations lb expects.
# See: https://live-team.pages.debian.net/live-manual/html/live-manual/managing-a-configuration.en.html
mkdir -p auto
cp /img/auto/* auto/
chmod +x auto/*
quietly lb config

mkdir -p config/package-lists
cp /img/config/packages.list.chroot config/package-lists/rite.list.chroot

CHROOT=config/includes.chroot

install -D -m 0755 "$BINARY"                        "$CHROOT/usr/bin/rite"
install -D -m 0755 /img/config/rite-session         "$CHROOT/usr/lib/rite/rite-session"
install -D -m 0755 /img/config/rite-kiosk           "$CHROOT/usr/lib/rite/rite-kiosk"
install -D -m 0755 /img/config/mount-outputs        "$CHROOT/usr/lib/rite/mount-outputs"
install -D -m 0644 /img/config/rite-session.service "$CHROOT/etc/systemd/system/rite-session.service"
install -D -m 0644 /img/config/rite-session.pam     "$CHROOT/etc/pam.d/rite-session"
install -D -m 0644 /img/config/logind.conf          "$CHROOT/etc/systemd/logind.conf.d/rite.conf"
install -D -m 0644 /img/config/foot.ini             "$CHROOT/etc/xdg/foot/foot.ini"
install -D -m 0644 /img/config/bashrc               "$CHROOT/etc/skel/.bashrc"

# Runs in the chroot after the includes above are copied in.
mkdir -p config/hooks/live
install -m 0755 /img/config/setup-hook.sh config/hooks/live/0100-rite-setup.hook.chroot

# Boot menu. live-build reads the user GRUB configuration from
# config/bootloaders/grub-pc for every GRUB target, including grub-efi, the only
# bootloader auto/config enables.
install -D -m 0644 /img/config/bootloaders/grub.cfg config/bootloaders/grub-pc/grub.cfg

note "Building the $LB_ARCH live system with live-build; this downloads the Debian packages and takes several minutes."
quietly lb build

ISO_FILE=$(find . -maxdepth 1 -name "*.iso" | head -1)
[[ -n "$ISO_FILE" ]] || die "live-build finished without producing an ISO"
mv "$ISO_FILE" "$OUTPUT_PATH"

echo "iso  sha256:$(sha256sum "$OUTPUT_PATH" | cut -d' ' -f1)  $OUTPUT"
