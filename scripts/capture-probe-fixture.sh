#!/bin/sh
#
# Capture, on the Linux system it runs on, the files the platform and network
# probes read, as a fixture for the tests in
# crates/rite-stdlib/src/verification/probe_fixtures.rs. Run it as an
# ordinary user, on the system to capture (Rite Live, a laptop, a container,
# a virtual machine):
#
#     sh capture-probe-fixture.sh /media/usb/rite-live-0.8.0-thinkpad-t14
#
# It writes DIR/root/ only. Copy DIR to crates/rite-stdlib/tests/fixtures/probes/,
# review every file, then follow the steps in
# crates/rite-stdlib/src/verification/probe_fixtures.rs.
#
# Only what the probes read is copied: no MAC address, no IP address, no
# serial number. Of /proc/cpuinfo, only the vendor_id and flags lines are kept,
# of the kernel command line only roothash=, and of /run/.containerenv only
# image=.
# Directories whose presence is all that counts are recorded with an empty
# .keep file, which the probes ignore, and the ceremony layer with an empty
# file of the same name.

set -eu

DIR=${1:-}
if [ -z "$DIR" ] || [ -e "$DIR" ]; then
  echo "usage: $0 <new directory>" >&2
  exit 1
fi
ROOT=$DIR/root
mkdir -p "$ROOT"

# Copy the file at absolute path $1 under $ROOT, when it is readable.
copy() {
  if [ -r "$1" ] && [ -f "$1" ]; then
    mkdir -p "$ROOT$(dirname "$1")"
    cat "$1" > "$ROOT$1" 2>/dev/null || rm -f "$ROOT$1"
  fi
}

# Record that the path $1 exists, as an empty file.
mark_file() {
  if [ -e "$1" ]; then
    mkdir -p "$ROOT$(dirname "$1")"
    : > "$ROOT$1"
  fi
}

# Record that the directory $1 exists, with a .keep file in it.
mark_dir() {
  if [ -d "$1" ]; then
    mkdir -p "$ROOT$1"
    : > "$ROOT$1/.keep"
  fi
}

# The operating system and the Rite Live identity.
copy /etc/os-release
[ -e "$ROOT/etc/os-release" ] || copy /usr/lib/os-release
# Of the kernel command line, only the roothash= options the probes read: the
# rest can name the machine (a VM id, a disk serial).
if [ -r /proc/cmdline ]; then
  mkdir -p "$ROOT/proc"
  tr ' ' '\n' < /proc/cmdline | grep '^roothash=' | tr '\n' ' ' > "$ROOT/proc/cmdline" || true
fi
copy /proc/sys/kernel/osrelease
copy /run/rite/ceremony.sha256
copy /run/rite/ceremony-error
mark_file /run/extensions/ceremony.raw

# Container markers. Podman's .containerenv also names the container and its
# id; only the image line is read.
if [ -f /run/.containerenv ]; then
  mkdir -p "$ROOT/run"
  grep '^image=' /run/.containerenv > "$ROOT/run/.containerenv" || true
fi
copy /run/systemd/container
mark_file /.dockerenv

# Virtual machine markers.
copy /sys/class/dmi/id/sys_vendor
copy /sys/class/dmi/id/product_name
copy /proc/device-tree/hypervisor/compatible
if [ -r /proc/cpuinfo ]; then
  mkdir -p "$ROOT/proc"
  grep -m1 '^vendor_id' /proc/cpuinfo > "$ROOT/proc/cpuinfo" || true
  grep -m1 '^flags' /proc/cpuinfo >> "$ROOT/proc/cpuinfo" || true
fi

# Firmware: each entry of /sys/firmware, and the SecureBoot variable. A
# container shows /sys/firmware empty, which the .keep alone records.
mark_dir /sys/firmware
for entry in /sys/firmware/*; do
  mark_dir "$entry"
done
if [ -d /sys/firmware/efi/efivars ]; then
  mark_dir /sys/firmware/efi/efivars
  copy /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-e39edca8b4ae
  # A mounted efivarfs has variables; record one more by name, empty.
  for var in /sys/firmware/efi/efivars/*-*; do
    case $var in */SecureBoot-*) continue ;; esac
    [ -e "$var" ] && mark_file "$var" && break
  done
fi

# Network interfaces: link type, carrier, DEVTYPE, and the directories that
# say Wi-Fi or a device behind the link.
for dir in /sys/class/net/*; do
  [ -d "$dir" ] || continue
  copy "$dir/type"
  copy "$dir/carrier"
  if [ -r "$dir/uevent" ]; then
    mkdir -p "$ROOT$dir"
    grep '^DEVTYPE=' "$dir/uevent" > "$ROOT$dir/uevent" || rm -f "$ROOT$dir/uevent"
  fi
  mark_dir "$dir/device"
  mark_dir "$dir/wireless"
  mark_dir "$dir/phy80211"
  mark_dir "$dir"
done

# Radios.
for dir in /sys/class/rfkill/rfkill*; do
  [ -d "$dir" ] || continue
  for file in type name soft hard; do
    copy "$dir/$file"
  done
done

echo "Captured into $ROOT:"
(cd "$ROOT" && find . -type f | sort)
