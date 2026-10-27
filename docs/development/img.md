# Rite Live

Rite Live runs a Rite ceremony from a USB drive, on a read-only system that runs only
Rite. `img/` builds it in two parts: the Live system, a Debian system with the `rite`
binary, published with each release, and the ceremony layer, which holds the ceremony
definitions and their input materials. `build-img` puts both in one image, with a
partition for the outputs of each run. Written to a USB drive, the image becomes the
ceremony medium.

The operator boots the machine from the ceremony medium, runs the ceremony, and reads the
outputs back on another machine.

## Layout of an image

An image is a GPT disk with five partitions:

| Partition | Content | Built by |
|---|---|---|
| EFI system partition | systemd-boot and the unified kernel image (UKI): the kernel, its initrd and its command line in one file | `build-system`, once per `rite` release and architecture |
| Root | Debian trixie, `rite` and the ceremony session, as a read-only EROFS file system | `build-system` |
| Root verity | The dm-verity hashes of the root partition | `build-system` |
| `rite-ceremony` | The ceremony layer: the ceremony definitions and their materials, as a system extension image | `build-img`, once per ceremony |
| `RITE-OUT` | Empty FAT32 partition, mounted at `/rite/outputs` | `build-img` |

The first three partitions are the Live system. Its root hash, which covers every block
of the root partition, is on the UKI's command line, and the kernel checks each block it
reads against it: a modified block stops the machine. The system writes to memory, never
to the medium, except for the outputs partition.

At boot, the system copies the ceremony layer into memory once, records its SHA-256 in
`/run/rite/ceremony.sha256`, and merges the copy into `/usr` (systemd-sysext); the
ceremony files appear in `/rite/inputs`. A layer with files outside `/usr/share/rite`,
which could replace programs of the system, is not merged, and the start screen says so.
The same Live system serves every ceremony. The outputs partition is FAT32, which Linux,
macOS and Windows read and write without extra drivers.

## Released tooling and Live systems

Each release publishes the Docker tooling image as `ghcr.io/rite-ly/rite-img:<version>`,
and a Live system per architecture, `rite-live-<version>-amd64.img.xz` and
`rite-live-<version>-arm64.img.xz`, with the release files. The release workflow builds
each Live system with that release's `rite-img` image and the `rite` binary from its
`rite` Docker image, which has the PIV and YubiKey backends. To use them, skip to
[Add a ceremony](#add-a-ceremony), with `ghcr.io/rite-ly/rite-img:<version>` in place of
`rite-img` and the downloaded file as `--system`; `build-img` reads it compressed.
Releases up to 0.7.2 name the file `rite-base-<version>-<arch>.img.xz`, and their
`rite-img` takes `--base` and `--ceremony` in place of `--system` and `--definition`.

Check the downloads against the release before using them:

```
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify rite-live-<version>-amd64.img.xz --repo rite-ly/rite
gh attestation verify oci://ghcr.io/rite-ly/rite-img:<version> --repo rite-ly/rite
```

The attestations tie each file and the image to the release workflow run and its commit.
The Debian packages a Live system holds, with their versions, are listed in
`rite-live-<version>-<arch>.manifest.json` next to it.

Its root hash is in `rite-live-<version>-<arch>.roothash`, which `SHA256SUMS` and the
attestations also cover. The Live system is not reproducible, so this file is the reference
for its root hash. On a machine booted from the medium, the second terminal shows the root
hash the system runs with:

```
grep -o 'roothash=[0-9a-f]*' /proc/cmdline
```

## Build the Docker tooling image

Two kinds of image appear on this page: the Docker image that holds the build tools, and
the bootable `.img` those tools produce. Build the Docker image from the repo root:

```
docker build -t rite-img img/
```

Run `build-system` with `--privileged`, because mkosi, which builds the Live system,
mounts file systems inside its build tree. `build-img` and `extract` run without
privileges.

The examples mount the current directory at `/work`, the commands' working directory, and
run from the repo root. Relative paths then mean the same inside the container and on the
host, and the commands print them back as given. Every file a command reads or writes must
be under the mounted directory. The examples write into `out/`, which git ignores:

```
mkdir -p out
```

## Build the Live system

`build-system` takes a Linux `rite` binary. The architecture comes from the binary.
Released Live systems carry the glibc binary, which is also published in the `-glibc`
release tarballs. It has the PIV and YubiKey backends and vendors the OpenSSL version of
the `openssl-src` crate in `Cargo.lock`. The manifest lists `libssl3t64` for the toolbox
`openssl` command, not for `rite`.
A Bake target builds the binary on its own, here for arm64, into `dist/glibc-arm64/`:

```
docker buildx bake binary-glibc-arm64
```

The static binary from a `rite-<version>-linux-<arch>.tar.gz` release archive also works,
for ceremonies that use no hardware token.

```
docker run --rm --privileged -v "$PWD:/work" rite-img build-system \
    --binary dist/glibc-arm64/rite \
    --output out/rite-live-arm64.img
```

A build downloads the Debian packages from snapshot.debian.org, and takes a few minutes.
`--manifest FILE` also writes the list of packages and their versions.

An amd64 Live system builds the same way on an arm64 host, with the amd64 binary: Docker
Desktop runs the image's amd64 programs under emulation, which makes the build slower.
The amd64 binary compiles under emulation too, which takes far longer than the native
build:

```
docker buildx bake binary-glibc-amd64
docker run --rm --privileged -v "$PWD:/work" rite-img build-system \
    --binary dist/glibc-amd64/rite \
    --output out/rite-live-amd64.img
```

`build-system` prints two lines:

```
image  sha256:7d27da65…  out/rite-live-arm64.img
root   744904d5…
```

`image` is the SHA-256 of the file. `root` is the root hash, which the build puts on the
kernel command line (`roothash=` in `/proc/cmdline` on the running system).
`--roothash FILE` also writes it to a file, as the release does.

The Debian packages are those snapshot.debian.org served at the date in
`img/mkosi/mkosi.conf`; moving that date is how package updates come in. Two builds of the
Live system install the same packages but differ in timestamps, so the released Live
system is the reference.

### What the Live system contains

- The ceremony session on tty1 and a second terminal on tty2 (see
  [Run the ceremony](#run-the-ceremony)), as the `rite` user.
- PC/SC (`pcscd`) and the CCID driver, for PIV and YubiKey.
- CPU microcode updates for AMD and Intel processors (amd64), which the kernel applies
  at boot.
- Network: DHCP on every wired link. No Wi-Fi, Bluetooth, NFC or cellular modem driver
  loads, so the only network it can use is a cable the participants can see.
- A toolbox, which neither `rite` nor the session needs, for the operator's convenience in
  the second terminal: `openssl`, `jq`, `xxd`, `file`, `nano`, `ip`, `qrencode`,
  `zbarimg`, `gpg`, `ykman`, `pkcs11-tool`, `pcsc_scan`, `python3` and `man`. They are
  part of the Live system, so its root hash covers them.

## Add a ceremony

```
docker run --rm -v "$PWD:/work" rite-img build-img \
    --system out/rite-live-arm64.img \
    --definition examples/showcase/demo.rite.yaml \
    --output out/demo.img
```

`--material FILE` adds a file the ceremony reads, and can be repeated. A definition names
its files by paths relative to its own directory, so a material must be in the definition's
directory or below it, and keeps that relative path on the medium:

```
docker run --rm -v "$PWD:/work" rite-img build-img \
    --system out/rite-live-arm64.img \
    --definition examples/showcase/import_key.rite.yaml \
    --material examples/showcase/test_keys/transport_kek_component.bin \
    --material examples/showcase/test_keys/escrow_private.pem \
    --output out/import_key.img
```

### Several ceremonies on one medium

`--definition` can be repeated to put several ceremonies on one medium. Each input keeps
its path relative to the common ancestor directory of all the definitions, which keeps
every definition's relative file references valid. For example, with
`examples/showcase/demo.rite.yaml` and `examples/pki/root_ca_software.rite.yaml`, the common
ancestor is `examples/`, and the medium holds `/rite/inputs/showcase/demo.rite.yaml` and
`/rite/inputs/pki/root_ca_software.rite.yaml`.

A medium with every example, for demonstrations (Bash, from the repo root):

```
args=()
for f in examples/showcase/*.rite.yaml examples/pki/*.rite.yaml; do args+=(--definition "$f"); done
for f in examples/showcase/test_*/* examples/pki/test_*/*; do args+=(--material "$f"); done
docker run --rm -v "$PWD:/work" rite-img build-img \
    --system out/rite-live-arm64.img "${args[@]}" --output out/examples.img
```

For a real ceremony, use one ceremony per medium. Each medium's outputs partition then
holds a single ceremony's evidence, and the operator has no choice of ceremony to get
wrong.

### Hashes

`build-img` is reproducible: with the same `rite-img` Docker image, the same Live system,
definitions and materials give the same `.img`, byte for byte. Every file, file system and
partition table `build-img` generates has fixed modes, owners, identifiers and timestamps,
so only the contents and paths of the inputs affect it.

The tool versions in the Docker image are part of the input. Building the Docker image
installs the current Debian packages, so two builds of `img/Dockerfile` can differ. A
rebuild for comparison uses the same Docker image, identified by its ID rather than its
tag:

```
docker image inspect --format '{{.Id}}' rite-img
```

A released image is pinned by its digest instead, which `docker pull` prints:
`ghcr.io/rite-ly/rite-img@sha256:<digest>`.

`build-img` prints its SHA-256 hashes on stdout, one per line, and its progress on stderr,
so `> hashes.txt` keeps only the hashes:

```
image       sha256:f581111c…  out/demo.img
medium      sha256:d193b10b…  977272832
layer       sha256:6f90fd17…
definition  sha256:c61593fd…  /rite/inputs/demo.rite.yaml
```

| Line | What the hash covers |
|---|---|
| `image` | The complete `.img` file, for checking a download or a copy. |
| `medium` | The first `N` bytes of the image, with `N` the last field of the line: everything before the outputs partition, that is the partition table, the Live system and the ceremony layer. Participants use it to check the ceremony medium they wrote. |
| `layer` | The ceremony layer partition. The running system records the same value in `/run/rite/ceremony.sha256`. |
| `definition` | Each ceremony definition, as raw bytes, with its path on the medium. The transcript records the same value as the definition's `template` digest in `ceremony_started`. |

`build-system` prints the lines shown above, and `extract` the path of each run directory
it copies. Errors go to stderr; a usage error exits with status 2 and any other failure
with status 1. With `--verbose`, `build-system` and `build-img` show the output of the
tools they run.

## Write it to a USB drive

Writing the image erases the target device. Check the device name carefully, and use the
whole USB disk, not a partition on it.

On Linux, with `/dev/sdX` the USB drive (`lsblk` lists the disks):

```
sudo dd if=out/demo.img of=/dev/sdX bs=4M conv=fsync status=progress
```

On macOS, with `/dev/diskN` the USB drive (`diskutil list` lists the disks), then eject it
before unplugging:

```
diskutil unmountDisk /dev/diskN
sudo dd if=out/demo.img of=/dev/rdiskN bs=4m
diskutil eject /dev/diskN
```

Each participant can check the ceremony medium against the published `medium` hash.
Replace `N` with the length in bytes from the end of the `medium` line:

```
sudo head -c N /dev/sdX | sha256sum               # Linux
sudo head -c N /dev/rdiskN | shasum -a 256        # macOS
```

The medium starts with the same bytes as the image, so the same `N` applies to both. The
check excludes the outputs partition: plugging the medium into a machine can write to that
partition (macOS adds its own files when it mounts it), and the ceremony writes to it, so
the check gives the same result before and after the ceremony.

## Run the ceremony

The machine must boot the medium in UEFI mode, with Secure Boot off, and with no other
ceremony medium plugged in: the system looks for the ceremony layer and the outputs
partition on the disk its root comes from, and two media made from the same Live system
have the same root. The start screen's SHA-256 shows which ceremony was loaded. The medium
stays plugged in until power off: the system reads its files from it as they are used.

The UKI is not signed, so firmware with Secure Boot on refuses it. The integrity of the
medium rests on the `medium` hash the participants check before boot, and on dm-verity,
which checks every block of the root as it is read. Machines whose firmware cannot turn
Secure Boot off cannot run Rite Live.

The boot menu has three entries:

- **Rite Ceremony**: the ceremony session in a fullscreen terminal (cage and foot), with
  strict IOMMU DMA protection.
- **Rite Ceremony (safe mode)**: the same session on the text console, with boot progress
  shown, without IOMMU protection and without a graphics driver, for machines where the
  main entry does not boot or does not display.
- **Power Off The System**.

The boot menu cannot edit the entries: their kernel command line, root hash included, is
part of the UKI. With Secure Boot off, a UEFI shell can still start the UKI with another
command line (see [What Rite Live proves](#what-rite-live-proves)).

The session starts on its own as the `rite` user. Its start screen shows the `rite`
version, the ceremony definition with its SHA-256, where the outputs go, and the `rite run`
command for the ceremony. Pressing Enter starts `rite run` with that ceremony, and
`rite run` asks for any parameter the ceremony leaves open. For other flags, such as
`--dry-run` or `--role`, the operator types the word `shell` at the prompt and runs the
command by hand.

When the outputs partition is missing or does not mount, the start screen says so and
offers no Enter shortcut: the ceremony's outputs would be lost at power off, so running it
anyway takes typing the command in the shell.

On a medium with several ceremonies, the start screen lists each ceremony with its SHA-256
and opens the shell. The operator chooses the ceremony and runs it with `rite run`, so the
SHA-256 shown is the one to compare with the published `definition` hash.

The shell has tab completion for `rite` and starts in `/rite/outputs`. `rite run` writes
to the current directory unless given `--output`, so a run started from the shell also
writes to the medium. `poweroff` shuts the machine down; leaving the shell returns to the
start screen. If the graphical session fails to start, the session continues on the text
console.

Ctrl+Alt+F2 opens a second terminal, a shell as the `rite` user in `/rite/outputs`, and
Ctrl+Alt+F1 returns to the ceremony session; the ceremony keeps running in the meantime.
Each terminal shows one at a time, and they do not share a clipboard.

In the graphical session, dragging with the mouse selects text, and a middle click or
Ctrl+Shift+V pastes it; Ctrl+Shift+C copies a selection to the clipboard. The text console
has no mouse support.

The `rite` user has no root access and the system has no `sudo`. polkit lets it power the
machine off and reboot it (`poweroff`, `reboot`, `shutdown`), use smart cards and switch
terminals, and refuses everything else. No terminal offers a login.

The system gets a network address by DHCP on any wired link, and loads no radio
driver. A ceremony that needs an air gap establishes it physically, by leaving out the
cable, and records it as a witnessed confirmation step, such as `verify_air_gap` in
`examples/showcase/demo.rite.yaml`.

The keyboard layout is US.

### Known hardware issues

- **Secure Boot.** The setting is named differently from one firmware to another. On ASUS
  boards, Boot > Secure Boot > OS Type set to "Other OS" turns it off, while the page may
  still show Secure Boot as enabled. A firmware that only offers to clear the Secure Boot
  keys can save them first: restore that copy afterwards rather than the factory keys,
  which may lack certificates the installed system needs. Windows with BitLocker asks for
  its recovery key when it boots with a different Secure Boot setting, so set it back
  before starting Windows again.
- **Boot menu entries.** The firmware's boot menu may list the medium several times. The
  entry that starts with "UEFI:" and names partition 1, the EFI system partition, boots
  the image. Entries without "UEFI:" are legacy BIOS boot, which the medium does not have.
- **Firmware messages.** Lines such as `[Firmware Bug]` from AMD-Vi or `tpm_crb … probe
  failed` at the start of the boot report faulty firmware tables. The system continues
  without the affected feature.
- **TPM.** The system neither uses nor waits for the TPM, and leaves it as it found it: the
  systemd services that store a key or a policy in the TPM are masked.
- **Graphics.** The system has the firmware that AMD, NVIDIA and Intel graphics drivers
  load. AMD memory encryption stays off, because the NVIDIA driver leaves the display black
  with it. On a machine where the main entry still shows nothing, safe mode keeps the
  display the firmware set up.

## Read the outputs

On another machine, mount the `RITE-OUT` partition; most desktop systems mount it when the
medium is plugged in. It holds one directory per run. Copy the directory for the run to
check, then pass the path of the copy to `rite verify`:

```
rite verify /path/to/copied/run
```

From an image file, for a ceremony run in a VM, `extract` copies the partition's content
without mounting it, into a new or empty directory, and prints the path of each run
directory it copied:

```
docker run --rm -v "$PWD:/work" rite-img extract \
    --image out/demo-run.img \
    --output out/outputs
```

## Test in a VM

On an Apple Silicon Mac, with QEMU from Homebrew, boot a copy of the image so the original
stays unchanged:

```
cp out/demo.img out/demo-run.img
truncate -s 64m out/vars.fd
qemu-system-aarch64 \
    -machine virt -accel hvf -cpu host -smp 4 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="$(brew --prefix)/share/qemu/edk2-aarch64-code.fd" \
    -drive if=pflash,format=raw,file=out/vars.fd \
    -drive if=none,id=stick,format=raw,file=out/demo-run.img \
    -device qemu-xhci -device usb-storage,drive=stick \
    -device virtio-gpu-pci -device usb-kbd -device usb-tablet \
    -nic none
```

`vars.fd` is the firmware's variable store, the VM's counterpart of a motherboard's NVRAM;
start each test with a new one. `-nic none` gives the VM no network interface. An amd64
image boots the same way under `qemu-system-x86_64 -machine q35`, with OVMF
(`edk2-x86_64-code.fd`) as the UEFI firmware.

## What Rite Live proves

The checks on this page establish different things:

- **Medium integrity.** The `medium` hash lets each participant check that the measured
  part of the written medium matches the published digest. This authenticates the medium
  only if the digest comes through a channel the participants trust independently of the
  image. A digest obtained from the same source as the image does not authenticate it.
- **Integrity while running.** The kernel checks every block of the root it reads against
  the root hash on the UKI's command line, and stops the machine on a mismatch. A medium
  modified after the participants checked it, in the root partition, is caught when the
  modified block is read. The ceremony layer is read once into memory, and its hash is
  recorded at that moment.
- **Reproducibility.** Rebuilding the image from the released Live system and the same
  definitions and materials, with the same `rite-img` Docker image, gives a check that
  does not rely on whoever built the medium.
- **Ceremony identity.** The transcript's `template` digest identifies the ceremony
  definition the run used, and `rite verify` checks the transcript and its artifacts.

Rite Live does not establish what actually ran. Nothing in the transcript records which
Live system booted, and no TPM is used. With Secure Boot off, someone who can write to the
medium between the check and the boot can replace the UKI, root hash included. Anyone at
the keyboard during boot can open a UEFI shell, from the firmware or from another USB
drive, and start the UKI with their own command line, which gives a root shell without
changing a byte of the medium. The mitigation is physical supervision: participants keep
the medium and the machine under observation from the check to power off, so they can see
any interaction with the boot process. Observation does not prove what booted.

## Files

| File | Role |
|---|---|
| `img/Dockerfile`, `img/entrypoint.sh` | Docker tooling image, with mkosi pinned by commit, and its subcommand dispatch |
| `img/build-system.sh` | Live system build with mkosi |
| `img/mkosi/mkosi.conf`, `img/mkosi/mkosi.conf.d/` | Live system: distribution and snapshot date, packages, kernel command line |
| `img/mkosi/mkosi.uki-profiles/safe.conf` | The safe mode boot entry |
| `img/mkosi/mkosi.repart/` | Partitions of the Live system: EFI system partition, root, root verity |
| `img/mkosi/mkosi.postinst.chroot`, `img/mkosi/mkosi.finalize` | Build-time setup inside the image: the `rite` user, completion, masked units; the boot menu title |
| `img/mkosi/mkosi.extra/` | Files copied into the image, at their paths in it |
| `.../efi/loader/loader.conf` | Boot menu: timeout, no editing |
| `.../usr/lib/systemd/system/rite-session.service`, `rite-shell.service`, `.../etc/pam.d/rite-session` | The session on tty1 and the shell on tty2, run as `rite` |
| `.../usr/lib/rite/rite-kiosk` | Starts the session or the shell in cage and foot, or on the text console |
| `.../usr/lib/rite/rite-session`, `rite-shell` | The operator's start screen, and the second terminal |
| `.../usr/lib/systemd/system/rite-ceremony-load.service`, `.../usr/lib/rite/load-ceremony` | Copies the ceremony layer into memory and records its hash |
| `.../usr/lib/rite/mount-outputs`, `boot-partition` | Mounts `RITE-OUT` at `/rite/outputs`; finds a partition on the boot disk |
| `.../usr/lib/systemd/system-preset/10-rite.preset` | Units enabled at build time |
| `.../etc/systemd/network/80-rite-dhcp.network` | DHCP on wired links |
| `.../etc/skel/.bashrc`, `.../etc/xdg/foot/foot.ini`, `.../etc/systemd/logind.conf.d/rite.conf` | Shell, terminal and login settings |
| `.../etc/polkit-1/rules.d/10-rite.rules` | polkit rule: the `rite` user may use smart cards, switch terminals, power off and reboot, nothing else |
| `img/build-img.sh`, `img/ceremony.repart.d/` | Ceremony layer and outputs partition |
| `img/extract-outputs.sh` | Outputs from an image file |
| `.github/workflows/ci.yml` | The `Image` jobs build a Live system and an image for each architecture, and check that `build-img` is reproducible, on every pull request to main and push to main |
| `.github/workflows/release.yml` | Publishes `rite-img` and the Live systems with each release |
