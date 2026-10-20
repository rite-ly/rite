# Ceremony image

`img/` builds a bootable USB image for running a Rite ceremony. The image holds a Debian
live system with the `rite` binary, the ceremony and its input materials, and a separate
partition for the outputs of each run.

The operator boots the machine from the stick, runs the ceremony, and reads the outputs
back on another machine.

## Layout of an image

| Part | Content | Built by |
|---|---|---|
| Base ISO | Debian trixie live system, `rite`, the ceremony session | `build-iso`, once per `rite` release and architecture |
| Ceremony layer | `ceremony.squashfs`: the ceremony YAML files and their materials, in `/rite/inputs` | `build-img`, once per ceremony |
| EFI system partition | A byte copy of the ISO's EFI boot image (`/boot/grub/efi.img`, a small FAT filesystem), for firmware that boots a USB disk from its EFI system partition | `build-img` |
| Outputs partition | Empty FAT32 partition labelled `RITE-OUT`, mounted at `/rite/outputs` | `build-img` |

At boot, live-boot overlays the ceremony layer on the base system, so the same base ISO
serves every ceremony. The outputs partition is FAT32, which Linux, macOS and Windows read
and write without extra drivers.

## Released tooling and base ISOs

Each release publishes the Docker tooling image as `ghcr.io/rite-ly/rite-img:<version>`,
and a base ISO per architecture, `rite-<version>-amd64.iso` and `rite-<version>-arm64.iso`,
with the release files. The release workflow builds each ISO with that release's
`rite-img` image and Linux `rite` binary. To use them, skip to
[Add a ceremony](#add-a-ceremony), with `ghcr.io/rite-ly/rite-img:<version>` in place of
`rite-img` and the downloaded ISO as `--iso`.

Check the downloads against the release before using them:

```
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify rite-<version>-amd64.iso --repo rite-ly/rite
gh attestation verify oci://ghcr.io/rite-ly/rite-img:<version> --repo rite-ly/rite
```

The attestations tie each file and the image to the release workflow run and its commit.
An ISO cannot be rebuilt to the same bytes, because live-build downloads the current
Debian packages, so the published hash is the one to cite for a base ISO. The Debian
packages it holds, with their versions, are listed in `rite-<version>-<arch>.packages`
next to it, and in the ISO at `/live/filesystem.packages`.

The `rite` in a base ISO is the Linux release binary, which has no PIV or YubiKey
backend, and the live system has no `pcscd`. A ceremony that uses a hardware token does
not run from these ISOs.

## Build the Docker tooling image

Two kinds of image appear on this page: the Docker image that holds the build tools, and
the bootable `.img` those tools produce. Build the Docker image from the repo root:

```
docker build -t rite-img img/
```

Run `build-iso` with `--privileged`, because live-build mounts filesystems inside its
chroot. `build-img` and `extract` run without privileges.

The examples mount the current directory at `/work`, the commands' working directory, and
run from the repo root. Relative paths then mean the same inside the container and on the
host, and the commands print them back as given. Every file a command reads or writes must
be under the mounted directory. The examples write into `out/`, which git ignores:

```
mkdir -p out
```

## Build the base ISO

`build-iso` takes a Linux `rite` binary, from a `rite-<version>-linux-<arch>.tar.gz`
release archive or a musl build. The architecture comes from the binary.

```
docker run --rm --privileged -v "$PWD:/work" rite-img build-iso \
    --binary rite \
    --output out/rite-arm64.iso
```

A build downloads the Debian packages, and typically takes about ten minutes, depending on
the network and the host.

The ISO is built for the binary's architecture, and the Docker image must run that
architecture too. To build an amd64 ISO on an arm64 host, build the Docker image for amd64
and run it under emulation, which is slower:

```
docker build --platform linux/amd64 -t rite-img:amd64 img/
docker run --rm --privileged --platform linux/amd64 -v "$PWD:/work" rite-img:amd64 build-iso \
    --binary rite-amd64 \
    --output out/rite-amd64.iso
```

## Add a ceremony

```
docker run --rm -v "$PWD:/work" rite-img build-img \
    --iso out/rite-arm64.iso \
    --ceremony examples/showcase/demo.rite.yaml \
    --output out/demo.img
```

`--material FILE` adds a file the ceremony reads, and can be repeated. A definition names
its files by paths relative to its own directory, so a material must be in the ceremony's
directory or below it, and keeps that relative path on the stick:

```
docker run --rm -v "$PWD:/work" rite-img build-img \
    --iso out/rite-arm64.iso \
    --ceremony examples/showcase/import_key.rite.yaml \
    --material examples/showcase/test_keys/transport_kek_component.bin \
    --material examples/showcase/test_keys/escrow_private.pem \
    --output out/import_key.img
```

### Several ceremonies on one stick

`--ceremony` can be repeated to put several ceremonies on one stick. Each input keeps its
path relative to the common ancestor directory of all the ceremony files, which keeps every
ceremony's relative file references valid. For example, with
`examples/showcase/demo.rite.yaml` and `examples/pki/root_ca_software.rite.yaml`, the common
ancestor is `examples/`, and the stick holds `/rite/inputs/showcase/demo.rite.yaml` and
`/rite/inputs/pki/root_ca_software.rite.yaml`.

A stick with every example, for demonstrations (Bash, from the repo root):

```
args=()
for f in examples/showcase/*.rite.yaml examples/pki/*.rite.yaml; do args+=(--ceremony "$f"); done
for f in examples/showcase/test_*/* examples/pki/test_*/*; do args+=(--material "$f"); done
docker run --rm -v "$PWD:/work" rite-img build-img \
    --iso out/rite-arm64.iso "${args[@]}" --output out/examples.img
```

For a real ceremony, use one ceremony per stick. Each stick's outputs partition then holds
a single ceremony's evidence, and the operator has no choice of ceremony to get wrong.

### Hashes

`build-img` is reproducible: with the same `rite-img` Docker image, the same base ISO,
ceremonies and materials give the same `.img`, byte for byte. Every file, filesystem and
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
image     sha256:cf93263c…  out/demo.img
system    sha256:fa8234a7…  400869376
layer     sha256:dd7079ca…
ceremony  sha256:c61593fd…  /rite/inputs/demo.rite.yaml
```

| Line | What the hash covers |
|---|---|
| `image` | The complete `.img` file, for checking a download or a copy. |
| `system` | The first `N` bytes of the image, with `N` the last field of the line: everything before the outputs partition, that is the base system, the ceremony layer and the EFI system partition. Participants use it to check the written stick. |
| `layer` | `ceremony.squashfs`. |
| `ceremony` | Each ceremony YAML file, as raw bytes, with its path on the stick. The transcript records the same value as the definition's `template` digest in `ceremony_started`. |

`build-iso` prints one line, `iso  sha256:<hash>  <path>`, and `extract` the path of each
run directory it copies. Errors go to stderr; a usage error exits with status 2 and any
other failure with status 1. With `--verbose`, `build-iso` and `build-img` show the output
of the tools they run.

## Write it to a USB stick

Writing the image erases the target device. Check the device name carefully, and use the
whole USB disk, not a partition on it.

On Linux, with `/dev/sdX` the stick (`lsblk` lists the disks):

```
sudo dd if=out/demo.img of=/dev/sdX bs=4M conv=fsync status=progress
```

On macOS, with `/dev/diskN` the stick (`diskutil list` lists the disks), then eject it
before unplugging:

```
diskutil unmountDisk /dev/diskN
sudo dd if=out/demo.img of=/dev/rdiskN bs=4m
diskutil eject /dev/diskN
```

Each participant can check the stick against the published `system` hash. Replace `N`
with the length in bytes from the end of the `system` line:

```
sudo head -c N /dev/sdX | sha256sum               # Linux
sudo head -c N /dev/rdiskN | shasum -a 256        # macOS
```

The stick starts with the same bytes as the image, so the same `N` applies to both. The
check excludes the outputs partition: plugging the stick into a machine can write to that
partition (macOS adds its own files when it mounts it), and the ceremony writes to it, so
the check gives the same result before and after the ceremony.

## Run the ceremony

The machine must boot the stick in UEFI mode, with no other Rite stick plugged in: the
live system takes its base system and ceremony layer from the first Rite medium it finds,
which with two sticks present may be the other one. The start screen's SHA-256 shows
which ceremony was loaded, and the outputs go to the stick it was loaded from.

The image carries Debian's signed shim and GRUB, the boot path for UEFI Secure Boot.
Booting with Secure Boot on is not tested.

The boot menu has three entries:

- **Rite Ceremony**: the ceremony session in a fullscreen terminal (cage and foot), with
  memory encryption on AMD CPUs that support it and strict IOMMU DMA protection.
- **Rite Ceremony (safe mode)**: the same session on the text console, with boot progress
  shown and without memory encryption and IOMMU options, for machines where the main entry
  does not boot or does not display.
- **Power off**.

The session starts on its own as the `rite` user. Its start screen shows the `rite`
version, the ceremony file with its SHA-256, where the outputs go, and the `rite run`
command for the ceremony. Pressing Enter starts `rite run` with that ceremony, and
`rite run` asks for any parameter the ceremony leaves open. For other flags, such as
`--dry-run` or `--role`, the operator types the word `shell` at the prompt and runs the
command by hand.

When the outputs partition is missing or does not mount, the start screen says so and
offers no Enter shortcut: the ceremony's outputs would be lost at power off, so running it
anyway takes typing the command in the shell.

On a stick with several ceremonies, the start screen lists each ceremony with its SHA-256
and opens the shell. The operator chooses the ceremony and runs it with `rite run`, so the
SHA-256 shown is the one to compare with the published ceremony hash.

The shell has tab completion for `rite` and starts in `/rite/outputs`. `rite run` writes
to the current directory unless given `--output`, so a run started from the shell also
writes to the stick. `poweroff` shuts the machine down; leaving the shell returns to the
start screen. If the graphical session fails to start, the session continues on the text
console.

In the graphical session, dragging with the mouse selects text, and a middle click or
Ctrl+Shift+V pastes it; Ctrl+Shift+C copies a selection to the clipboard. The text console
has no mouse support.

The `rite` user has no root access. Its only `sudo` rule is `systemctl poweroff` and
`systemctl reboot`. No other virtual terminal offers a login.

The image keeps network drivers. A ceremony that needs an air gap establishes it
physically and records it as a witnessed confirmation step, such as `verify_air_gap` in
`examples/showcase/demo.rite.yaml`.

## Read the outputs

On another machine, mount the `RITE-OUT` partition; most desktop systems mount it when the
stick is plugged in. It holds one directory per run. Copy the directory for the run to
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

`vars.fd` is the firmware's variable store, the VM's counterpart of a motherboard's NVRAM.
`-nic none` gives the VM no network interface. An amd64 image boots the same way under
`qemu-system-x86_64` with OVMF as the UEFI firmware.

## What the image proves

The checks on this page establish different things:

- **Image integrity.** The `system` hash lets each participant check that the measured part
  of the written stick matches the published digest. This authenticates the image only if
  the digest comes through a channel the participants trust independently of the image. A
  digest obtained from the same source as the image does not authenticate it.
- **Reproducibility.** Rebuilding the image from the same base ISO, ceremony files and
  materials, with the same `rite-img` Docker image, gives a check that does not rely on
  whoever built the stick.
- **Ceremony identity.** The transcript's `template` digest identifies the ceremony
  definition the run used, and `rite verify` checks the transcript and its artifacts.

The image does not establish what actually ran. It does not measure its own boot: nothing
in the transcript records which base system booted, and no TPM is used. Anyone at the
keyboard during boot can edit the boot menu entry and get a root shell. The mitigation is
physical supervision: participants keep the machine under observation from power on, so
they can see any interaction with the boot process. Observation does not prove what
booted.

## Files

| File | Role |
|---|---|
| `img/Dockerfile`, `img/entrypoint.sh` | Docker tooling image and its subcommand dispatch |
| `img/build-iso.sh`, `img/auto/` | Base ISO build with live-build |
| `img/build-img.sh` | Ceremony layer, EFI system partition and outputs partition |
| `img/extract-outputs.sh` | Outputs from an image file |
| `img/config/packages.list.chroot` | Packages in the live system |
| `img/config/setup-hook.sh` | Build-time setup inside the image: completion, session unit, sudo rule |
| `img/config/rite-session.service`, `img/config/rite-session.pam` | The session on tty1, run as `rite` |
| `img/config/rite-kiosk` | Starts the session in cage and foot, or on the text console |
| `img/config/rite-session` | The operator's start screen |
| `img/config/mount-outputs` | Mounts `RITE-OUT` at `/rite/outputs` |
| `img/config/bootloaders/grub.cfg` | Boot menu |
| `img/config/bashrc`, `img/config/foot.ini`, `img/config/logind.conf` | Shell, terminal and login settings |
| `.github/workflows/img.yml` | Builds an image for each architecture, and checks that `build-img` is reproducible, on pull requests that change `img/` |
| `.github/workflows/release.yml` | Publishes `rite-img` and the base ISOs with each release |
