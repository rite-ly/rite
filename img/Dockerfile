# img/Dockerfile
# Single image that builds Rite ceremony images.
#
# Subcommands (dispatched by entrypoint.sh):
#   build-iso   Assemble a base Debian Live ISO with the rite binary.
#               Needs --privileged (live-build mounts inside its chroot).
#   build-img   Layer a ceremony onto a base ISO and emit a flashable .img.
#   extract     Copy ceremony outputs out of a .img.
#
# The three share one image because they need the same tooling (live-build,
# squashfs-tools, xorriso, dosfstools, mtools).

FROM debian:trixie-20260316@sha256:55a15a112b42be10bfc8092fcc40b6748dc236f7ef46a358d9392b339e9d60e8

ARG TARGETARCH

RUN apt-get update && apt-get install -y \
    live-build \
    debootstrap \
    squashfs-tools \
    xorriso \
    mtools \
    dosfstools \
    fdisk \
    util-linux \
    zstd \
    && if [ "$TARGETARCH" = "arm64" ]; then \
         apt-get install -y grub-efi-arm64-bin; \
       else \
         apt-get install -y grub-efi-amd64-bin; \
       fi \
    && rm -rf /var/lib/apt/lists/*

# live-build's working directory, where build-iso writes its configuration and
# the build tree.
RUN mkdir /iso-build

# The commands run from /work, where the examples mount the current directory,
# so relative paths given to them, and printed back, are the same inside the
# container and on the host.
WORKDIR /work

COPY lib/    /img/lib/
COPY auto/   /img/auto/
COPY config/ /img/config/
COPY entrypoint.sh build-iso.sh build-img.sh extract-outputs.sh /img/
RUN chmod +x /img/*.sh /img/auto/*

ENTRYPOINT ["/img/entrypoint.sh"]
