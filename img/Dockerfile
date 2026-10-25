# img/Dockerfile
# Single image with the tools that build Rite Live.
#
# Subcommands (dispatched by entrypoint.sh):
#   build-system  Build the Live system: Debian, the rite binary and the
#                 ceremony session. Needs --privileged (mkosi mounts inside its
#                 build tree).
#   build-img     Add a ceremony to a Live system and emit a flashable .img.
#   extract       Copy ceremony outputs out of a .img.
#
# The three share one image because they need the same tooling (systemd-repart,
# dosfstools, mtools).

FROM debian:trixie-20261005@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5

# The tools mkosi drives, from Debian. build-img and extract use systemd-repart,
# fdisk, dosfstools and mtools on their own.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    python3 \
    python3-pefile \
    apt \
    dpkg \
    debian-archive-keyring \
    systemd-repart \
    systemd-ukify \
    systemd-boot \
    systemd-boot-efi \
    udev \
    cryptsetup-bin \
    erofs-utils \
    dosfstools \
    mtools \
    fdisk \
    util-linux \
    file \
    kmod \
    cpio \
    zstd \
    xz-utils \
    bubblewrap \
    uidmap \
    && rm -rf /var/lib/apt/lists/*

# mkosi 27.1, pinned by commit. It is pure Python and runs from the checkout;
# Debian trixie packages an older version.
ARG MKOSI_COMMIT=ecf7f5702bb2052b7a69cab3fe7d37bc3b9ad77b
RUN git init -q /opt/mkosi \
    && git -C /opt/mkosi fetch -q --depth 1 https://github.com/systemd/mkosi.git "$MKOSI_COMMIT" \
    && git -C /opt/mkosi checkout -q FETCH_HEAD \
    && rm -rf /opt/mkosi/.git \
    && ln -s /opt/mkosi/bin/mkosi /usr/local/bin/mkosi

# The commands run from /work, where the examples mount the current directory,
# so relative paths given to them, and printed back, are the same inside the
# container and on the host.
WORKDIR /work

COPY lib/              /img/lib/
COPY mkosi/            /img/mkosi/
COPY ceremony.repart.d/ /img/ceremony.repart.d/
COPY entrypoint.sh build-system.sh build-img.sh extract-outputs.sh /img/
RUN chmod +x /img/*.sh

ENTRYPOINT ["/img/entrypoint.sh"]
