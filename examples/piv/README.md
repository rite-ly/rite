# PIV / YubiKey Ceremonies

Examples using a PIV smart card, such as a YubiKey. The private key stays on
the device.

These ceremonies need a `rite` binary built with the `piv` and `yubikey`
features. The macOS and Windows release binaries (including `brew install rite`)
and the Docker image (`ghcr.io/rite-ly/rite`) include them. Static musl Linux binaries do not; build from source on Linux:

```sh
cargo build -p rite --features piv,yubikey
```

On Linux, the build needs `libpcsclite-dev`. PC/SC is built into macOS and
Windows.

## `yubikey_signing.rite.yaml`: Release signing with PIV

Signs a release manifest with the key in PIV slot 9C. The ceremony reads its
certificate, requests a Yubico F9 attestation certificate showing the key was
generated on the device and not imported, signs the manifest with the PIN, and
records witness and operator attestations. Slot 9C must already contain the
signing key and certificate.

Check the definition without a card:

```sh
cargo run -p rite --features piv,yubikey -- check examples/piv/yubikey_signing.rite.yaml
```

Run it with the YubiKey inserted:

```sh
cargo run -p rite --features piv,yubikey -- run examples/piv/yubikey_signing.rite.yaml
```

### Rehearse without a device

`--dry-run` substitutes a mock backend, which supplies placeholder
certificates and a synthetic slot key. The ceremony can complete without a
YubiKey, but its signature and attestation certificate are synthetic and are
not evidence of a real device:

```sh
cargo run -p rite --features piv,yubikey -- run --dry-run --frontend headless \
  examples/piv/yubikey_signing.rite.yaml
```

For manual verification of real on-card signing and the attestation root, see
[hardware backends](../../docs/development/hardware-backends.md).
