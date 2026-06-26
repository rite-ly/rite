# PIV / YubiKey Ceremonies

Examples that drive a hardware PIV smart card (such as a YubiKey) where the
private key never leaves the device.

These ceremonies require a `rite` binary with the hardware backends. The
prebuilt macOS and Windows release binaries (including `brew install rite`) and
the Docker image (`ghcr.io/rite-ly/rite`) already include them. Only the static
musl Linux tarballs leave them out, so on Linux from a tarball build from source:

```sh
cargo build -p rite --features piv,yubikey
```

The `piv` and `yubikey` features link the PC/SC system library (`libpcsclite`
on Linux; built in on macOS and Windows) and are off in the default feature set.

## Ceremonies

### `yubikey_signing.rite.yaml`: Release Signing with YubiKey PIV

Signs a release manifest with an on-device key in PIV slot 9C. Demonstrates:

- Reading the signing certificate from the slot (`piv_read_certificate`)
- Proving the key was generated on-device, never imported
  (`yubikey_attest_slot`, the Yubico F9 attestation)
- A PIN-protected detached signature over the manifest (`piv_sign`)
- Witness and operator attestation in the closing act

The ceremony assumes slot 9C is already provisioned with the signing key and its
certificate.

## Running

Validate the ceremony (no hardware needed):

```sh
cargo run -p rite --features piv,yubikey -- check examples/piv/yubikey_signing.rite.yaml
```

Execute with a real YubiKey inserted:

```sh
cargo run -p rite --features piv,yubikey -- run examples/piv/yubikey_signing.rite.yaml
```

### Dry run

`--dry-run` substitutes a mock backend so the ceremony can be rehearsed without a
device:

```sh
cargo run -p rite --features piv,yubikey -- run --dry-run --frontend headless \
  examples/piv/yubikey_signing.rite.yaml
```

The dry run walks the whole ceremony, including `piv_sign`: the mock returns
placeholder certificates and lazily mints a synthetic stand-in signing key for
the slot, so the rehearsal completes without a device. The signatures and
attestation certificates it produces are clearly synthetic, never real evidence.
See [`docs/development/hardware-backends.md`](../../docs/development/hardware-backends.md)
for the manual hardware verification procedure (real on-card signing and
attestation-root verification).
