# PIV / YubiKey Ceremonies

Examples using a PIV smart card, such as a YubiKey. The private key stays on
the device.

These ceremonies need a `rite` binary built with the `piv` and `yubikey`
features. The macOS and Windows release binaries (including `brew install rite`),
the Docker image (`ghcr.io/rite-ly/rite`) and the Rite Live system
(`docs/development/img.md`) include them. Static musl Linux binaries do not; build from source on Linux:

```sh
cargo build -p rite --features piv,yubikey
```

On Linux, the build needs `libpcsclite-dev`. PC/SC is built into macOS and
Windows.

## `yubikey_signing.rite.yaml`: Release signing with PIV

Signs a release manifest with the key in PIV slot 9C. The ceremony declares
the key as a `backend_key` material and the card's PIN under `credentials:`,
reads its certificate, requests a Yubico F9 attestation certificate
showing the key was generated on the device and not imported, asks for the PIN
in an `authenticate` step, signs the manifest with
`sign_data`, checks the signature in software against the certificate, and
records witness and operator attestations. Slot 9C must already contain the
signing key and certificate, and the YubiKey needs firmware 5.3 or later, which
reports a slot's public key.

Slot 9C clears the PIN after each signature, so a ceremony signing twice with
it puts an `authenticate` step before each. To bind the ceremony to one card, add
the key's `fingerprint:` to the material once it is known: a run shows it in
the `key_bound` fact.

[Preparing a YubiKey](../../docs/yubikey.md) covers setting up a card for real
ceremonies. To prepare a YubiKey kept for testing, generate a key and a self-signed
certificate in 9C with `ykman`. This replaces whatever slot 9C holds; the
second command asks for the PIN (factory default `123456`):

```sh
ykman piv keys generate --algorithm ECCP256 9c 9c.pub
ykman piv certificates generate --subject "CN=Release Signing" 9c 9c.pub
```

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

## `yubikey_key_generation.rite.yaml`: Key generation on the card

Generates a P-256 signing key in slot 9C, requests its attestation
certificate, and outputs its public key. The card's management key is stored
on it behind the PIN (`ykman piv access change-management-key --generate
--protect`): the `authenticate` step asks for the PIN, the card releases the
management key, and `generate_key` replaces whatever slot 9C holds. The card
reports its management key's algorithm, so an AES key (the default from
firmware 5.7) and a 3DES key both work.

```sh
cargo run -p rite --features piv,yubikey -- check examples/piv/yubikey_key_generation.rite.yaml
```

For manual verification of real on-card signing and the attestation root, see
[hardware backends](../../docs/development/hardware-backends.md).
