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
then:

1. reads the key's certificate from the card;
2. obtains the key's attestation with `attest_key`;
3. checks the attestation with `verify_attestation`: the chain against
   Yubico's roots, the attested key against the signing key, and the required
   PIN policy;
4. asks for the PIN in an `authenticate` step and signs the manifest with
   `sign_data`;
5. checks the signature in software against the certificate, and records
   witness and operator attestations.

Slot 9C must already contain the signing key and certificate, and the YubiKey
needs firmware 5.3 or later, which reports a slot's public key. A YubiKey
attests only keys it generated; importing a key into the slot makes the
attestation step fail.

The transcript records the chain, anchor, claims, and requirement results. It
never records the card's serial. A relying party can repeat the chain check
with the attestation bundle and the roots and intermediates named by the
ceremony:

```sh
openssl verify -CAfile examples/piv/yubico/attestation-roots.pem \
  -untrusted signing_key_attestation.pem \
  -untrusted examples/piv/yubico/attestation-intermediates.pem \
  signing_key_attestation.pem
```

The [`yubico/` files](yubico/) contain Yubico's published roots and
intermediates. See [the YubiKey guide](../../docs/yubikey.md) for which roots
apply to each firmware generation. Check the roots against Yubico's
publication before a real ceremony.

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
certificates and a synthetic slot key. It attests keys under a rehearsal root.
The run trusts that root as well as the ceremony's roots; `key_attested`
records the anchor as `rehearsal`, and the requirements do not affect the
rehearsal result. Nothing the rehearsal produces is evidence of a real device:

```sh
cargo run -p rite --features piv,yubikey -- run --dry-run --frontend headless \
  examples/piv/yubikey_signing.rite.yaml
```

## `yubikey_key_generation.rite.yaml`: Key generation on the card

Generates a P-256 signing key in slot 9C that requires the PIN before each use
and a touch, cached for 15 seconds. The ceremony has the card attest the key,
checks the attestation against Yubico's roots and the required policies, and
outputs the public key.

The card's management key is stored on it behind the PIN (`ykman piv access
change-management-key --generate --protect`): the `authenticate` step asks for
the PIN, the card releases the management key, and `generate_key` replaces
whatever slot 9C holds. The card reports its management key's algorithm, so an
AES key (the default from firmware 5.7) and a 3DES key both work.

```sh
cargo run -p rite --features piv,yubikey -- check examples/piv/yubikey_key_generation.rite.yaml
cargo run -p rite --features piv,yubikey -- run --dry-run --frontend headless \
  examples/piv/yubikey_key_generation.rite.yaml
```

For manual verification of real on-card signing and the attestation root, see
[hardware backends](../../docs/development/hardware-backends.md).
