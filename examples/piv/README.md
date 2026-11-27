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
and then:

1. reads the key's certificate from the card;
2. asks the card to attest the key (`attest_key`): a certificate over the key,
   signed by the card's attestation key, followed by that key's certificate
   from slot F9;
3. checks the attestation (`verify_attestation`) against Yubico's roots: the
   chain reaches a root, the attested key is the signing key, and the card
   asks for the PIN before each use of it;
4. asks for the PIN in an `authenticate` step and signs the manifest with
   `sign_data`;
5. checks the signature in software against the certificate, and records
   witness and operator attestations.

Slot 9C must already contain the signing key and certificate, and the YubiKey
needs firmware 5.3 or later, which reports a slot's public key. A YubiKey
attests only keys it generated: a key imported into the slot stops the run at
the attestation, and the error says why.

The transcript's `key_attested` fact records the chain that was built, the
root it reached, the card's claims (origin, PIN and touch policies, firmware)
and each requirement with what the card stated. It never records the card's
serial, which links every ceremony made with the card. A relying party can
repeat the check with the attestation file and Yubico's roots alone:

```sh
openssl verify -CAfile examples/piv/yubico/attestation-roots.pem \
  -untrusted signing_key_attestation.pem \
  -untrusted examples/piv/yubico/attestation-intermediates.pem \
  signing_key_attestation.pem
```

`yubico/` holds Yubico's roots and intermediates as Yubico publishes them
(`developers.yubico.com/PKI`): PIV Root CA Serial 263751, for firmware before
5.7.4, and Attestation Root 1 with its intermediates for later firmware. The
roots are the check's only trust anchors; compare them with Yubico's before a
real ceremony.

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
certificates and a synthetic slot key, and attests its keys under a rehearsal
root whose private keys are in this repository. The run trusts that root
beside Yubico's, and `key_attested` records the anchor as `rehearsal` with
the requirements not exercised. The ceremony completes without a YubiKey, and
nothing it produces is evidence of a real device:

```sh
cargo run -p rite --features piv,yubikey -- run --dry-run --frontend headless \
  examples/piv/yubikey_signing.rite.yaml
```

## `yubikey_key_generation.rite.yaml`: Key generation on the card

Generates a P-256 signing key in slot 9C that needs the PIN before each use and
a touch within 15 seconds of it, has the card attest the key, checks the
attestation against Yubico's roots and the policy the ceremony asked for, and
outputs the public key. The record then shows, on Yubico's word and not the
operator's, that the card generated the key with those policies.

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
