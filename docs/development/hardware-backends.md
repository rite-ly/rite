# Hardware backends (PIV / YubiKey)

`rite` can drive PIV smart cards, including YubiKeys, so that signing and
attestation happen on a device the private key never leaves. The support ships
as two opt-in crates and a set of ceremony actions in `rite-stdlib`.

## Crates and features

| Crate          | Provider string | Capabilities                                             |
|----------------|-----------------|----------------------------------------------------------|
| `rite-piv`     | `piv`           | `KeyStore`, `Sign`, `CertStore`, `Piv`                   |
| `rite-yubikey` | `yubikey`       | the above plus `Yubikey` (attestation) and `Attestation` |

Both are pure backends: they depend only on `rite-sdk` and the vendor `yubikey`
crate. The ceremony actions that drive them live in `rite-stdlib` and reach the
device only through the `rite-sdk` capability traits.

Build them in with the matching Cargo features on the `rite` binary:

```sh
cargo build -p rite --features piv,yubikey
```

`yubikey` implies `piv`. Both are **off in the default feature set**: the
`yubikey` crate links the PC/SC system library (`libpcsclite` on Linux; built in
on macOS and Windows), so a plain `cargo build` and the statically linked musl
release artifacts leave them out. CI installs `libpcsclite-dev` for the
`--workspace` lint and test jobs.

The prebuilt distributions enable them where the system can link PC/SC:

| Distribution                                    | Hardware backends             |
|-------------------------------------------------|-------------------------------|
| macOS / Windows release binaries (and Homebrew) | yes (system PC/SC framework)  |
| Docker image (`ghcr.io/rite-ly/rite`, glibc)    | yes (`libpcsclite`)           |
| Linux release tarballs (static musl)            | no (PC/SC cannot static-link) |

So only the static musl Linux tarballs are software-only; everything else ships
the backends. See [`docs/docker.md`](../docker.md) for the image build split.

## Actions

| Action                 | Feature   | Backend capability used                  | Produces      |
|------------------------|-----------|------------------------------------------|---------------|
| `piv_read_certificate` | `piv`     | `CertStoreBackend::read_cert`            | `Certificate` |
| `piv_sign`             | `piv`     | `PivBackend` (PIN) + `SignBackend::sign` | `Bytes`       |
| `yubikey_attest_slot`  | `yubikey` | `YubikeyBackend::attest_slot`            | `Certificate` |

Both certificate-producing actions return a parsed `CertificateDer`, so a
malformed certificate is refused at the step that read it rather than deep
inside a later parser, and both write out as PEM by default.

Neither PIV backend implements `VerifyBackend`. A card signs; a signature check
needs only the public key, so it runs in software or on a backend named for the
purpose. Naming a card on a `verify_signature` step fails when the step runs,
naming the missing capability.

The capability is absent rather than refused, which makes it a static property
`as_verify_mut` exposes. Nothing reads it ahead of time yet: `rite check` sees
only whether an action requires a backend, never whether the named backend can
do the work.

A ceremony selects a backend by provider string:

```yaml
backends:
  token:
    provider: yubikey   # or: piv
```

## Slots

Slot identifiers in ceremony YAML accept the four standard PIV slots (`9a`,
`9c`, `9d`, `9e`), the retired key-management slots by their hex key reference
(`82`..`95`), and any of these with a `piv:` prefix. `rite-sdk`'s `PivSlot`
stores retired slots as a 0-based index (`0..=19`); `rite-piv` converts to and
from the `yubikey` crate's raw key references (`0x82..=0x95`).

## Operations left unimplemented

These return a clear `UnsupportedOperation` error rather than a silent no-op,
because they need the `yubikey` crate's `untested` write paths and are not part
of the initial scope: key import, change PIN, unblock PIN, change management
key, and block PUK.

## Verification

CI cannot touch a physical device, so:

- **Unit tests** cover the pure logic (slot parsing, type conversion, error
  mapping, signing-algorithm parsing) and each action's `execute` against the
  `MockBackend`, using the `ReporterHarness` to assert the produced artifact and
  the emitted `BackendOperation` fact. The `piv_sign` test answers the PIN
  prompt via `ReporterHarness::enqueue_response`. These run in CI behind the
  `piv`/`yubikey` features (`cargo test -p rite-stdlib --features piv,yubikey`).
- **Dry run** (`rite run --dry-run --frontend headless`) substitutes the mock
  backend and walks the whole ceremony, including `piv_sign`, so a rehearsal of
  a pre-provisioned-slot ceremony completes without hardware. The mock holds one
  committed P-256 keypair standing in for the slot: it reports that key in slot
  metadata, reads the certificate carrying it, and signs P-256 slot references
  with it. A signature made during a rehearsal therefore verifies against the
  certificate the rehearsal just read, which is what a ceremony checks. Other
  algorithms have no committed slot key and mint a stand-in on first use, so
  their signatures verify only against the exported stand-in. Attestation
  certificates are synthetic throughout: nothing chains to the Yubico root.
- **Manual hardware check** with a real YubiKey, run before a release that
  touches this code:

  1. Provision a signing key and certificate in slot 9C
     (`ykman piv keys generate`, `ykman piv certificates generate`).
  2. Run `examples/piv/yubikey_signing.rite.yaml` with the device inserted.
  3. Confirm `piv_sign` prompts for the PIN and produces a signature, and that
     `yubikey_attest_slot` emits an attestation certificate that chains to the
     Yubico attestation root.
  4. Cover the full algorithm matrix, not just the example's default: repeat
     `piv_sign` for each supported algorithm (`ECDSA-SHA256`, `ECDSA-SHA384`,
     `RSA-PKCS1-SHA256`, each against a slot provisioned with the matching key
     type) and verify every signature off-card against the slot certificate
     (`openssl dgst -sha256 -verify`). Cargo tests exercise these paths only
     against test doubles; the encoding the card actually accepts (bare digest
     for ECDSA, padded PKCS#1 block for RSA) is proven here or nowhere.
