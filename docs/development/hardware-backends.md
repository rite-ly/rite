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
| Linux `-glibc` release tarballs (glibc 2.36+)   | yes (`libpcsclite`)           |
| Docker image (`ghcr.io/rite-ly/rite`, glibc)    | yes (`libpcsclite`)           |
| Rite Live (`rite-live-*-<arch>.img.xz`)         | yes (`libpcsclite`, `pcscd`)  |
| Linux release tarballs (static musl)            | no (PC/SC cannot static-link) |

On supported platforms, only the static musl Linux tarballs are software-only;
Intel macOS is not supported. See [`docs/docker.md`](../docker.md) for the image
build split.

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

## Key agreement

Both PIV backends implement `KeyAgreementBackend` for ECDH on P-256 and
P-384, using GENERAL AUTHENTICATE with the peer's point under tag `0x85`.
The `yubikey::piv::decrypt_data` function sends this command and is gated by
the crate's `untested` feature, which `rite-piv` enables. The ceremony
`decrypt_data` action uses key agreement to open a CMS `kari` container.

- **Slots.** Agreement is permitted in slot 9D and retired key-management slots
  `82`..`95`. PIV keys have no usage attribute, so the slot determines their
  use. The backend refuses slots 9A, 9C, and 9E with
  `OperationNotPermitted`. Slot 9E requires no PIN, so anyone holding the card
  could use its key for agreement.
- **Peer key.** The container supplies the ephemeral public key. Before sending
  it to the card, the backend checks that it is on P-256 or P-384 and that its
  point lies on that curve. An invalid point returns `InvalidData`. See
  [`cryptographic-dependencies.md`](cryptographic-dependencies.md) for why
  this check belongs in the hardware backend.
- **Curve and slot contents.** The peer's curve selects the card algorithm.
  The card refuses an algorithm that does not match its key, so a mismatch
  computes nothing. A card refusal triggers a GET METADATA request, when
  supported, to identify the slot's key. YubiKey firmware 5.2.3 and later
  supports this request. Without it, the backend cannot distinguish an empty
  slot from an incompatible key.
- **Secret length.** The backend accepts a shared secret only at the full field
  length: 32 bytes for P-256 or 48 bytes for P-384.

No ceremony can reach agreement on hardware yet: the `decrypt_data` action
takes its key as a `BackendKey` artifact, which a slot provisioned beforehand
does not have, and it does not prompt for the PIN required by slot 9D's
default policy. The mock backend performs agreement in software and does not
call `rite_piv::ops::agree`. Unit tests cover host-side checks; the manual
check below describes the hardware test.

A ceremony selects a backend by its provider:

```yaml
backends:
  token:
    provider: yubikey   # or: piv
```

The providers are a closed list, `rite_sdk::Provider`: `rite check` refuses a
name outside it. Whether this build carries one is asked by `rite run`, which
refuses before the first step a provider compiled out of the build. A dry run
only warns, since it swaps in the mock and can rehearse a hardware ceremony on
a build without the hardware. A new provider is a variant there, an arm in
`create_backend` and in `is_built` (`rite-stdlib/src/backend/mod.rs`); the
compiler points at both.

## Slots

Slot identifiers in ceremony YAML accept the four standard PIV slots (`9a`,
`9c`, `9d`, `9e`), the retired key-management slots by their hex key reference
(`82`..`95`), and any of these with a `piv:` prefix. `rite-sdk`'s `PivSlot`
stores retired slots as a 0-based index (`0..=19`); `rite-piv` converts to and
from the `yubikey` crate's raw key references (`0x82..=0x95`).

## Keys provisioned before the ceremony

A key already in a slot is a material of type `backend_key`:

```yaml
materials:
  decryption_key:
    type: backend_key
    backend: token
    id: "piv:9d"
    algorithm: ECDSA-P256
    fingerprint: "sha256:..."   # optional
```

`id` and `algorithm` are required: there is no default slot, and the
algorithm is a claim checked against the card. `fingerprint` pins the public
key and is optional, since a template cannot know it. The material is an
artifact like a generated key, so `sign_data`, `decrypt_data` and every other
action that reads a key take it unchanged.

Nothing is read when the run starts, so the card need only be inserted by the
first step that names the key in its `reads:`. That step asks the backend for
the slot's public key, checks the algorithm and any pinned fingerprint, and
records a public `key_bound` fact (see `docs/transcript-format.md`). An empty
slot, or a key that is not the declared one, fails the attempt with
`KeyNotFound`, which the operator can retry after inserting the right card. A
key referenced only from a `with:` expression is not bound by it; name it in
`reads:`.

`rite check` refuses a held key on an undeclared backend, and a step that
uses its private half on another backend. A step that uses only its public
half (the `recipient` of `encrypt_data` or `wrap_key`, or any input of
`verify_signature`) may run on any backend; the binding still reads the key
from its own.

No step verifies the PIN yet, outside `piv_sign`, so on a real card a step
using a slot whose PIN policy requires it fails with `PinRequired`.

## Operations left unimplemented

These return a clear `UnsupportedOperation` error rather than a silent no-op:
key import, change PIN, unblock PIN, change management key, and block PUK.
The `yubikey` crate gates them behind its `untested` feature, which `rite-piv`
enables for key agreement. Each operation still needs implementation and
hardware testing.

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
  For each `backend_key` material, `rite run` gives the mock a `held_keys`
  config naming the id and algorithm, and the mock stands in for the key from
  the start: the slot key for P-256, a fresh key otherwise. Reading,
  signing with and agreeing with the declared id all reach the stand-in, which
  permits every usage, as a slot does.
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
  5. Test key agreement as described in [Key agreement](#key-agreement):
     provision an EC key and certificate in slot 9D, encrypt content to the
     certificate with `openssl cms -encrypt` using an ECDH recipient, then open
     it with `decrypt_data` and compare the content. Repeat with P-256 and
     P-384.
