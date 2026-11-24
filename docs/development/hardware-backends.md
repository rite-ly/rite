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
| `authenticate`         | (none)    | `PivBackend::verify_pin`                 | nothing       |
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
The `yubikey::piv::decrypt_data` function sends this command. The ceremony
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

A ceremony reaches the card's key by declaring it as a held key (see [Keys
provisioned before the ceremony](#keys-provisioned-before-the-ceremony)) and
unlocking the card with `authenticate`. The mock backend performs agreement in
software and does not call `rite_piv::ops::agree`. Unit tests cover the
host-side checks, and the hardware suite under [Verification](#verification)
covers the card.

## Key decryption

Both PIV backends implement `KeyDecryptBackend` for a key encrypted to an
RSA-2048 or RSA-4096 key with RSAES-OAEP-SHA256. The `decrypt_data` action uses it to open
a CMS `ktri` container.

A PIV card does no OAEP. It runs the raw RSA private-key operation through
GENERAL AUTHENTICATE with the ciphertext under tag `0x81`, and returns the
encoded block. The backend removes the OAEP encoding on
the host (`rite-piv/src/oaep.rs`). Signing is the mirror image: the backend
encodes the PKCS#1 v1.5 or PSS block on the host and the card applies the
private key to it. A PSS block (`rite-piv/src/pss.rs`) uses SHA-256 for the
hash and for MGF1, and a 32-byte salt from the operating system, the
parameters `rite-openssl` signs with. The block is the modulus length, so
before an RSA signature the backend reads the slot's key size through GET
METADATA. A card that cannot answer is
taken to hold RSA-2048, the only RSA size standard PIV defines for Rite: a
YubiKey that holds RSA-4096 answers GET METADATA.

Both backends accept RSA-4096, since the `piv` backend also drives
YubiKeys. Generating an RSA-4096 key or decrypting a 512-byte ciphertext on
a card that reports a version older than 5.7 is refused with
`UnsupportedAlgorithm` naming the version, before the card is asked.

- **Slots.** As for key agreement: slot 9D and retired slots `82`..`95`,
  refused elsewhere with `OperationNotPermitted`.
- **Size.** RSA-2048 or RSA-4096. A ciphertext is exactly the modulus
  length, so its length names the size sent to the card: 256 bytes for
  RSA-2048, 512 for RSA-4096. The backend refuses any other length with
  `InvalidData` before sending it to the card. RSA-4096 is a YubiKey
  extension, from firmware 5.7. Rite has no RSA-3072 algorithm, and refuses
  RSA-1024 as too weak.
- **Decoding.** The block holds the content key, so the decoder checks its
  contents without data-dependent branches or early returns, then makes one
  decision on validity. Every OAEP decoding failure returns the same
  `InvalidData` message. Distinguishing failures or content-dependent timing
  can expose an OAEP oracle, as in Manger's attack. See
  [`cryptographic-dependencies.md`](cryptographic-dependencies.md) for why
  this code is written in `rite-piv` rather than taken from a library.
- **Slot contents.** On a card refusal, the backend reads GET METADATA, as for
  key agreement, to name an empty slot, a key that is not RSA, or an RSA key
  of the other size. A refusal under a key of the ciphertext's size is a
  ciphertext the key does not decrypt, and returns the decoding failure's
  `InvalidData`, so the runtime does not offer a retry.

A device that implements OAEP itself, such as a PKCS#11 token with
`CKM_RSA_PKCS_OAEP`, can implement the same trait without host-side decoding.

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

## Entering the PIN

A card refuses a private-key operation until its PIN is entered. The PIN is
declared under `credentials:`, a declaration with no value. An `authenticate`
step reads it as `${credential.<id>}`, asks the person in the step's role for
the PIN and has the card verify it; the steps after it on the same backend use
the unlocked card:

```yaml
credentials:
  card_pin:
    backend: token
    grants: user          # admin | user | unblock
    source: entered       # factory_default | entered | held | on_device

steps:
  unlock:
    action: authenticate
    backend: token
    reads:
      credential: ${credential.card_pin}
    with:
      message: "Enter the PIN of the release signing card"   # optional
  sign:
    action: sign_data
    backend: token
    reads:
      key: ${artifact.signing_key}
      data: ${artifact.manifest}
    creates: signature
```

Rite authenticates with a user credential its holder types (`grants: user`,
`source: entered`), and with a YubiKey's management key (below). The other
values are part of the model and `rite check` refuses them as not supported
yet: the PUK is set with `ykman` before the ceremony (see
[Preparing a YubiKey](../yubikey.md)). A credential of another backend than the
step's is an error.

The step reads the card's retry count first, warns at one try left, and
asks again for a PIN outside 6 to 8 bytes before sending it, so a slip costs no
try.
A wrong PIN fails the attempt with the tries left, and the operator may retry;
a blocked PIN stops the run. The transcript records an `authenticate` backend
operation with the credential, what it grants, its source and the tries left
before entry, never the PIN or its length.

The card stays unlocked until the run ends, the card is reset or removed, or
another program selects an application on it (the PC/SC connection is
shared). A slot whose PIN policy is `always` clears it after each use: slot
9C defaults to `always` on a YubiKey, so a ceremony signing twice with it
enters the PIN before each signature. Rite does not keep the PIN to replay
it, which would undo that policy. A step that meets a locked card fails with
`PinRequired`, and the operator is told where the `authenticate` step belongs;
retrying does not ask for the PIN.

`rite check` warns when a step uses the private half of a key on a `piv` or
`yubikey` backend, held before the run or made on it, with no `authenticate` on
it earlier (except in slot 9E, which needs no PIN by default), and when a key
in slot 9C is used again with no `authenticate` since its last use. The slot is
the key id of a held key, or the `slot` of the `generate_key` step that made
it (9A when absent). Warnings, not errors: a held key's policy may differ from
its slot's default, and it is not known before the card is read. An
`authenticate` on an `openssl` backend is an error.

## Authenticating with the management key

A card generates a key only in an admin session. An `authenticate` step opens
one with a credential that has `grants: admin`, on a `yubikey` backend (`rite
check` refuses one on a `piv` backend). Its `source` is `factory_default`, `held`
(the step reads the key from an artifact as `value`), or
`protected_by: ${credential.<id>}` naming a user credential of the same backend.
A protected key is stored on the card behind the PIN: the step asks for that
PIN, records it as its own `authenticate` operation, then reads the key from
the card and leaves both sessions open.

The card's metadata gives the key's algorithm, so a 24-byte key is AES-192 or
3DES as the card has it, not as its length suggests. The `authenticate`
operation records the algorithm and whether the card reports the key as still
the default (firmware 5.3 and later), never the key. A refused key fails with
`ManagementKeyRequired`.

`rite check` refuses a `generate_key` on a `yubikey` backend with no admin
`authenticate` earlier on it, naming the backend's admin credential when the
ceremony declares one; any `generate_key` on a `piv` backend; a held credential without `value`, or `value` for
any other; and a protected credential whose `protected_by` does not name a
user credential of its backend. An admin `authenticate` unlocks no key, unless
it was protected by the PIN.

## Operations left unimplemented

These return a clear `UnsupportedOperation` error rather than a silent no-op:
key import, change PIN, unblock PIN, change management key, and block PUK.
Each operation still needs implementation and hardware testing.

## Verification

CI cannot touch a physical device, so:

- **Unit tests** cover the pure logic (slot parsing, type conversion, error
  mapping, PKCS#1 and PSS encoding, and OAEP decoding against OpenSSL) and each action's `execute` against the
  `MockBackend`, using the `ReporterHarness` to assert the produced artifact and
  the emitted `BackendOperation` fact. The `authenticate` tests answer the PIN
  prompt via `ReporterHarness::enqueue_response`. These run in CI behind the
  `piv`/`yubikey` features (`cargo test -p rite-stdlib --features piv,yubikey`).
- **Dry run** (`rite run --dry-run --frontend headless`) substitutes the mock
  backend and walks the whole ceremony, including the PIN step, so a rehearsal of
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
  signing, agreeing, and decrypting with the declared id all reach the stand-in, which
  permits every usage, as a slot does. The mock accepts any PIN, reports three
  tries, and models no PIN policy, so a rehearsal never stops at `PinRequired`;
  the `rite check` warning above is what catches a missing `authenticate`.
  It accepts any management key and reports it as AES-192, the default only
  when the step presents the factory key; `rite check` catches a missing admin
  session.
- **Hardware suite** (`crates/rite/tests/hardware_yubikey.rs`), run by hand
  on a YubiKey kept for testing, since it resets the PIV application,
  provisions its own keys in 9A, 9C, 9D and 82 to 84 (83 is RSA-4096, so
  it needs firmware 5.7 or later), and generates keys in 85 to 87:

  ```sh
  RITE_HW_YUBIKEY_SERIAL=<serial> cargo test -p rite --features piv,yubikey \
      --test hardware_yubikey -- --ignored --test-threads=1
  ```

  It needs `ykman`, and does nothing unless the inserted YubiKey is the one
  named. It covers `authenticate`, signing with keys the card held (RSA-2048,
  RSA-4096 and P-384, each checked by OpenSSL against the key `ykman`
  exported, and RSA-PSS under both RSA sizes), opening what was sealed to 9D (P-384, by agreement), 82
  (RSA-2048, by decryption) and 83 (RSA-4096, by decryption), slot 9C
  needing the PIN before each signature, an RSA key with PIN policy
  `always` in 84 signing after one `authenticate`, a wrong PIN retried,
  pinned fingerprints, a refused management key, and a key generated after
  the management key from each source: factory default, held (typed in hex),
  and protected by the PIN, which the test stores with `ykman --protect` and
  resets afterwards.
  Unplugging the card mid-run and the attestation chain stay manual, below.
- **Manual hardware check** with a real YubiKey, run before a release that
  touches this code:

  1. Provision a signing key and certificate in slot 9C
     (`ykman piv keys generate`, `ykman piv certificates generate`).
  2. Run `examples/piv/yubikey_signing.rite.yaml` with the device inserted.
  3. Confirm `authenticate` prompts for the PIN, `sign_data` produces a
     signature that `check_signature` accepts, and `yubikey_attest_slot` emits
     an attestation certificate that chains to the Yubico attestation root.
  4. Cover the full algorithm matrix, not just the example's default: repeat
     `sign_data` for each supported algorithm (`ECDSA-SHA256`, `ECDSA-SHA384`,
     `RSA-PKCS1-SHA256`, `RSA-PSS-SHA256`, each against a slot provisioned with the matching key
     type, RSA under both RSA-2048 and RSA-4096) and verify every signature off-card against the slot certificate
     (`openssl dgst -sha256 -verify`, adding `-sigopt rsa_padding_mode:pss
     -sigopt rsa_pss_saltlen:32` for PSS). Cargo tests exercise these paths only
     against test doubles; the encoding the card actually accepts (bare digest
     for ECDSA, padded PKCS#1 or PSS block for RSA) is proven here or nowhere.
  5. Test key agreement as described in [Key agreement](#key-agreement):
     provision an EC key and certificate in slot 9D, encrypt content to the
     certificate with `openssl cms -encrypt` using an ECDH recipient, then open
     it with `decrypt_data` and compare the content. Repeat with P-256 and
     P-384.
  6. Test key decryption as described in [Key decryption](#key-decryption):
     provision an RSA-2048 key and certificate in slot 9D, encrypt content to
     the certificate with `openssl cms -encrypt -keyid -keyopt
     rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt
     rsa_mgf1_md:sha256`, then open it with `decrypt_data` and compare the
     content. Repeat with RSA-2048 and RSA-4096.
