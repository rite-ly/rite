# Showcase Ceremonies

These examples demonstrate Rite's authoring features and actions. They run with
the OpenSSL backend and the files included here, with no external setup.
Comments in the YAML explain the choices an author makes in each step.

> These are examples, not production ceremonies. Names, keys, and procedures are
> illustrative; review and adapt every detail before using Rite for real work.

## Ceremonies

### `demo.rite.yaml`

A compact root-key ceremony: environment check, RSA-4096 key generation,
self-signed certificate issuance, public-key export, and witness attestation.

### `offline_backup.rite.yaml`

The longest printed-script example, and the only one here with acts,
prerequisites, physical materials, and post-ceremony duties. Use it to see how a
dense, formal ceremony renders across pages. Its steps are illustrative, not a
recommended operational policy.

### `retry_guards.rite.yaml`

Per-step retry policies on signing-key operations: `retry: { attempts: 3 }`
caps retries, `retry: never` forbids them, and a step without the field
prompts on a transient failure. See [the retry model](../../docs/error-handling.md).

### `dice.rite.yaml`

A participant mixes physical dice rolls into the ceremony seed, and a
certificate serial is drawn from that seed. `rite verify` re-derives the seed,
the dice contribution, and the serial from the transcript.

### `sign_and_verify.rite.yaml`

Signs a release manifest with `sign_data` and checks it with
`verify_signature`. Signing names a backend because it needs the private key;
verification needs only a public key, so the same step checks a signature made
on a smart card or one that arrived from outside the ceremony. The key can be a
keypair, a public key, or a certificate, in DER or PEM.

### `import_key.rite.yaml`

Imports two keys made elsewhere with `import_key`: a 32-byte AES key component
carried in by a custodian, and an encrypted PEM private key opened with a
passphrase typed at an `enter_secret` step. `algorithm` is required, because
raw bytes do not say what they are; `expect_key` checks the imported key
against its paperwork, so a swapped component fails the step. An `enter_value`
step records the media serial.

The fixture passphrase is `placeholder-secret`, which is what a dry run types
for a secret. `rite verify` reports the wrap as `addressed to a key imported
into this ceremony`, a weaker claim than a generated key earns. See
[typed entry](../../docs/typed-entry.md) and
[key wrapping](../../docs/key-wrapping.md).

### `wrap_and_unwrap.rite.yaml`

Wraps one key twice and unwraps it back. `wrapping_key` names a key the backend
holds, so the ceremony can undo the wrap; `recipient` names a public key held
by someone else, so only they can open the result. The escrow wrap pins its
recipient with `expect_recipient`, and the unwrap asserts the round trip with
`expect_key`. The ceremony also wraps and recovers an AES-256 KEK, the way a
KEK is carried to a second HSM, identified by its `cmac-aes:` check value.

Run `rite verify` on the output directory to see each wrapped blob read back
and compared against the transcript. See [key wrapping](../../docs/key-wrapping.md).

### `encrypt_and_decrypt.rite.yaml`

Encrypts a sample runbook with `encrypt_data`, decrypts it with
`decrypt_data`, and compares the result. These are separate from `wrap_key`
and `unwrap_key` because the claim differs: a wrap says a key left a backend
under protection, while encrypted content says only that the bytes are
unreadable without the key. `rite verify` lists the container under
`Containers`. See [content encryption](../../docs/encrypting-content.md).

### `split_and_combine.rite.yaml`

Splits a sample secret into three shares, any two of which recover it, reveals
share 3 for its custodian to copy, recovers the secret from two shares, and
compares the result. `rite script` prints the worksheet for the `reveal` step.
Shares from different splits combine into a wrong secret without an error,
which is why a recovery ends by checking what came back. See
[secret sharing](../../docs/secret-sharing.md).

### `recover_from_paper.rite.yaml`

Two custodians type their shares back from paper, and the recovered secret is
checked against a digest recorded at the split. `enter_share` checks each row
as it is typed: a wrong character is corrected and named, an unreadable one
typed as `?` is recovered, and a row that needs more is typed again. The sheets
are in `test_data/recovery_sheets.txt`; try changing a character in one. This
example needs a person at the keyboard; `rite run --dry-run` stops at the first
share.

### `recovery_phrase.rite.yaml`

A hardware wallet's 24-word recovery phrase is entered, split two of three,
recovered from two shares, and shown again as words to enter on a spare
device. `enter_secret` with `format: bip39` checks each word against the BIP-39
English list and the last word's checksum, and keeps the 32 bytes of entropy
the words encode, so each share is two rows of paper32 rather than ten.
`reveal` with `format: bip39` shows the recovered entropy as numbered words,
and `rite script` prints a 24-row sheet for it. A dry run enters the all-zero
phrase (`abandon` 23 times, then `art`). See
[typed entry](../../docs/typed-entry.md).

## Run an example

From the repository root:

```sh
cargo run -p rite -- check examples/showcase/demo.rite.yaml
cargo run -p rite -- script examples/showcase/demo.rite.yaml
cargo run -p rite -- run --dry-run examples/showcase/demo.rite.yaml
```

Replace `demo.rite.yaml` with another ceremony. A dry run uses mock backends;
it is a rehearsal, not evidence of a real ceremony.
