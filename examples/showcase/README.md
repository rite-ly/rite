# Showcase Ceremonies

These ceremonies exist to **demonstrate Rite's features**: roles and abbreviations,
acts and sections, prerequisites, physical and digital materials, structured
step instructions (paragraphs and bullet lists), generated outputs, and
post-ceremony duties. They render well as printed scripts and run end to end with
the OpenSSL backend.

> **Not real ceremonies.** The roles, names, parameters, and key material here are
> illustrative. Do not copy these as-is for an actual key ceremony.

All ceremonies in this directory are runnable with no external setup.

## Ceremonies

### `demo.rite.yaml` — Demo: Root Signing Key Ceremony

A compact, single-page ceremony: environment check, RSA-4096 keypair generation,
self-signed certificate issuance, public-key export, and witness attestation. This
is the ceremony used in the project demo recording.

### `offline_backup.rite.yaml` — Offline Backup Key Ceremony

The structure and rendering showcase, and the only ceremony here that uses acts,
prerequisites, physical materials, and post-ceremony duties. Deliberately
maximalist: four acts, four roles, and long step instructions built from
paragraphs and bullet lists. Use it to see how a dense, formal script renders
across pages. It escrows a key along the way, but `wrap_and_unwrap.rite.yaml` is
where wrapping itself is explained.

### `retry_guards.rite.yaml` — Signing Key Ceremony with Retry Guards

A compact signing-key ceremony that demonstrates the `retry` field. The device
steps carry a per-step retry policy: `generate_key` caps retries with
`retry: { attempts: 3 }`, certificate issuance forbids them with `retry: never`,
and the CSR step omits the field to show the prompt-on-transient-failure default.
It runs end to end on OpenSSL but reads as a template you could retarget to a
hardware backend. See `docs/error-handling.md` for the retry model.

### `dice.rite.yaml` — Dice Entropy Ceremony

Demonstrates verifiable ceremony randomness: a participant folds a physical dice
roll into the run seed with `gather_entropy`, then a certificate is issued whose
serial number is drawn from that seed. `rite verify` later re-derives the seed,
the dice contribution, and the serial from the transcript alone.

### `sign_and_verify.rite.yaml` — Detached Signature over a Release Manifest

Signs a document with `sign_data` and checks it back with `verify_signature`.
Signing names a `backend` because it needs the private key; verification names
none, because a public key is all a signature check requires. The same step
shape therefore verifies a signature made on a smart card, or one that arrived
from outside the ceremony. Neither step names an algorithm; both derive it from
the key.

The `key` a verification step names can be a keypair, a bare public key, or a
certificate carrying one, in DER or PEM. Adding a `backend` chooses who runs
the check, for a deployment that requires it inside a validated boundary, and
does not change what the step accepts.

### `import_key.rite.yaml` — Importing a Transport Key

Takes a key-encryption key that was produced somewhere else, installs it with
`import_key`, and uses it to wrap a key generated in the room. The component
arrives as a material, thirty-two raw bytes on the media a custodian carried
in, which is the case the payments world calls key component entry.

`algorithm` is required, because raw material says nothing about itself and a
secret's bytes look like any others of the same length. `expect_key` is
optional and given here, checked against what the backend computed after the
import, so a component swapped on the way in fails the step rather than
becoming a key the ceremony trusts.

`rite verify` reports the wrap as `addressed to a key imported into this
ceremony`, which is a weaker claim than the one a generated key earns and is
stated rather than left out. See `docs/key-wrapping.md`.

### `wrap_and_unwrap.rite.yaml` — Wrapping a Key for Transport

Wraps one key twice and unwraps it back. `wrapping_key` names a key the backend
already holds, so the ceremony can undo the wrap itself; `recipient` names a
public key held by someone else, so only they can open the result. The step
reads one or the other, never both, and `rite check` rejects a step that names
neither.

The escrow wrap declares `expect_recipient`, so the step refuses a key whose
fingerprint does not match what the ceremony committed to in advance. The
unwrap declares `expect_key` as an expression over the key that went in, which
makes the step assert the round trip; a restore ceremony would put the origin
ceremony's recorded fingerprint there instead. No step names a scheme:
`unwrap_key` reads it from the wrapped artifact, so it cannot disagree with the
bytes being decrypted.

The ceremony also wraps its symmetric key-encryption key and recovers it, which
is what carrying a KEK to a second HSM looks like. That unwrap declares
`algorithm: AES-256`, because nothing travels with a wrapped key saying what it
is and a secret's bytes look like any others of the same length, and its
`expect_key` is a `cmac-aes:` check value rather than a fingerprint, since a
symmetric key has no public half to fingerprint.

Run it and then `rite verify` on the output directory to see the wrap checks:
each blob is read back and compared against what the transcript says was done
to it. See `docs/key-wrapping.md`.

### `encrypt_and_decrypt.rite.yaml` — Sealing a Runbook and Proving It Opens

Encrypts a document under a key generated in the room, then opens it again and
compares it against what went in. `encrypt_data` and `decrypt_data` are to
content what `wrap_key` and `unwrap_key` are to keys, and they are separate
verbs because they make a different claim: a wrap says a key left a backend
under protection, while encrypted content says only that these bytes are
unreadable without the key they are addressed to.

The archive key never encrypts the document. `encrypt_data` has the backend
produce a fresh content-encryption key per message and protect that, which is
the only shape a key-protection device offers and the reason the same ceremony
works when the key moves to an HSM.

Nothing is declared on the way back. The container carries the algorithms, and
the step checks that it is addressed to the key it was given before decrypting,
so a wrong key fails by name. What comes out is read like any byte artifact,
which is why the drill can compare it against the document that went in. It is
held wiped in memory and, since no output names it, never written out.

`rite verify` reports the seal beside any wraps, under `Containers`. See
`docs/encrypting-content.md`.

### `split_and_combine.rite.yaml` — Splitting a Secret and Putting It Back

Splits a secret into three shares of which any two recover it, recovers it
from two, and compares the result against what went in. `split_secret` checks
every pair of shares before the step completes, so a share that leaves the
room has been shown to work. `combine_shares` takes its shares as a list, in
any order; each share knows how many are needed, so too few is refused.

What a share cannot tell is whether it belongs with the others: shares from
two different splits give a wrong secret without complaint, which is why a
recovery ends by checking what came back. This example has the original in
hand; a real recovery checks something derived from the secret instead.

Shares and the recovered secret stay in memory and are never written to a
file. The transcript names the scheme, the threshold and which shares went
into the recovery, and nothing about the secret itself.
