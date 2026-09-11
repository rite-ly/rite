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

A compact signing-key ceremony that demonstrates the `retry:` field. The device
steps carry a per-step retry policy: `generate_keypair` caps retries with
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
Signing names a `backend:` because it needs the private key; verification names
none, because a public key is all a signature check requires. The same step
shape therefore verifies a signature made on a smart card, or one that arrived
from outside the ceremony. Neither step names an algorithm; both derive it from
the key.

The `key` a verification step names can be a keypair, a bare public key, or a
certificate carrying one, in DER or PEM. Adding a `backend:` chooses who runs
the check, for a deployment that requires it inside a validated boundary, and
does not change what the step accepts.

### `wrap_and_unwrap.rite.yaml` — Wrapping a Key for Transport

Wraps one key twice and unwraps it back. `wrapping_key:` names a key the backend
already holds, so the ceremony can undo the wrap itself; `recipient:` names a
public key held by someone else, so only they can open the result. The step
reads one or the other, never both, and `rite check` rejects a step that names
neither.

The escrow wrap declares `expect_recipient:`, so the step refuses a key whose
fingerprint does not match what the ceremony committed to in advance. The
unwrap declares `expect_key:` as an expression over the key that went in, which
makes the step assert the round trip; a restore ceremony would put the origin
ceremony's recorded fingerprint there instead. Neither step names a scheme:
`unwrap_key` reads it from the wrapped artifact, so it cannot disagree with the
bytes being decrypted.

Run it and then `rite verify` on the output directory to see the wrap checks:
each blob is read back and compared against what the transcript says was done
to it. See `docs/key-wrapping.md`.
