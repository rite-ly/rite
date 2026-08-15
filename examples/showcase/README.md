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

A deliberately maximalist ceremony spanning four acts, four roles, physical and
digital materials, and long structured step instructions. It generates a
backup-wrapping key, escrows it under the bundled test key, and hands sealed media
to a custodian. Use it to see how a dense, formal script renders across pages.

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
The contrast between the two steps is the point: signing names a `backend:`
because it needs the private key, while verification names none, because a
public key is all a signature check requires. That is what lets the same step
shape verify a signature made on a smart card, or one that arrived from outside
the ceremony. Neither step names an algorithm; both derive it from the key.

The `key` a verification step names can be a keypair, a bare public key, or a
certificate carrying one. That last form is what makes the smart-card case work
in practice, since `piv_read_certificate` yields a certificate rather than a
bare key.
