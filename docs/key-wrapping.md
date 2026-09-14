# Key wrapping

`wrap_key` encrypts a private key so it can leave the machine that holds it.
`unwrap_key` decrypts one and imports it into a backend. Both are about
custody: who ends up able to use the key.

## The two paths

The input a step reads selects the path, and the choice is visible in the
ceremony definition and in the transcript.

```yaml
# Under a key this backend holds. The ceremony keeps the means to unwrap.
wrap_for_restore:
  action: wrap_key
  backend: openssl
  reads:
    key_to_wrap: ${artifact.root_ca_keypair}
    wrapping_key: ${artifact.kek}
  creates: wrapped_root_ca_key

# To a public key held elsewhere. Only its holder can open the result.
escrow_to_custodian:
  action: wrap_key
  backend: openssl
  reads:
    key_to_wrap: ${artifact.root_ca_keypair}
    recipient: ${artifact.escrow_pubkey}
  with:
    expect_recipient: ${param.escrow_fingerprint}
  creates: wrapped_root_ca_key
```

Naming neither input, or both, is a `rite check` error: the path would be
undetermined.

## Declaring the recipient

`expect_recipient:` is the SHA-256 of the recipient public key's SPKI DER, as
`sha256:<64 hex digits>`, obtained out of band. The step refuses to run if the
key it is given does not match.

Without it, the transcript records whatever key was present, and nothing in
the ceremony corroborates that it belongs to the intended recipient. A key
wrapped to the wrong recipient cannot be unwrapped again, so the check has no
useful retry: the step fails and the run stops.

`unwrap_key` takes `expect_key:` the same way, against the key that comes out.
It is usually the fingerprint the origin ceremony's `generate_key` step
recorded.

## Choosing a scheme

`scheme:` names the container. It defaults to `CMS-AES-256-GCM` and most
ceremonies should leave it alone.

| Scheme | Output | Reach for it when |
|---|---|---|
| `CMS-AES-256-GCM` | CMS `AuthEnvelopedData` DER | the blob is archived, or the recipient reads CMS. Works for a public-key recipient and for a symmetric wrapping key alike. The default. |
| `RSA-AES-KEY-WRAP-SHA256` | raw bytes | the blob is imported by a cloud KMS or another HSM. |
| `RSA-OAEP-SHA256` | raw bytes | a small payload, to a recipient that accepts bare RSA-OAEP. |
| `AES-128-KWP`, `AES-256-KWP` | raw bytes | a symmetric wrapping key, where the recipient requires exactly RFC 5649 bytes. |
| `AES-128-KW`, `AES-256-KW` | raw bytes | the same, for RFC 3394. |

The choice is about where the blob is going, not about strength. What happens
*inside* a scheme is never an author's choice. It follows the recipient key.

`RSA-OAEP-SHA256` carries at most `k - 2*hLen - 2` bytes: 190 under RSA-2048
and 446 under RSA-4096. That fits a symmetric key or an EC private key and
never fits an RSA one, so the step refuses an over-size pair with a message
naming the ceiling. `RSA-AES-KEY-WRAP-SHA256` exists for exactly that reason
and has no ceiling: it puts an ephemeral AES key under RSA-OAEP and the payload
under AES-KWP, which is the shape every cloud KMS import expects.

The two RSA schemes need an RSA recipient. The wrapped key is always PKCS#8
`PrivateKeyInfo`, which is what PKCS#11 specifies and what KMS import accepts.

## Wrapping under a symmetric key

`generate_key` produces an AES key when `algorithm:` names one, and that
key can only be a wrapping key: it has no public half, so it never appears as
`recipient:`.

```yaml
make_kek:
  action: generate_key
  backend: hsm
  with:
    algorithm: AES-256
  creates: kek

wrap_under_kek:
  action: wrap_key
  backend: hsm
  reads:
    key_to_wrap: ${artifact.ca_key}
    wrapping_key: ${artifact.kek}
  creates: wrapped_ca_key
```

No `scheme:` there, because the default CMS container takes a symmetric key
too. The recipient becomes a `KEKRecipientInfo` (RFC 5652 §6.2.3) naming the
key both sides hold, with the content-encryption key under `id-aes256-wrap`
and the content under AES-256-GCM. Everything else about the blob is what the
public-key paths produce, and `openssl cms -decrypt -secretkey <hex>
-secretkeyid <kcv>` opens it.

Prefer that. It is the only symmetric option whose artifact carries its own
algorithm identifiers, so `rite verify` re-derives them and reports the wrap
as checked rather than as recorded. A CMS wrap needs a 256-bit key, since the
key-encryption algorithm is fixed at `id-aes256-wrap`.

The raw mechanisms are for a recipient that requires exactly those bytes, such
as an HSM or cloud KMS import path:

```yaml
  with:
    scheme: AES-256-KWP
```

They name the KEK size because the RFC 3394 and RFC 5649 object identifiers
are per-size and the output carries neither, so a ceremony that means a
256-bit KEK says so and a 128-bit one is refused rather than wrapped under in
silence. Prefer `KWP` (RFC 5649) over `KW` (RFC 3394): `KW` carries only a
payload that is a multiple of 8 bytes and at least 16, which a PKCS#8 private
key is not.

A symmetric key is recorded by a key check value rather than by a fingerprint:
AES-CMAC over a zero block, leftmost three bytes, as `cmac-aes:763cbc`. It is
the value an HSM displays, so the transcript records what the room checked,
and a ceremony reads it back with `${artifact.kek.kcv | hex}`.

That value is also what a CMS wrap puts in `kekid.keyIdentifier`, so the blob
names which key it is for and `rite verify` matches it against the step that
generated the key, without either side holding it.

## Recovering a key

Nothing travels with a wrapped key saying what it is. A 32-byte secret and any
other 32 bytes are the same bytes, so the receiving ceremony declares what it
is restoring, the way it already declares `policy:`:

```yaml
  - id: restore_kek
    action: unwrap_key
    backend: openssl
    reads:
      unwrapping_key: ${artifact.transport_key}
      wrapped_data: ${artifact.wrapped_kek}
    with:
      algorithm: AES-256
      expect_key: cmac-aes:763cbc
      label: restored-kek
```

`algorithm:` is required to recover a symmetric key. It is optional for a
keypair, which names itself once its DER parses, and checked against what came
out when given, so a declaration that disagrees with the blob fails the step
rather than importing something the ceremony did not mean to restore. Without
it a recovered secret is refused by name rather than failing inside OpenSSL.

`expect_key:` names the key the same way the transcript does: a `sha256:`
fingerprint for a keypair, a `cmac-aes:` check value for a symmetric key.

The declared algorithm also picks the default `policy:` usages, sign and verify
for a keypair and wrap and unwrap for a symmetric key, exactly as at generation.
`extractable` defaults to true either way, because the backend has just held the
key in the clear and claiming otherwise would be a claim the run cannot support.

## What the transcript records

For a CMS wrap, the ceremony does not select the algorithms. Which
encapsulation the scheme takes follows the recipient key: an RSA recipient
takes key transport, an EC recipient takes the RFC 5753 key-agreement path, an
ML-KEM recipient takes the RFC 9629 `KEMRecipientInfo` path. So the wrap fact
records what the produced artifact says was done, read back out of its DER: the
`RecipientInfo` variant and every algorithm identifier the structure names,
under `wrap`.

A raw mechanism has nothing to read back. Its output is bare ciphertext with no
algorithm identifiers in it, so the recorded algorithms are what the backend
invoked rather than something re-derived, and the record is weaker by exactly
that much. The scheme name is what tells a verifier which of the two it has.

Three fingerprints tie the record together: the key that went in, the recipient
it went to (its own fact), and, on unwrap, the key that came out.

## What `rite verify` checks, and what it cannot

Pointed at a run directory, `rite verify` reads each wrapped artifact and
compares it against the transcript:

- the recorded algorithms against the ones in the DER;
- the recipient the blob names against the recipient the transcript recorded;
- the key a wrap consumed against a key generated in the same ceremony.

A wrap whose artifact is not in the directory is reported as unchecked, not as
verified.

A raw-mechanism wrap is reported as `recorded`, which is neither of those. The
first two checks have nothing to run against, so the line states that the
algorithms are as invoked rather than re-derived. It cannot be mistaken either
for a checked wrap or for a CMS blob that failed to parse. The third check still
holds, because it compares two transcript facts and never touches the blob.

Two things remain outside the reach of the bundle, and no output should be read
as covering them: that the recipient can open the result, and that the
recipient is who the ceremony believed. Both are human assumptions. Give them
human evidence: an attestation step naming the fingerprint, and a
`expect_recipient:` value that came from somewhere other than the key itself.

## Post-quantum recipients

An ML-KEM-768 key can be a recipient wherever an RSA or EC key can, with no
change to the step. It is worth reaching for when the wrapped blob will be
archived: a signature only has to hold while it is trusted, but a wrapped key
copied off the media today can be kept until there is something to open it
with. `examples/pki/root_ca_post_quantum.rite.yaml` does this.

Not every key type can receive a wrap. Ed25519 and ML-DSA sign and do not
encapsulate, so wrapping to one is refused with a message saying so rather than
an error from inside OpenSSL.

ML-KEM needs OpenSSL 3.5 or newer. Where the ceremony generates the key,
`rite check` warns and `rite run` refuses before the ceremony starts. Where the
recipient arrives as a public key from outside, its algorithm is not known
until the step runs, so an older build fails there instead.

## Software backends export the key

Both paths ask the backend for the target key in DER before encrypting it, so
the OpenSSL backend has the plaintext private key in process memory. That suits
software keys. A key generated inside a hardware boundary and marked
non-extractable cannot be wrapped this way at all; moving one runs through the
vendor's own cloning or backup procedure.

## The key has to be allowed to leave

Both wrap paths ask the backend for the target key, so a key that may not leave
cannot be wrapped. What a key may do is declared where it is generated:

```yaml
generate_backup_key:
  action: generate_key
  backend: openssl
  with:
    algorithm: ECDSA-P256
    policy:
      extractable: true        # required before any wrap_key step
      usages: [sign, verify]   # PKCS#11 vocabulary, not the X.509 profile
  creates: backup_keypair
```

The default policy is the restrictive one: a persistent, sensitive,
non-extractable key that may sign and verify. A ceremony that wraps a key it
generated has to say `extractable: true`, and a key used as a local
`wrapping_key:` needs `usages: [wrap, unwrap]`. Omitting either is refused
before the wrap, with a message naming the step to change.

These are PKCS#11 attributes: what the token permits. They are a different
thing from the X.509 `KeyUsage` extension in a certificate, which comes from
`profile:` on `issue_certificate`. `key_usage:` is not a parameter of
`generate_key`, and naming it fails the check like any other key the action
does not have.

Which of them bite depends on who holds the key. A token enforces the whole
policy itself, because each field is an attribute the key is created with. The
software backend has no token, so it enforces the two that describe operations
it performs: `extractable` gates both wrap paths, and `usages` gates signing,
wrapping, and unwrapping. `persistent`, `sensitive`, and `wrap_with_trusted_only`
describe a token that is not there, so in software they are recorded in the
transcript and nothing more.

`unwrap_key` takes the same `policy:` block for the key it recovers. Nothing
travels with a wrapped key that says what it may do, so the receiving ceremony
declares it: without one the key may sign, verify, and be wrapped again, and a
key restored to serve as a `wrapping_key:` has to say `usages: [wrap, unwrap]`.

A backend that cannot honour a policy must refuse it rather than ignore it. A
PIV key, for instance, is non-extractable by hardware design, so asking for
`extractable: true` there is an error rather than a silent downgrade.
