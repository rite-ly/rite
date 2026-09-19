# Encrypting content

`encrypt_data` encrypts bytes so they can sit on media nobody guards.
`decrypt_data` opens them again. Neither is about custody of a key, which is
what separates them from `wrap_key` and `unwrap_key` in
[key-wrapping.md](key-wrapping.md).

The two pairs write the same container. What differs is the claim: a wrap says
a key left a backend under protection, and the transcript's custody language
follows from that. Encrypted content says only that these bytes are unreadable
without the key they are addressed to.

```yaml
seal_the_runbook:
  action: encrypt_data
  backend: openssl
  reads:
    data: ${artifact.runbook}
    encryption_key: ${artifact.archive_key}
  creates: sealed_runbook

open_the_sealed_runbook:
  action: decrypt_data
  backend: openssl
  reads:
    encrypted_data: ${artifact.sealed_runbook}
    decryption_key: ${artifact.archive_key}
  creates: recovered_runbook
```

`data` is any artifact that resolves to bytes: a material carried into the
room, a document an earlier step produced, the output of another decrypt.

## The key encrypts a key, not the content

`encryption_key` names a 256-bit symmetric key the backend holds. It never
touches the content. The backend produces a fresh content-encryption key per
message and a copy of that key only the named key can open, the content is
encrypted under the first, and the container carries the second.

This is envelope encryption, and it is the operation these devices offer rather
than a speed-up. No key-protection device Rite talks to is a cipher you hand a
file to: a cloud KMS caps a direct encrypt at a few kilobytes by design, a TPM
takes a kilobyte per call over a slow bus, and a smart card is slower still.
Every one of them offers exactly this operation instead, so a ceremony written
against a software backend keeps working when the key moves to a device.

Make the key with `generate_key` or install one with `import_key`:

```yaml
generate_the_archive_key:
  action: generate_key
  backend: openssl
  with:
    algorithm: AES-256
    policy:
      usages: [wrap, unwrap]
  creates: archive_key
```

`wrap` and `unwrap` are the usages, because protecting a content-encryption key
is a wrap. A key without them is refused by name.

## The container

`scheme` names the container. It defaults to `CMS-AES-256-GCM`, which is the
only value `encrypt_data` accepts, and it is written out only where a ceremony
wants the choice visible in the printed script.

The artifact is a CMS `AuthEnvelopedData` (RFC 5083) with a `KEKRecipientInfo`
(RFC 5652 §6.2.3), the content-encryption key under `id-aes256-wrap` and the
content under AES-256-GCM. `openssl cms -decrypt -secretkey <hex> -secretkeyid
<kcv>` opens it, which is what makes the archive readable in a decade with no
Rite binary present.

The recipient identifier is the key's check value, so the blob says which key
opens it without anyone holding a key. Write that value on the envelope:

```yaml
read_back_the_archive_key:
  action: oral_readback
  with:
    value: ${artifact.archive_key.kcv | hex}
```

`decrypt_data` compares the two before decrypting anything, so the wrong key
fails by name rather than as an authentication error that says nothing about
why.

## What comes out

`decrypt_data` declares nothing. Which container the bytes are in and how the
content was encrypted are both in the artifact, and a restated value could
disagree with the bytes that have to be decrypted.

What it produces is a byte artifact, read the way a material is. A step can
hash it, compare it, sign it, or hand it to `import_key`, which is how a key
archived as content becomes a key again.

The artifact is held as opened content: the bytes are wiped from memory when
the run drops them, a step that reads them borrows rather than copies, and
nothing prints them. The content was encrypted because it is secret, and the
tool cannot tell a runbook from a private key, so it treats every opened
artifact the same way.

## Writing opened content to disk

Sometimes the plaintext has to become a file. A signing key archived as
encrypted content is restored for an appliance that imports keys only from a
file on media, so the ceremony decrypts it and writes it out. An output
receives opened content only when it says so:

```yaml
output:
  restored_signing_key:
    type: document
    secret: true
    description: "The signing key in PKCS#8, for the appliance's import tool."

steps:
  restore_the_signing_key:
    action: decrypt_data
    backend: openssl
    reads:
      encrypted_data: ${artifact.archived_signing_key}
      decryption_key: ${artifact.archive_key}
    creates: restored_signing_key
```

Without `secret: true`, `rite check` reports the output and the runtime refuses
the write. With it, the file is written to the run directory like any other
output, the operator is warned at the moment it happens, and the flag stands in
the ceremony definition for anyone reviewing where the key went. Whether the
plaintext belongs next to the transcript is the author's call; the flag is what
makes it a call rather than a default.

One path stays open, because closing it would close the ceremony's own hands:
an expression. `${artifact.restored_signing_key | sha256 | hex}` puts a digest
in a `check_value` step, and `${artifact.restored_signing_key | base64}` would
put the key itself wherever that step records its inputs, transcript included.
What an expression exposes is the author's choice, and Rite does not
second-guess it.

An encrypted artifact is its own type, so it can be given to `decrypt_data` and
not to `unwrap_key`. The reverse holds too. The bytes of the two are the same
shape and the claims are not, and the type is what keeps them apart.

## What the transcript records

The scheme, the artifact both steps name, the check value of the key, the size
of the content, and, read back out of the DER, every algorithm identifier the
container names.

Deliberately no digest of the content, in either direction. Content is
encrypted because it is secret, and a hash of a secret in a record is a thing an
auditor cannot judge without knowing how hard it is to search.

## What `rite verify` checks

An encrypted artifact is checked on the terms a wrap gets, and appears beside
wraps under `Containers`:

```
Containers:
  seal_the_runbook: ok (artifact matches the recorded algorithms, addressed to a
  key generated in this ceremony)
```

- the recorded algorithms against the ones in the DER;
- the key the blob is addressed to against a key this ceremony generated or
  imported.

An artifact that is not in the run directory is reported as unchecked, not as
verified. That the content is what the ceremony meant to encrypt is outside the
bundle. A recovery drill in the room, opening the archive again and comparing
what comes out, is what covers that, and an attestation naming the drill is what
records it happened in front of someone.

## Not yet

Encrypting to a public key, the way `wrap_key` does with `recipient`. Only a
symmetric key the backend holds can be an `encryption_key` today.
