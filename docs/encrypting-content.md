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

## Encrypting to a public key

`recipient` in place of `encryption_key` addresses the content to a public key
whose private half is held elsewhere, the way `wrap_key` does:

```yaml
seal_the_runbook_for_the_custodian:
  action: encrypt_data
  backend: openssl
  reads:
    data: ${artifact.runbook}
    recipient: ${artifact.custodian_public_key}
  with:
    expect_recipient: "sha256:3b9c…"
  creates: sealed_runbook
```

The recipient is an RSA-2048 or RSA-4096 key, in any shape `wrap_key` accepts
for a recipient: a key or certificate an earlier step produced, or DER or PEM
bytes carried in as a material. The step's backend supplies the random bytes of
the content-encryption key, and the public key protects it with RSAES-OAEP over
SHA-256. No key of the backend's is involved.

`expect_recipient` is the recipient's `sha256:` fingerprint, written into the
definition before the ceremony. The step compares the key it receives against
it and refuses to run on a mismatch, since content sealed to the wrong key is
readable by that key's holder and by nobody the ceremony meant. Without it, the
transcript records whichever key arrived.

The holder opens the result with `decrypt_data` and the private key in a
backend, or with `openssl cms -decrypt -inkey`. Nothing in the ceremony shows
they can.

## The container

`scheme` names the container. It defaults to `CMS-AES-256-GCM`, which is the
only value `encrypt_data` accepts, and it is written out only where a ceremony
wants the choice visible in the printed script.

The artifact is a CMS `AuthEnvelopedData` (RFC 5083) with the content under
AES-256-GCM and one recipient:

- for `encryption_key`, a `KEKRecipientInfo` (RFC 5652 §6.2.3), the
  content-encryption key under `id-aes256-wrap`. `openssl cms -decrypt
  -secretkey <hex> -secretkeyid <kcv>` opens it.
- for `recipient`, a `KeyTransRecipientInfo` (RFC 5652 §6.2.1), the
  content-encryption key under RSAES-OAEP with SHA-256 for the digest and for
  MGF1. `openssl cms -decrypt -inkey <key>` opens it.

Either is what makes the archive readable in a decade with no Rite binary
present.

The recipient identifier names the key, so the blob says which key opens it
without anyone holding a key. A symmetric key is named by its check value, a
public key by the SHA-256 of its SPKI, which is its `sha256:` fingerprint. For
a symmetric key, write the check value on the envelope:

```yaml
read_back_the_archive_key:
  action: oral_readback
  with:
    value: ${artifact.archive_key.kcv | hex}
```

`decrypt_data` compares the two before decrypting anything, so the wrong key
fails by name rather than as an authentication error that says nothing about
why.

## A container sealed elsewhere

`decrypt_data` also opens a CMS file brought into the room as a material, such
as a document someone sealed with `openssl cms` to a key the ceremony holds.

```yaml
materials:
  sealed_document:
    type: digital
    path: "media/document.p7m"
    description: "Document sealed to the custodian's key."

# ...

open_the_sealed_document:
  action: decrypt_data
  backend: openssl
  reads:
    encrypted_data: ${artifact.sealed_document}
    decryption_key: ${artifact.custodian_key}
  creates: document
```

The file has to be an `AuthEnvelopedData` with AES-256-GCM content and one
recipient, in one of two forms:

- a `KEKRecipientInfo` under `id-aes256-wrap`, for a 256-bit key the backend
  holds, named by its check value;
- a `KeyTransRecipientInfo` under RSAES-OAEP with SHA-256 for the digest and for
  MGF1, for an RSA-2048 or RSA-4096 key the backend holds with the `unwrap`
  usage. The recipient is named by subject key identifier: either the SHA-256 of
  the key's SPKI, which is how Rite names a key, or the SHA-1 of RFC 5280
  method 1, which is what a certificate's subject key identifier usually holds.

The `openssl` command line writes the second form for a certificate when told to
use OAEP and to name the recipient by key identifier:

```sh
openssl cms -encrypt -binary -aes-256-gcm -keyid -outform DER \
  -recip custodian.crt \
  -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 \
  -in document.pdf -out document.p7m
```

Without those options it writes forms `decrypt_data` refuses, by name:

- RSA key transport under PKCS#1 v1.5, the default without `-keyopt`. Its
  padding check is what Bleichenbacher's attack queries, so it is not opened.
- A recipient named by issuer and serial number, the default without `-keyid`.
  That names a certificate, and the ceremony holds a key.
- `EnvelopedData` with CBC content, the default without `-aes-256-gcm`. Its
  content is not authenticated.

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

Where the bytes go from there is the author's call, made in the definition.
Declaring the artifact under `output:` writes it to the run directory like any
other output, in the clear next to the transcript; a signing key archived as
encrypted content and restored for an appliance that imports keys only from a
file is one reason to. An expression exposes what the author asks of it:
`${artifact.restored_key | sha256 | hex}` puts a digest in a `check_value`
step, and `${artifact.restored_key | base64}` would put the key itself wherever
that step records its inputs, transcript included. Rite does not second-guess
either.

An encrypted artifact is its own type, so it can be given to `decrypt_data` and
not to `unwrap_key`. The reverse holds too. The bytes of the two are the same
shape and the claims are not, and the type is what keeps them apart. A
material carries no such claim, which is why `decrypt_data` reads one as a
container sealed elsewhere.

## What the transcript records

The scheme, the artifact both steps name, the key (its check value for a
symmetric key, the `sha256:` fingerprint of its public key for an RSA one), the
size of the content, and, read back out of the DER, every algorithm identifier
the container names.

For `recipient`, the fingerprint is in a `wrap_recipient_recorded` fact of its
own, as for `wrap_key`, recorded before anything is encrypted and saying
whether the ceremony declared it. The fact is restricted, so a disclosure can
publish how the content was encrypted and withhold to whom.

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
  imported, or, for `recipient`, against the recorded recipient, reported as
  declared where the definition named it.

An artifact that is not in the run directory is reported as unchecked, not as
verified. That the content is what the ceremony meant to encrypt is outside the
bundle. A recovery drill in the room, opening the archive again and comparing
what comes out, is what covers that, and an attestation naming the drill is what
records it happened in front of someone.
