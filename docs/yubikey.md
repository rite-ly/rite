# Preparing a YubiKey

Prepare a YubiKey before the ceremony: set its PIN, PUK and management key. A ceremony
then generates its keys on the card, or uses keys put in their slots beforehand. This page
lists what Rite does during a ceremony and what `ykman` does before it.

## What Rite does, and what `ykman` does

| Operation | Rite, during a ceremony | `ykman`, before it |
|---|---|---|
| Enter the PIN | `authenticate`, with a credential under `credentials:` | |
| Authenticate with the management key | `authenticate`, with an admin credential | |
| Generate a key in a slot, with its PIN and touch policies | `generate_key`, after the management key | `ykman piv keys generate` |
| Sign, or open content sealed to a slot key | `sign_data`, `decrypt_data` | |
| Read a slot's certificate | `piv_read_certificate` | |
| Show whether a key was generated on the card, and with which policies | `attest_key`, then `verify_attestation` against Yubico's roots | |
| Write a certificate to a slot | | `ykman piv certificates import` |
| Change the PIN, PUK or management key | | `ykman piv access` |
| Set retries, unblock the PIN or reset the card | | `ykman piv access`, `ykman piv reset` |

If a ceremony needs a `ykman` operation in the room, run the command and record it with a
`confirm` step. The transcript records the officer's confirmation, not the card's contents.

## Preparing a card

On a YubiKey with firmware 5.7 and factory settings:

```sh
ykman piv reset
ykman piv access set-retries 5 3
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

- Set retries first. This resets the PIN and PUK to their factory values.
- `--protect` stores the new management key on the card, protected by the PIN. Later
  `ykman` commands request the PIN instead of the key, and so does Rite: see
  [The management key in a ceremony](#the-management-key-in-a-ceremony).

Generate a key and request a certificate:

```sh
ykman piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy CACHED 9c 9c.pub
ykman piv certificates request --subject "CN=Release Signing" 9c 9c.pub 9c.csr
```

Have your CA sign `9c.csr`, then import the certificate:

```sh
ykman piv certificates import 9c 9c.crt
```

The PIN and touch policies are fixed when the key is generated. The ceremony reads the
key as a `backend_key` material and checks its origin and policies with `attest_key` and
`verify_attestation`. It
declares the PIN under `credentials:` with `grants: user` and `source: entered`, and an
`authenticate` step asks the holder for it.

## The management key in a ceremony

Generating a key on the card needs an admin session: an `authenticate` step with the
management key, declared as a credential with `grants: admin`. Its `source` says where
the key comes from:

- `factory_default`: the card's factory key, on a card not yet prepared.
- `protected_by: ${credential.<pin>}`: the key `--protect` stored on the card. The step
  asks for that PIN, then reads the key from the card. The PIN stays verified for later
  steps.
- `held`: a key kept outside the card. The step reads it from an artifact as `value`, for
  example one `combine_shares` recombined from custodians' shares, or one typed with
  `enter_secret` and `format: hex`. The value is the key's bytes: typed without
  `format: hex`, it is the hex text, twice the length, and the card refuses it.

```yaml
credentials:
  card_pin:
    backend: token
    grants: user
    source: entered
  card_admin:
    backend: token
    grants: admin
    source:
      protected_by: ${credential.card_pin}

steps:
  admin_login:
    action: authenticate
    backend: token
    reads:
      credential: ${credential.card_admin}
  make_key:
    action: generate_key
    backend: token
    with:
      algorithm: ECDSA-P256
      slot: "9c"
      policy:
        authentication: per_use   # PIN policy ALWAYS
        presence: cached          # touch policy CACHED
    creates: signing_key
```

`authentication` sets the key's PIN policy and `presence` its touch policy, both fixed
once the key exists:

| Value | `authentication` (PIN) | `presence` (touch) |
|---|---|---|
| `never` | `NEVER` | `NEVER` |
| `per_session` | `ONCE` | refused |
| `cached` | refused | `CACHED`, 15 seconds |
| `per_use` | `ALWAYS` | `ALWAYS` |

A field left out takes the slot's default. Write each as a value, not an expression:
`rite check` refuses a value the backend cannot enforce. The `generate_key` record holds
both what the step asked for and what the card reports it set, and the step fails if
the two differ. An `authenticate` step warns when the card's PIN or PUK
is still the factory value.

The card reports the management key's algorithm, 3DES or AES, and whether it is still
the factory key; the transcript records both, never the key. `rite check` refuses a
`generate_key` on a card with no admin `authenticate` before it.
`examples/piv/yubikey_key_generation.rite.yaml` is a complete ceremony.

## Certificates on a PIV card

A PIV slot can hold a private key and a separate certificate. The certificate contains
public-key information, not the private key. Three certificates matter here:

- **The slot certificate** identifies the key. A CA issues it, or it is self-signed.
  Smart card software, including Windows and macOS support and PKCS#11 modules such as
  `ykcs11` and OpenSC, commonly uses it to find the key and often ignores a slot without
  one. Rite addresses the slot directly and does not need this certificate.
- **The attestation certificate** shows that the key was generated on this card and
  records its policies. The card creates it on demand and signs it with the attestation
  key in slot F9.
- **The F9 certificate** identifies the card's attestation key. Yubico installs it at the
  factory; it chains to the Yubico PIV root CA.

The attestation chain from the Yubico root through F9 to the slot key is evidence that the
key was generated on the card. `verify_attestation` checks it against the roots the
ceremony names, and against the PIN and touch policies the step requires.
[`examples/piv/yubico/`](../examples/piv/yubico/) holds Yubico's roots and intermediates as
Yubico publishes them: PIV Root CA Serial 263751 for firmware before 5.7.4, Attestation
Root 1 and its intermediates after. Compare them with Yubico's before a real ceremony.
