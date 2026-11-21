# Preparing a YubiKey

Prepare a YubiKey before the ceremony. Set its PIN, PUK and management key, and put
required keys in their declared slots. This page lists what Rite does during a ceremony
and what `ykman` does before it.

## What Rite does, and what `ykman` does

| Operation | Rite, during a ceremony | `ykman`, before it |
|---|---|---|
| Enter the PIN | `authenticate`, with a credential under `credentials:` | |
| Sign, or open content sealed to a slot key | `sign_data`, `decrypt_data` | |
| Read a slot's certificate | `piv_read_certificate` | |
| Show whether a key was generated on the card | `yubikey_attest_slot` | |
| Generate a key in a slot | | `ykman piv keys generate` |
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
  `ykman` commands request the PIN instead of the key.

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
key as a `backend_key` material and checks its origin with `yubikey_attest_slot`. It
declares the PIN under `credentials:` with `grants: user` and `source: entered`, and an
`authenticate` step asks the holder for it.

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
key was generated on the card.
