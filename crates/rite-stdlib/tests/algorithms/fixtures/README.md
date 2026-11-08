# Algorithm matrix fixtures

The inputs of the `algorithms` test in `rite-stdlib` (`tests/algorithms/`).

## `keys/`

One key per type the matrix names, including types Rite does not support, plus the payload
keys:

- a keypair as `<name>.key.der` (PKCS#8 DER) and `<name>.pub.der` (SPKI DER);
- a symmetric key as `<name>.key`, the key bytes themselves.

**These keys protect nothing.** They are committed so that a test can open what was sealed to
them, and so that no run depends on what the linked OpenSSL can generate. Never use one
outside these tests.

`payload-p-256` is the key `wrap_key` wraps and, as PKCS#8 DER, the content of every container.
`payload-aes-256` is what AES-KW wraps, since AES-KW takes whole 64-bit blocks only.
`payload-rsa-2048` is larger than raw RSA-OAEP carries. `p-256-compressed` is `p-256` itself,
with its point compressed in both encodings. `rsa-pss-2048` is an RSA key whose SPKI names
`id-RSASSA-PSS`, restricting it to PSS signatures.

## `certificates/`

A self-signed certificate for each key the shape tables use (`CERTIFIED` in `shape.rs`), so a
key can arrive as a certificate, DER or PEM. Made with the keys, by `openssl x509 -new`.

## `cms/`

Containers written by `openssl cms -encrypt`, one per row of `FIXTURES` in `wrapping/cases.rs`. The row is
the command: its content cipher, whether recipients are named by key identifier, and each
recipient with its `-keyopt` arguments. `MADE_WITH` holds the version of the command line that
wrote them.

## `signatures/`

Signatures written by `openssl pkeyutl -sign -rawin`, one per row of `FIXTURES` in
`signatures/cases.rs`, all over the same message (`MESSAGE` in `signatures/mod.rs`). The row is
the command: the key, the digest and the `-pkeyopt` arguments. A row in the P1363 encoding is
converted from the DER signature the command line writes. `MADE_WITH` holds the version of the
command line.

## Regenerating

```sh
RITE_REGENERATE_FIXTURES=1 cargo test -p rite-stdlib --test algorithms
```

This writes the keys, certificates and fixtures the tables name and the disk lacks, and leaves
every committed file as it is: run it after adding a row or a key type. To rewrite a file,
delete it first. A fixture is made with a key, so replacing a key means deleting its public half,
certificate and fixtures too; to replace everything, delete `keys/`, `certificates/`, `cms/` and
`signatures/`. ECDSA and ML-DSA signatures differ on every run, so a rewritten fixture changes
even when its row did not. A family's `MADE_WITH` gains a line for each run that wrote to it.
Regenerating needs OpenSSL on the `PATH`, or named by `RITE_OPENSSL_CLI`: 3.5 or later for the
ML-KEM and ML-DSA keys and the ML-DSA signatures, and 3.6 or later for `kemri-ml-kem-768`.

A form the OpenSSL command line cannot write has no fixture. X25519 key agreement and
ChaCha20-Poly1305 content are examples, and the matrix has no read-side test for them. Add a
fixture when a producer that writes the form is available.
