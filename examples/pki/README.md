# PKI Ceremonies

Examples for generating offline certificate-authority keys, issuing root
certificates, and protecting private-key backups.

## Ceremonies

### `root_ca_software.rite.yaml`: Software root CA

Generates an RSA-4096 root key with OpenSSL, issues a self-signed certificate,
and wraps the private key to a transport public key. Two witnesses and the
crypto officer attest at the end. The transport private key is required to
recover the backup.

### `root_ca_post_quantum.rite.yaml`: Post-quantum root CA

Uses ML-DSA-87 for the root key and ML-KEM-768 for the transport key. ML-KEM
requires a binary built against OpenSSL 3.6 or newer.
Released binaries and the container image include a current OpenSSL.

A root issued today with a 20-year validity is still a trust anchor when a
cryptographically relevant quantum computer becomes plausible, and a root key
cannot be rotated without redistributing the trust anchor everywhere it is
pinned. That lifetime is the reason to choose a lattice signature now.
ML-DSA-87 is the NIST category 5 parameter set required by CNSA 2.0;
`generate_key` also accepts `ML-DSA-65` and `ML-DSA-44`. The certificate is
around 10 KB against 2 KB for RSA-4096, which does not matter for a root that
issues a handful of certificates.

The transport key has a longer horizon than the signature. A signature has to
hold only while it is trusted, but a copy of the wrapped backup can be kept
until something can open it (harvest now, decrypt later). The backup is
therefore wrapped to ML-KEM rather than to RSA.

Check the OpenSSL linked into a system build with:

```sh
openssl version
```

### Planned examples

- `intermediate_ca.rite.yaml`: Issue an intermediate certificate using the
  root key recovered from the software ceremony's backup.
- `root_ca_hsm.rite.yaml`: Generate a root key in a PKCS#11 HSM. The key is
  never exported, so the ceremony has no wrap step; backup uses the vendor's
  cloning or backup procedure, outside PKCS#11.

## Test keys

```
test_keys/transport_public.pem        RSA-4096 transport key, software ceremony
test_keys/transport_private.pem       opens its wrapped backup
test_keys/kem_transport_public.pem    ML-KEM-768 transport key, post-quantum ceremony
test_keys/kem_transport_private.pem   opens its wrapped backup
```

These keys are for the examples only. **Never use them in a real ceremony.**
Generate your own:

```sh
openssl genrsa -out transport_private.pem 4096
openssl rsa -in transport_private.pem -pubout -out transport_public.pem

openssl genpkey -algorithm ML-KEM-768 -out kem_transport_private.pem
openssl pkey -in kem_transport_private.pem -pubout -out kem_transport_public.pem
```

ML-KEM key generation requires OpenSSL 3.5 or newer.

## Run the software ceremony

```sh
rite check  examples/pki/root_ca_software.rite.yaml
rite script examples/pki/root_ca_software.rite.yaml
rite run    examples/pki/root_ca_software.rite.yaml
```

Replace the filename with `root_ca_post_quantum.rite.yaml` for the
post-quantum example. After a run, set `RUN_DIR` to the output directory
printed by `rite run`, then verify the wrapped backup with its matching test
private key:

```sh
RUN_DIR=/path/to/run-output
openssl cms -decrypt -inform DER \
  -in "$RUN_DIR/artifacts/wrapped_root_ca_key.p7c" \
  -inkey examples/pki/test_keys/transport_private.pem | \
  openssl pkey -inform DER -check -noout
```

For the post-quantum example, use `kem_transport_private.pem` instead. OpenSSL
reads the recipient type from the container and selects the matching key
operation.
