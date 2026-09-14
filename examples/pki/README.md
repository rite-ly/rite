# PKI Ceremonies

Examples covering certificate authority lifecycle operations: generating root and
intermediate CA keypairs, issuing certificates, and protecting key material for transport.

## Ceremonies

### `root_ca_software.rite.yaml` — Root CA Key Generation (Software)

Generates an offline root CA keypair using the OpenSSL backend. Demonstrates:

- Environment verification before touching key material (clock, machine identity, air gap)
- RSA-4096 keypair generation, declared extractable so the backup wrap can run
- Self-signed root CA certificate issuance
- Private key wrapping to a transport public key (CMS `AuthEnvelopedData`, AES-256-GCM)
- Multi-role attestation: two witnesses and the crypto officer attest in the closing act

The ceremony produces a self-signed root CA certificate and an encrypted key backup.
The backup can only be recovered by the holder of the transport private key, which is
the input to the intermediate CA signing ceremony.

### `root_ca_post_quantum.rite.yaml` — Root CA Key Generation (ML-DSA + ML-KEM)

The same ceremony with an ML-DSA-87 root key (FIPS 204) instead of RSA-4096, and an
ML-KEM-768 transport key (FIPS 203) instead of RSA-4096.

A root CA issued today with a 20-year validity is still a trust anchor in the window
where a cryptographically relevant quantum computer is plausible, and a root key cannot
be rotated without redistributing the trust anchor everywhere it is pinned. That lifetime
is the reason to pick a lattice signature now.

ML-DSA-87 is the NIST category 5 parameter set and the CNSA 2.0 requirement. `ML-DSA-65`
(category 3) and `ML-DSA-44` (category 2) are also accepted by `generate_key`. The
resulting certificate is around 10 KB against 2 KB for RSA-4096, which is immaterial for
a root that issues a handful of certificates over its life.

The transport key is the other half, and signature and confidentiality fail
differently. A signature has to hold only while it is trusted; a wrapped key copied off
the media today can be kept until there is something to open it with, which is exactly
the shape harvest-now-decrypt-later takes. An archived backup therefore carries the
longer horizon of the two, so it is wrapped to a lattice KEM rather than to RSA.

**Requires OpenSSL 3.5 or newer.** Support is decided when `rite` is built, not when it
runs: a binary linked against an older OpenSSL has no ML-DSA code compiled in and fails
the key generation step with an unsupported-algorithm error. Released binaries and the
container image bundle a current OpenSSL and always support it. To check a local build:

```sh
openssl version   # the library rite was built against, if system-linked
```

### `intermediate_ca.rite.yaml` _(planned — requires `root_ca_software` outputs)_

Signs an intermediate CA CSR using the root CA private key recovered from the encrypted
backup. Requires the wrapped key and certificate produced by `root_ca_software`.

### `root_ca_hsm.rite.yaml` _(planned — requires a PKCS#11 backend)_

Root CA key generation on a PKCS#11-capable HSM. The private key is generated on-device
and never exported, so the ceremony has no wrapping step: the wrapping actions export the
target key to DER, which an HSM-resident key does not permit. Backup runs through the
vendor's own cloning or backup procedure, outside PKCS#11.

## Test Keys

```
test_keys/transport_public.pem        RSA-4096 transport key, classical ceremonies
test_keys/transport_private.pem       used to decrypt their wrapped output
test_keys/kem_transport_public.pem    ML-KEM-768 transport key, post-quantum ceremony
test_keys/kem_transport_private.pem   used to decrypt its wrapped output
```

> **Test keys only.** Never use these in a real ceremony. Generate your own:
>
> ```sh
> openssl genrsa -out transport_private.pem 4096
> openssl rsa -in transport_private.pem -pubout -out transport_public.pem
>
> openssl genpkey -algorithm ML-KEM-768 -out kem_transport_private.pem
> openssl pkey -in kem_transport_private.pem -pubout -out kem_transport_public.pem
> ```
>
> ML-KEM needs OpenSSL 3.5 or newer.

## Running

```sh
rite check  examples/pki/root_ca_software.rite.yaml
rite script examples/pki/root_ca_software.rite.yaml
rite run    examples/pki/root_ca_software.rite.yaml
```

Substitute `root_ca_post_quantum.rite.yaml` for the ML-DSA variant.

After the ceremony, decrypt the wrapped private key to verify the output:

```sh
openssl cms -decrypt -inform DER -in wrapped_root_ca_key.p7c \
  -inkey examples/pki/test_keys/transport_private.pem | \
  openssl pkey -inform DER -text -noout
```

The post-quantum ceremony wraps to the ML-KEM key, so use
`kem_transport_private.pem` there. The command is otherwise identical: the
recipient form differs inside the blob, and `openssl cms -decrypt` picks it up
from the key it is given.
