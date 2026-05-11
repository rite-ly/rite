# PKI Ceremonies

Examples covering certificate authority lifecycle operations: generating root and
intermediate CA keypairs, issuing certificates, and protecting key material for transport.

## Ceremonies

### `root_ca_software.rite.yaml` — Root CA Key Generation (Software)

Generates an offline root CA keypair using the OpenSSL backend. Demonstrates:

- Environment verification before touching key material (clock, machine identity, air gap)
- RSA-4096 keypair generation with `key_cert_sign` / `crl_sign` key usage
- Self-signed root CA certificate issuance
- Private key wrapping with a transport public key (CMS-RSA-GCM)
- Multi-role attestation: two witnesses and the crypto officer attest in the closing act

The ceremony produces a self-signed root CA certificate and an encrypted key backup.
The backup can only be recovered by the holder of the transport private key, which is
the input to the intermediate CA signing ceremony.

### `intermediate_ca.rite.yaml` _(planned — requires `root_ca_software` outputs)_

Signs an intermediate CA CSR using the root CA private key recovered from the encrypted
backup. Requires the wrapped key and certificate produced by `root_ca_software`.

### `root_ca_hsm.rite.yaml` _(planned — requires PKCS#11 backend)_

Root CA key generation on a PKCS#11-capable HSM. The private key is generated on-device
and never exported.

## Test Keys

```
test_keys/transport_public.pem    transport key used by the ceremonies
test_keys/transport_private.pem   used to decrypt wrapped ceremony output
```

> **Test keys only.** Never use these in a real ceremony. Generate your own:
> `openssl genrsa -out transport_private.pem 4096 && openssl rsa -in transport_private.pem -pubout -out transport_public.pem`

## Running

```sh
rite check  examples/pki/root_ca_software.rite.yaml
rite script examples/pki/root_ca_software.rite.yaml
rite run    examples/pki/root_ca_software.rite.yaml
```

After the ceremony, decrypt the wrapped private key to verify the output:

```sh
openssl cms -decrypt -inform DER -in wrapped_root_ca_key.p7c \
  -inkey examples/pki/test_keys/transport_private.pem | \
  openssl pkey -inform DER -text -noout
```
