# DSL Conventions

Scope: `.rite.yaml` ceremony files.

## Quoting

Strings fall into three categories with three styles:

| Content                  | Style                                 | Example                                                      |
|--------------------------|---------------------------------------|--------------------------------------------------------------|
| Pure expression `${...}` | unquoted                              | `role: ${role.crypto_officer}`                               |
| Identifier-like literal  | unquoted                              | `action: confirm`, `backend: openssl`, `algorithm: RSA-4096` |
| Human prose              | quoted (or `\|` block for multi-line) | `name: "Crypto Officer"`                                     |

Read as: **quotes mean words, no quotes mean references.**

An identifier-like literal is a short, fixed value: an action name,
backend name, algorithm name, or declared identifier.

### When to quote anyway

Quote regardless of category when:

- YAML syntax requires it (the value contains special characters,
  parses as a number/boolean/date, or has surrounding whitespace).
- The value is a path, URI, fingerprint, or other free-form literal
  that could contain such characters even when this instance does not.

```yaml
path: "test_keys/transport_public.pem"   # path, always quoted
default: "2026-03-28"                    # would parse as a date
subject: "CN=Root CA,O=Example Org"      # contains a comma
```

### Mixed expressions stay quoted

An expression inside a larger string is not a pure expression:

```yaml
path: "${param.out_dir}/root_ca.pem"  # mixed: quoted
key:  ${artifact.root_ca_keypair}     # pure: unquoted
```

### Multi-line prose

Use the `|` block scalar:

```yaml
description: |
  Generate the offline root CA keypair on an air-gapped machine.
  The private key is wrapped with a transport public key.
```
