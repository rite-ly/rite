# Rite

A DSL and runtime for describing, executing, and reviewing cryptographic key ceremonies.

> **Beta** — Breaking changes between 0.x versions.

## Example

```yaml
version: "0.2"
name: "Root CA Key Generation"

backends:
  openssl:
    provider: openssl

output:
  root_ca_public_key:
    type: public_key
    description: "Root CA public key for trust anchor distribution"

roles:
  crypto_officer:
    person: "Alice Smith"
  witness:
    person: "Bob Jones"

sections:
  keygen:
    role: "${role.crypto_officer}"
    steps:
      generate_root_ca:
        action: generate_keypair
        backend: openssl
        with:
          algorithm: RSA-4096
          key_usage: [key_cert_sign, crl_sign]
        creates: root_ca_keypair
      export_public_key:
        action: export_public
        backend: openssl
        reads: "${artifact.root_ca_keypair}"
        creates: root_ca_public_key
      attest_completion:
        action: attest
        role: "${role.witness}"
        with:
          statement: "I witnessed the key generation and public key export."
```

Run it:

```sh
rite check  ceremony.rite.yaml   # validate
rite script ceremony.rite.yaml   # generate script
rite run    ceremony.rite.yaml   # execute
```

Running a ceremony produces a timestamped output directory:

```
root-ca-key-generation-20260511T201639
├── artifacts
│   └── root_ca_public_key.pem
└── transcript.jsonl
```

Artifacts are written as they are produced. 
The transcript records every step, role, attestation, and artifact hash in an append-only JSONL file.

```sh
rite verify root-ca-key-generation-20260511T201639   # verify integrity
rite report root-ca-key-generation-20260511T201639   # generate audit report
```

## Installation

Install with Homebrew:

```sh
brew tap rite-ly/tap
brew install rite
```

Run with Docker:

```sh
docker run --rm -it --init \
  -v "$PWD:/workspace" \
  ghcr.io/rite-ly/rite:0.1.0-rc.6 check ceremony.rite.yaml
```

Build from source:

```sh
cargo build --release -p rite-cli
cargo build --release -p rite-ls   # language server for editor support
```

### Editor support

The `rite-ls` language server is available for editor integration (VS Code, IntelliJ, and other LSP clients).

## Features

- [x] YAML ceremony DSL with roles, steps, materials, and outputs
- [x] Guided execution with console UI (`rite run`)
- [x] OpenSSL backend (RSA and ECDSA-P256 key generation, signing, wrapping, and PKI)
- [x] Transcript generation and `rite verify`
- [x] Language server (`rite-ls`) with diagnostics, completions, hover, and go-to-definition
- [x] Elliptic curve support (EC keys, ECDSA signing)
- [ ] Post-quantum support: ML-KEM key encapsulation (hybrid KEM+wrap)
- [ ] Interactive TUI with role-specific views
- [ ] Hardware backends: 
  - [ ] YubiKey PIV
  - [ ] TPM 2.0
  - [ ] PKCS#11
- [ ] Bootable USB image for isolated ceremony environments
- [x] Docker image for containerised ceremony execution
- [ ] Error handling and ceremony resumption
- [x] Script and report generation (`rite script`, `rite report`)
  - [ ] Themeable output via template engine
- [ ] Plugin system for out-of-process backends

## Design

Ceremonies are human protocols with machine assistance: operators, witnesses, and physical steps are part of the protocol, not peripheral to it.

- **Evidence over execution** — the transcript is the product; guided execution is how you produce it
- **Error modes are first-class** — retries, aborts, and deviations are explicit
- **Trust boundaries must be explicit** — the tool distinguishes machine-verifiable facts from human attestations
- **One structure, many outputs** — a ceremony definition should produce guided execution, printable checklists, and verification artifacts

## License

GPLv3. The `rite-sdk` and `rite-model` crates are expected to move to MIT or Apache 2.0 in a future release.
