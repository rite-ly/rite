# Rite

A DSL and runtime for describing, executing, and reviewing cryptographic key ceremonies.

> **Beta** — Breaking changes between 0.x versions.

<p align="center"><img src="docs/demo/demo.gif" alt="Executing a ceremony with rite run" width="700"></p>
<p align="center"><sub>Guided execution with <code>rite run</code>, one phase of the <a href="#lifecycle">ceremony lifecycle</a>.</sub></p>

## The problem

Cryptography makes forgery mathematically hard. 
HSMs make key extraction physically hard.
Neither answers the questions that determine whether a sensitive operation was actually performed correctly: Who authorized this? Who was present? Was every step followed?

These questions require human attestation, role separation, and an auditable record: a _ceremony_.
The industry has learned to take them seriously, but still lacks simple, reusable ways to describe, execute, and review them.

*[Security Ceremonies: Why Secure Systems Are More Than Math →](https://ritely.io/blog/security_ceremonies/)*

## Lifecycle

A ceremony unfolds in phases. The same YAML drives all of them:

1. **Author** — write the ceremony as YAML. Editor extensions provide diagnostics, completion, and inline navigation.
2. **Validate** — `rite check` catches missing references, undefined roles, and schema errors.
3. **Prepare** — `rite script` produces the printed protocol participants follow and complete by hand during the ceremony, archived alongside the digital transcript.
4. **Execute** — `rite run` walks operators and witnesses through the steps and recording every action in an append-only transcript.
5. **Audit** — `rite verify` confirms transcript integrity; `rite report` produces a human-readable audit document for stakeholders.

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
    role: ${role.crypto_officer}
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
        reads: ${artifact.root_ca_keypair}
        creates: root_ca_public_key
      attest_completion:
        action: attest
        role: ${role.witness}
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
  ghcr.io/rite-ly/rite check ceremony.rite.yaml
```

Install from crates.io:

```sh
cargo install rite
```

### Editor support

Install the official IDE extensions:

- [VS Code](https://marketplace.visualstudio.com/items?itemName=rite-ly.rite) (Visual Studio Marketplace)
- [IntelliJ IDEA and other JetBrains IDEs](https://plugins.jetbrains.com/plugin/31139-rite-language) (JetBrains Marketplace)

Both bundle the `rite-ls` language server. For other LSP-aware editors, run `rite-ls` directly from the binaries attached to each release.

## Features

- [x] **Ceremony DSL** — roles, steps, materials, outputs
- [x] **Guided execution** — `rite run`
  - [x] Interactive TUI
  - [x] Error handling (taxonomy, operator-driven retry)
    - [ ] Ceremony resumption after interruption
    - [ ] Teardown act on abort or failure
- [x] **Cryptographic backends**
  - [x] OpenSSL: RSA, ECDSA-P256, signing, wrapping, PKI
    - [ ] Post-quantum: ML-KEM key encapsulation
  - [x] Hardware backends
    - [x] YubiKey PIV: key generation, signing, certificate read, on-device attestation
      - [ ] Write operations (key import, PIN/PUK and management-key changes)
    - [ ] TPM 2.0
    - [ ] PKCS#11
  - [ ] Plugin system for out-of-process backends
- [x] **Evidence and verification**
  - [x] Transcript generation and `rite verify`
  - [x] Verifiable randomness
  - [ ] Hardware-attested execution (TPM PCR measurements and signed quotes)
  - [ ] RFC3161 trusted timestamps
- [x] **Output formats**
  - [x] Script and report generation (`rite script`, `rite report`)
  - [x] Themeable output via template engine (not yet user-configurable)
- [x] **IDE support** — VS Code, IntelliJ
  - [x] Language server: diagnostics, completion, hover, go-to-definition, references, symbols
  - [x] Semantic-token highlighting (initial: expressions and reference categories)
  - [x] Inlay hints (initial: step labels)
  - [ ] Code lens for in-editor `check` / dry-run / run
  - [ ] Live script preview pane
  - [ ] Code actions for common diagnostics
- [x] **Isolation and deployment**
  - [x] Docker image for containerised execution
  - [ ] Bootable USB image for air-gapped ceremonies

## Design

Ceremonies are human protocols with machine assistance: operators, witnesses, and physical steps are part of the protocol, not peripheral to it.

- **Evidence over execution** — the transcript is the product; guided execution is how you produce it
- **Error modes are first-class** — retries, aborts, and deviations are explicit
- **Trust boundaries must be explicit** — the tool distinguishes machine-verifiable facts from human attestations
- **One structure, many outputs** — a ceremony definition should produce guided execution, printable checklists, and verification artifacts

## License

Licensing is split per crate. 
The `rite-sdk`, `rite-model`, and `rite-resolver` crates are dual-licensed under `Apache-2.0 OR MIT`, so backend authors and third-party tooling can integrate with Rite without GPL obligations. 
The runtime, stdlib, OpenSSL backend, CLI, and language server are licensed under `GPL-3.0-only`.
