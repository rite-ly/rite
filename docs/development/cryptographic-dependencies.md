# Cryptographic dependencies

Which library performs which class of work, and where to add a new algorithm.

## The split

- **OpenSSL performs cryptographic primitives**, through `rite-openssl`: key
  generation, signing, verification, wrapping, unwrapping, and random bytes,
  for every algorithm.
- **RustCrypto performs ASN.1 and DER structure.** `x509-cert` and the `der`
  family build and parse certificates, CSRs, and algorithm identifiers. They
  handle no key material and perform no cryptographic operation.

The dividing line is whether the code touches a key. Parsing a
`SubjectPublicKeyInfo` is structure. Verifying a signature under that key is a
primitive. A new algorithm needs work on both sides: an OID and identifier in
`rite-stdlib/src/pki/oids.rs`, and an implementation in `rite-openssl`.

`rite-sdk` sits on the structure side of that line. `PublicKeyDer` and
`CertificateDer` parse their own encoding with `x509-cert` so a build with no
crypto provider can still tell a key from a certificate and read a key's
algorithm. A new key algorithm also needs its OID in
`rite-sdk/src/key_material.rs`.

## Why one provider for primitives

Primitives use a single implementation rather than one crate per algorithm
family, for three reasons:

- **Signing and verifying stay on the same implementation.** Splitting them
  means a disagreement between the two is a Rite bug, and only a test covering
  the pair will find it.
- **The dependency set does not grow with the algorithm list.** A crate per
  signature family brings its own maturity, release cadence, and advisories.
- **Advisory applicability stays tractable.** Whether an advisory affects Rite
  depends on which paths use the crate, and that assessment has to be redone
  whenever the set changes. `.cargo/audit.toml` holds the one entry currently
  carried, with its rationale.

OpenSSL rather than some other single implementation: ceremonies largely run on
hardware (PIV cards, HSMs), so signing in a real ceremony happens outside any
Rust crate. Software crypto covers rehearsals and software-only runs, and
OpenSSL is the most widely deployed implementation to agree with.

The cost is a C dependency and its build requirements.

## Device bindings are not providers

`cryptoki` in `rite-pkcs11`, and `yubikey` in `rite-piv`, sit outside the
one-provider rule. Neither implements an algorithm: they speak a protocol to a
device that does. `cryptoki` in particular is a binding to whatever vendor
module the operator loads at run time, and Rite links none of those modules.

The consequence is that a claim about what a token does cannot be settled by
reading Rite's source. `crates/rite-pkcs11/tests/token_questions.rs` asks a
real token instead, under `#[ignore]` and `SOFTHSM2_MODULE`, and CI runs it
against SoftHSM. SoftHSM answers for the specification rather than for any
particular vendor; where a device differs, it differs from that baseline.

## Where the seam is

`rite-stdlib/src/signatures.rs`.

Actions call `signatures::verify`, never `rite_openssl::` directly. That module
is the only place backend-free cryptography names a provider, so changing the
provider is an edit to one file rather than an audit of every action.

The same module holds `signatures::resolve_public_key`, which turns an artifact
reference into a `PublicKeyDer`. It needs structure and no provider, and it sits
here so that every action naming a key accepts the same shapes: a keypair, an
exported key, a certificate, and DER or PEM bytes off a disk.

Backend *construction* is a separate seam with providers of its own
(`backend/mod.rs`, and `backend/mock.rs` for the rehearsal mock). Those select
which device performs an operation; `signatures.rs` covers operations that use
no device.

Only verification needs this seam. It takes a public key alone, so it is the
one cryptographic operation that runs without a backend. Operations needing a
private key go through the `rite-sdk` backend traits, which already abstract
the provider because it may be a smart card.

## Build-time capability

Algorithm availability is fixed when `rite-openssl` compiles, not when it runs.
ML-DSA and ML-KEM both arrived in OpenSSL 3.5, and their bindings sit behind a
`cfg` resolved from the OpenSSL headers present at build time. A binary linked
against OpenSSL 3.0 contains none of that code, so no runtime check can recover
the capability.

Two pieces make this visible:

- `crates/rite-openssl/build.rs` derives the `ossl350` cfg from the version
  `openssl-sys` publishes through its `links` metadata. (`openssl-sys` is a
  direct dependency of `rite-openssl` for this reason alone, since `links`
  metadata reaches only direct dependents.)
- `rite_openssl::build_limitation(algorithm)` names what about this build
  prevents generating a given key, and `rite_openssl::POST_QUANTUM_AVAILABLE`
  exposes the raw cfg behind it. Ask it wherever a useful alternative exists,
  such as skipping a test or warning during `rite check`, rather than waiting
  for an `UnsupportedAlgorithm` error mid-ceremony. `None` means this build does
  not limit the algorithm, which also covers one no build can generate, so it is
  a narrower question than whether the algorithm is supported at all. Keeping
  the per-algorithm answer in this crate is deliberate: it is the one that
  compiles the bindings. It carries no compiler enforcement, since
  `KeyAlgorithm` is `#[non_exhaustive]` and defined in `rite-sdk`, so a new
  algorithm reads as unlimited until it is listed and the backstop is the
  refusal in `generate_key`.

Building with post-quantum support requires OpenSSL 3.5 or newer. Distributions still
shipping 3.0, including Ubuntu 24.04, produce a working build with the
post-quantum algorithms absent. `--features openssl-vendored` bundles a current
OpenSSL and always includes them.

## Checking the other build before you push

CI compiles both sides and a development machine sits on one, so code written
against an API only 3.5 has passes locally and fails on the `Test` job, which
links the distribution's 3.0. `RITE_OSSL350` replaces the detected answer:

```sh
RITE_OSSL350=0 cargo clippy --workspace --all-targets -- -D warnings
RITE_OSSL350=0 cargo test -p rite-openssl -p rite-stdlib
```

This catches two things a local run otherwise cannot: an API the `openssl`
crate exposes only in the newer build, and a binding used only inside a
`cfg(ossl350)` block, which the older build reports as unused.

It overrides this crate's cfg and nothing else, so it answers whether the code
still builds without the post-quantum paths, not whether it works against
OpenSSL 3.0. The `Test` job answers that, and the vendored `Build (smoke)` job
is the only place the `ossl350` tests run at all. Neither sets the variable.
