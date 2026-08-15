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

## Where the seam is

`rite-stdlib/src/signatures.rs`.

Actions call `signatures::verify`, never `rite_openssl::` directly. That module
is the only place backend-free cryptography names a provider, so changing the
provider is an edit to one file rather than an audit of every action.

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
ML-DSA arrived in OpenSSL 3.5, and its bindings sit behind a `cfg` resolved from
the OpenSSL headers present at build time. A binary linked against OpenSSL 3.0
contains no ML-DSA code, so no runtime check can recover the capability.

Two pieces make this visible:

- `crates/rite-openssl/build.rs` derives the `ossl350` cfg from the version
  `openssl-sys` publishes through its `links` metadata. (`openssl-sys` is a
  direct dependency of `rite-openssl` for this reason alone, since `links`
  metadata reaches only direct dependents.)
- `rite_openssl::ML_DSA_AVAILABLE` exposes the result. Branch on it wherever a
  useful alternative exists, such as skipping a test, rather than waiting for
  an `UnsupportedAlgorithm` error mid-ceremony.

Building with ML-DSA support requires OpenSSL 3.5 or newer. Distributions still
shipping 3.0, including Ubuntu 24.04, produce a working build with the
post-quantum algorithms absent. `--features openssl-vendored` bundles a current
OpenSSL and always includes them.
