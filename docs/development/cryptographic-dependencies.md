# Cryptographic dependencies

Which library performs which class of work, and where to add a new algorithm.

## The split

**OpenSSL performs cryptographic primitives.** Key generation, signing,
verification, wrapping, unwrapping, and random bytes. Every one of them, for
every algorithm, through `rite-openssl`.

**RustCrypto performs ASN.1 and DER structure.** `x509-cert` and the `der`
family build and parse certificates, CSRs, and algorithm identifiers. They
handle no key material and perform no cryptographic operation.

The dividing line is whether the code touches a key. Parsing a
`SubjectPublicKeyInfo` is structure. Verifying a signature under that key is a
primitive. A new algorithm needs work on both sides: an OID and identifier in
`rite-stdlib/src/pki/oids.rs`, and an implementation in `rite-openssl`.

## Why one provider for primitives

The rule exists because the alternative was tried. Signature verification once
ran on three implementations at once: the `rsa` crate for RSA, `p256` for
ECDSA, and OpenSSL for ML-DSA, while OpenSSL produced all three signatures.

That shape has no upside and several costs:

- **Doubled bug surface for one operation.** Signing and verifying through
  different implementations means a disagreement between them is a Rite bug,
  discoverable only by testing the pair.
- **A new dependency per algorithm.** Each signature family arrives as its own
  crate, at its own maturity, with its own release cadence and advisories. The
  set only grows.
- **Advisory exposure that is hard to reason about.** Whether an advisory
  applies depends on which code path a crate is used for, and that argument has
  to be rebuilt every time the set changes. See `.cargo/audit.toml` for the one
  entry still carried and what it took to justify.

Choosing OpenSSL specifically follows from a property of the domain: ceremonies
are largely performed on hardware (PIV cards, HSMs), so a real ceremony's
signing already happens outside any Rust crate. Software crypto is the
rehearsal and the software-only case, and it should agree with the widest
deployed implementation rather than be a second opinion.

The cost is a C dependency and its build requirements. That is accepted.

## Where the seam is

`rite-stdlib/src/signatures.rs`.

Actions call `signatures::verify`, never `rite_openssl::` directly. That module
is the only place backend-free cryptography names a provider, so swapping the
one behind it means rewriting a file rather than auditing every action.

Backend *construction* is a separate seam and names providers of its own
(`backend/mod.rs`, and `backend/mock.rs` for the rehearsal mock). Those pick
which device performs an operation; `signatures.rs` covers the operations that
use no device at all.

Verification needs a seam because it takes only a public key, which is what lets
it check evidence the ceremony did not produce.

Operations that need a private key go through the `rite-sdk` backend traits
instead. Those already abstract the provider, because the provider might be a
smart card.

## Build-time capability

**Algorithm availability is fixed when `rite-openssl` compiles, not when it
runs.** ML-DSA arrived in OpenSSL 3.5, and the bindings for it sit behind a
`cfg` resolved from the OpenSSL headers present at build time. A binary linked
against OpenSSL 3.0 contains no ML-DSA code at all, so no runtime check can
recover the capability.

Two pieces make this visible:

- `crates/rite-openssl/build.rs` derives the `ossl350` cfg from the version
  `openssl-sys` publishes through its `links` metadata. (`openssl-sys` is a
  direct dependency of `rite-openssl` for this reason alone, since `links`
  metadata reaches only direct dependents.)
- `rite_openssl::ML_DSA_AVAILABLE` exposes the result. Branch on it wherever a
  useful alternative exists, such as skipping a test, rather than waiting for
  an `UnsupportedAlgorithm` error mid-ceremony.

**Building with ML-DSA support requires OpenSSL 3.5 or newer.** Distributions
still shipping 3.0, including Ubuntu 24.04, produce a working build with the
post-quantum algorithms absent. `--features openssl-vendored` bundles a current
OpenSSL and always has them.
