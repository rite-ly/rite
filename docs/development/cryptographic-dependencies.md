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
`rite-sdk/src/key_material.rs`. `PublicKeyDer::rfc5280_key_identifier` derives
the SHA-1 name X.509 tooling gives a key through `x509-cert`, as
`issue_certificate` does for the certificates it writes: it is a name read off
public bits, not an operation under a key.

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
  whenever the set changes. The `ignore` list in `deny.toml` holds the entries
  currently carried, with their rationale.

OpenSSL rather than some other single implementation: ceremonies largely run on
hardware (PIV cards, HSMs), so signing in a real ceremony happens outside any
Rust crate. Software crypto covers rehearsals and software-only runs, and
OpenSSL is the most widely deployed implementation to agree with.

The cost is a C dependency and its build requirements.

## Secret sharing

`rite-stdlib/src/sharing/gf256.rs` implements Shamir secret sharing over
GF(2^8). It is a primitive by the test above, since the arithmetic touches
the secret, and it is not taken from a provider because none offers it:
OpenSSL has no secret sharing, and neither does any device Rite talks to.

The module is one file with the textbook arithmetic, not a table-driven or
constant-time variant. A ceremony splits one secret once on an air-gapped
machine, so the property that matters is that the code can be read in full.
The scheme is stated in the module (Rijndael polynomial, one polynomial per
byte, a share is its threshold, its `x` from 1 and one `y` per byte) and named
in the transcript, so any GF(256) library reconstructs a secret without this
code. How a share is laid out in a file or on paper is a container's
business, in `sharing/wire.rs` and the paper encoding.

The module draws no randomness. The polynomial coefficients come from the
step's backend through `RandomBackend`, so the provider answers for the one
input whose quality matters.

It is a module rather than a crate. A crate in this workspace hides an
optional dependency behind a feature; this code has none and is always in the
binary.

## Checksums inside an encoding

`rite-model/src/bip39.rs` hashes a secret with `sha2`: a BIP-39 phrase ends
in the leading bits of the SHA-256 digest of its entropy. The digest is part
of the encoding, as paper32's parity is, and BIP-39 fixes the function, so
no provider could substitute another. It proves nothing and leaves the
function: a typed phrase either carries its checksum or is refused. `sha2`
is already how `rite-model` computes the transcript's commitments.

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

`rite-openssl` needs OpenSSL 3.5 or later, the first version with ML-DSA and
ML-KEM keys. Distributions still shipping 3.0, such as Ubuntu 24.04 and Debian
12, build with `--features openssl-vendored`, which bundles a current OpenSSL.
Every published binary does.

Wrapping to an ML-KEM key needs 3.6. A KEM key in Rite exists to be wrapped to,
and CMS carries an ML-KEM recipient in a `KEMRecipientInfo` (RFC 9629), which
OpenSSL implements from 3.6. A 3.5 build refuses by name to generate an ML-KEM
key or wrap to one. It still imports an ML-KEM key and carries it as a wrapped
payload. Debian 13 and Ubuntu 26.04 ship 3.5.

That line is fixed when `rite-openssl` compiles, not when it runs: the code
behind it sits behind a `cfg` resolved from the OpenSSL headers present at
build time, so no runtime check can recover it. Two pieces make it visible:

- `crates/rite-openssl/build.rs` derives the `ossl360` cfg from the version
  `openssl-sys` publishes through its `links` metadata. (`openssl-sys` is a
  direct dependency of `rite-openssl` for this reason alone, since `links`
  metadata reaches only direct dependents.)
- `rite_openssl::build_limitation(algorithm)` names what about this build
  prevents generating a given key, and `rite_openssl::ML_KEM_AVAILABLE`
  exposes the raw cfg behind it. Ask it wherever a useful alternative exists,
  such as skipping a test or warning during `rite check`, rather than waiting
  for an `UnsupportedAlgorithm` error mid-ceremony. `None` means this build
  does not limit the algorithm, which also covers one no build can generate,
  so it is a narrower question than whether the algorithm is supported at all.
  Keeping the answer in this crate is deliberate: it is the one that compiles
  the bindings.

## Checking the other build before you push

CI compiles both sides and a development machine sits on one, so code written
against an API only 3.6 has passes locally and fails on the `Test` job, which
links the distribution's 3.5. `RITE_OSSL360` replaces the detected answer:

```sh
RITE_OSSL360=0 cargo clippy -p rite-openssl --features vendored --all-targets -- -D warnings
RITE_OSSL360=0 cargo test -p rite-openssl --features vendored
```

This catches two things a local run otherwise cannot: an API the `openssl`
crate exposes only in the newer build, and a binding used only inside a
`cfg(ossl360)` block, which the older build reports as unused.

It overrides this crate's cfg and nothing else, so it answers whether the 3.5
side builds and refuses ML-KEM where it should, not whether it works against a
real 3.5 library. The `Test` job answers that, and the vendored `Build (smoke)`
job is the only place the `ossl360` tests run. That job also runs the two
commands above.
