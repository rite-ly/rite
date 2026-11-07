# Testing strategy

What we test, at which level, and where it lives in the tree. The rationale lives in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md#testing).

## Stability tiers

Crates do not all carry the same promise, so they are not tested the same way. Two kinds
of compatibility are in play and must not be conflated:

- **API compatibility** (Rust types and signatures). Broken freely at 0.x. Tests assert
  behavior, never the exact shape of an API, so a refactor touches one call site, not fifty
  assertions.
- **Format compatibility** (transcript, DSL schema, rendered documents). A data contract with
  the outside world: a transcript produced today must still `rite verify` tomorrow, and a
  ceremony written against the documented DSL must keep parsing, unless we deliberately bump the
  `version` field. Format changes are intentional and reviewed, never incidental.

| Tier             | Crates                                                         | Promise at 0.x                                                                   | Emphasis                                      |
|------------------|----------------------------------------------------------------|----------------------------------------------------------------------------------|-----------------------------------------------|
| **A (Contract)** | `rite-sdk`, `rite-model`                                       | API breakable; **wire strings and transcript/DSL format change only on purpose** | Contract tests + golden snapshots, mandatory  |
| **B (Core)**     | `rite-resolver`, `rite-runtime`, `rite-stdlib`, `rite-openssl` | No API promise; refactor freely                                                  | Unit + integration on behavior, not structure |
| **C (Edges)**    | `rite-tui`, `rite-render`, `rite-ls`, `rite`                   | No promise                                                                       | Snapshots + smoke + manual                    |

The MSRV CI job already pins only the published library floor (`rite-sdk`, `rite-model`,
`rite-resolver`); binaries float with stable Rust. Keep the two consistent.

## Levels and where they go

| Level             | In this project                                                                                                                 | Rust location                                                                |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| Unit              | Resolver lowering, expression eval, entropy ratchet, path safety, action input parsing                                          | Inline `#[cfg(test)] mod tests`. The only level that may touch private items |
| Integration       | A crate through its public API (a stdlib action + the real OpenSSL backend producing parseable DER; `analyze()` over a fixture) | `crates/<c>/tests/`. Public API only                                         |
| End-to-end        | A whole ceremony from YAML to transcript via the headless driver; the CLI as a subprocess; the example smoke tests              | `tests/` in `rite`; `assert_cmd` for subprocess                              |
| Contract / golden | Wire strings (enum `serde`/`Display`) and transcript / diagnostic / rendered-doc snapshots                                      | Table tests + `insta`                                                        |
| Property          | Round-trips, path confinement never escaping its root, resolver never panicking                                                 | `proptest`, selectively                                                      |
| Manual            | YubiKey/TPM device flows, the TUI, operator ergonomics                                                                          | `#[ignore]`d tests + `docs/` checklists                                      |

Notes that are easy to get wrong:

- **Default a new test to `tests/`.** Drop to an inline unit test only when you must assert a
  private invariant. The `tests/` location also catches anything accidentally left `pub`.
- **Doc tests are under-used on `rite-sdk` and `rite-model`.** A public item an external backend
  or verifier calls should carry a runnable `/// ```` example; treat a missing one on a new
  public item as a review nit.
- **Shared harness code** (e.g. `rite_runtime::test_support::ReporterHarness`) lives behind a
  `test_support` module so other crates' integration tests reuse it instead of duplicating setup.
- **Probes that read the running system** (platform, network, security features) are checked
  against files captured on real systems, under `crates/rite-stdlib/tests/fixtures/probes/`; the
  module comment of `rite-stdlib`'s `verification/probe_fixtures.rs` says how to add one.
- **A test lives in the crate that owns what it needs.** If it names an API behind a `cfg` or a
  feature, it belongs where that gate is decided. The post-quantum import sweep sits in
  `rite-openssl` because `ossl360` is set there; written in `rite-stdlib` it would fail to compile
  against OpenSSL 3.5, and a runtime skip cannot save a reference that must compile first.

## Naming

A test name is a sentence about behavior in `snake_case`, with no `test_` prefix. The attribute
already says it is a test, and the name is what a failure report shows.

```
unwrap_refuses_a_kek_that_did_not_wrap_the_key
resolving_an_unknown_artifact_fails
a_csr_keeps_the_subject_alternative_names_it_was_given
```

Name the claim, not the function under test. `delete_key_removes_it_from_the_listing` says what
broke; `test_delete_key` only says where to look.

## Coverage expectations

Most code needs no coverage mandate: assert behavior where it has value and stop. But four
surfaces are *extensible*, contributors add entries to them, and a gap there ships broken
behavior silently. Each new entry arrives with a test:

- **Every stdlib action**: at least one test that executes it and asserts the artifact or fact it
  produces, not merely that a ceremony using it exits 0.
- **Every backend**: a test per trait method it implements, including the failure shape, not only
  the success path.
- **Every resolver diagnostic**: a test that the offending input produces it, at the right span.
- **Every cryptographic algorithm**: a static vector, `f(input) == literal`, taken from an RFC, a
  FIPS document, or a cross-check against the `openssl` CLI, with the source named in a comment. A
  round-trip proves the code agrees with itself; only a vector proves it agrees with the standard.

These are registries contributors extend by adding an entry. Rendered prose (duty descriptions,
step instructions, prompts, report sections) is deliberately *not* on this list: it is covered
wholesale by the render snapshots, not by a per-item rule.

A smoke test that runs an action (the example ceremonies) does not satisfy this. It proves the
action does not crash, not that it does the right thing, those are different claims.

## Golden tests (insta)

Use `insta` for any assertion whose expected value is a document or a serialized structure,
rather than hand-built string equality: transcript JSONL (Tier A), resolver diagnostics, rendered
scripts and reports, CLI stdout/stderr.

- Review with `cargo insta review`; commit `.snap` files. A snapshot diff is a prompt to confirm
  the change was intended, especially for Tier-A outputs.
- Normalize nondeterminism (timestamps, temp paths, nonces) before snapshotting, so a diff always
  means a real change. The executor `Clock` and the entropy seed are the injection points.
- Prefer one snapshot of a meaningful whole (a full transcript) over many fragment snapshots.

## Example ceremonies

Everything under `examples/` is a test fixture. `crates/rite/tests/examples.rs` discovers every
`*.rite.yaml` and asserts each one passes `rite check` and completes `rite run --dry-run` through
the mock backend. New examples are covered automatically; they are discovered, not enumerated. An
example that stops resolving or running is a failed build, so examples cannot rot.

The one exception is an example with an `enter_share` step, which passes `rite check` and is left
out of the dry run: no made-up value is a share, so the step stops a headless run. Such an example
needs a test of its own that types its sheets back, as `crates/rite-stdlib/tests/actions.rs` does
for `recover_from_paper`.

## The algorithm matrix

`crates/rite-stdlib/tests/algorithms/` records what the cryptographic steps do with the key
types and forms listed in its tables. It is organized in families, each a pair of steps that
write and read one kind of artifact:

- `wrapping/`: `wrap_key` and `encrypt_data` write, `unwrap_key` and `decrypt_data` read;
- `signatures/`: `sign_data` writes, `verify_signature` reads.

Each family has its own table (`cases.rs`), fixtures, and coverage checks. The families share
the keys (`keys.rs`), the outcome vocabulary (`outcome.rs`), and the harness. Each row names a
step, a key, and the expected outcome under each policy level. The default level represents a
ceremony that declares no policy. Rows state what Rite does today.

A case's steps form a ceremony, and meet what a ceremony's would, in order. Before each step
runs, the steps so far are validated as `rite check` validates a file, so an algorithm or scheme
Rite has no name for is refused there, with the message an operator sees. The step then runs as
the resolver planned it, through the function the executor runs every step with, so its handler,
params, backend and errors are a real run's. What the matrix leaves out is the run around the
steps: the operator, the transcript file and the outputs on disk, which the end-to-end tests in
`crates/rite/tests/` cover. A key the backend holds is imported from the committed file or
generated by `generate_key`, as the row says. A public key arrives as its SPKI DER file in the
algorithm rows; a short shape table per family gives one key in every other form a step reads: PEM, a certificate as DER or PEM, a public key or certificate artifact, and a held
keypair. A signature from elsewhere is verified both in software and through the backend, since
naming a backend changes who checks and never what is accepted. The record states which ran;
the matrix cannot tell the two apart otherwise, since both call the same OpenSSL function.

An outcome is something written, something read, or a refusal. A written CMS form names its
standard algorithm identifiers, checked against the container bytes, the artifact, and the
operation fact the step records in the transcript. The container must name its recipient as a
third party computes it: a public key by the SHA-256 of its SPKI, a symmetric key by its check
value. A signature names the algorithm Rite records and its scheme as the OpenSSL command line
runs it, with the shape of its bytes. The operation fact must also name the keys involved and
the backend that ran it, and a read step that opens must record what it opened and what it
recovered. A refusal names its stage (`Check`, `Import`, `Generate` or `Step`),
whether it is `Unsupported` or `Refused`, and a message fragment that identifies the reason. The
refused step must record no operation. The fragment is part of the contract because it is what
the operator reads.

Unsupported forms are rows too. When Rite gains support, the old expected refusal fails until
the row is updated. Row names identify the step, path, key and scheme, not the outcome. The
outcome changes as support changes, so row names are an exception to the sentence-style test
naming rule above.

A successful write has a test where Rite reads it back (`::read_back`, `::verify_back`). Where
the OpenSSL command line can read the output independently, it also has `::openssl_opens` or
`::openssl_verifies`. Keys and fixtures are committed under `tests/algorithms/fixtures/`;
[`fixtures/README.md`](../../crates/rite-stdlib/tests/algorithms/fixtures/README.md) describes
them and how to regenerate them. Each container row lists OIDs that must or must not occur in
its bytes. The check searches for their DER encodings; it does not verify their positions in the
CMS structure. Each signature fixture must have the shape its scheme states before it is
verified. A case this build cannot run is skipped with the reason as its label; with
`RITE_MATRIX_REQUIRE_BUILD` set, as in the vendored OpenSSL CI job, a case the build would skip
fails instead.

The `coverage::` tests check that every key and scheme has the required rows, and that every
form Rite writes is read from a fixture another implementation wrote. In the wrapping family, a
form with no such fixture appears in a list of gaps with a reason, and every listed gap still
fails to open. The shared checks compare fixture files with the tables, Rite's algorithms with
the test keys, and test names for repeats. Tampering, wrong keys and malformed input belong in
error-mode tests, not in these algorithm rows. The matrix does not replace the primitive test
vectors of a named standard, such as RFC 3394 and RFC 5649 for AES key wrap or the ML-DSA known
answers, which stay in `rite-openssl`'s own tests.

Each row runs as its own `libtest-mimic` test:

```sh
cargo test -p rite-stdlib --test algorithms -- kari
cargo test -p rite-stdlib --test algorithms -- verify_signature::
```

To add an algorithm, add its key to `keys.rs`, add the rows the coverage tests ask for, and
regenerate with `RITE_REGENERATE_FIXTURES=1`, which writes the new key and fixtures and leaves
every committed file as it is. To add a family, add a module that exports a `Family` and list
it in `FAMILIES` in `main.rs`.

## What not to test

These cost maintenance and catch nothing. Remove on sight; do not add.

- **Fixture-count mirroring.** `assert_eq!(resolved.roles.len(), 3)` restates the fixture and
  breaks on every benign edit. Assert the property instead (resolves cleanly, a named role
  exists). Counting is fine only when the count *is* the behavior (e.g. "this input lowers to
  exactly two `after` duties").
- **The compiler's job.** Enum exhaustiveness, that a struct has a field, that a `match` is total.
- **Trivial internal mappings.** A `Display`/`as_str` with no external meaning needs no
  per-variant test. The test for whether a per-variant table is worth it: *does this string
  appear in YAML, a transcript, or a filename?* If yes it is a contract test (level 4) and
  exhaustive coverage is the point; if no, skip it.
- **The mock.** Exercising a mock and asserting it behaves as written tests nothing. Mocks are
  scaffolding for testing callers.

## Error modes

Error modes are first-class in the runtime, so they are first-class here. For every recoverable
path the model defines (retry, abort, a failed attestation, a missing artifact, a path-traversal
attempt in a ceremony file) there is a test that the failure is surfaced as the model promises,
not only that the happy path works.

## Running

```sh
cargo test --workspace        # everything CI runs
cargo test -p rite-runtime    # one crate
cargo test --doc              # doc tests only
cargo test -- --ignored --test-threads=1   # hardware/manual tests (need devices), one at a time
cargo insta review            # accept/reject snapshot changes

RITE_OSSL360=0 cargo test -p rite-openssl   # as the OpenSSL 3.5 CI runner sees it
```

A dev machine usually links a newer OpenSSL than the `Test` job does, so code behind `ossl360`
compiles locally and breaks in CI. Run that last line before pushing anything that touches
`rite-openssl`.
