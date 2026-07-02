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
  `version:` field. Format changes are intentional and reviewed, never incidental.

| Tier | Crates | Promise at 0.x | Emphasis |
|---|---|---|---|
| **A (Contract)** | `rite-sdk`, `rite-model` | API breakable; **wire strings and transcript/DSL format change only on purpose** | Contract tests + golden snapshots, mandatory |
| **B (Core)** | `rite-resolver`, `rite-runtime`, `rite-stdlib`, `rite-openssl` | No API promise; refactor freely | Unit + integration on behavior, not structure |
| **C (Edges)** | `rite-tui`, `rite-render`, `rite-ls`, `rite` | No promise | Snapshots + smoke + manual |

The MSRV CI job already pins only the published library floor (`rite-sdk`, `rite-model`,
`rite-resolver`); binaries float with stable Rust. Keep the two consistent.

## Levels and where they go

| Level | In this project | Rust location |
|---|---|---|
| Unit | Resolver lowering, expression eval, entropy ratchet, path safety, action input parsing | Inline `#[cfg(test)] mod tests`. The only level that may touch private items |
| Integration | A crate through its public API (a stdlib action + the real OpenSSL backend producing parseable DER; `analyze()` over a fixture) | `crates/<c>/tests/`. Public API only |
| End-to-end | A whole ceremony from YAML to transcript via the headless driver; the CLI as a subprocess; the example smoke tests | `tests/` in `rite`; `assert_cmd` for subprocess |
| Contract / golden | Wire strings (enum `serde`/`Display`) and transcript / diagnostic / rendered-doc snapshots | Table tests + `insta` |
| Property | Round-trips, path confinement never escaping its root, resolver never panicking | `proptest`, selectively |
| Manual | YubiKey/TPM device flows, the TUI, operator ergonomics | `#[ignore]`d tests + `docs/` checklists |

Notes that are easy to get wrong:

- **Default a new test to `tests/`.** Drop to an inline unit test only when you must assert a
  private invariant. The `tests/` location also catches anything accidentally left `pub`.
- **Doc tests are under-used on `rite-sdk` and `rite-model`.** A public item an external backend
  or verifier calls should carry a runnable `/// ```` example; treat a missing one on a new
  public item as a review nit.
- **Shared harness code** (e.g. `rite_runtime::test_support::ReporterHarness`) lives behind a
  `test_support` module so other crates' integration tests reuse it instead of duplicating setup.

## Coverage expectations

Most code needs no coverage mandate: assert behavior where it has value and stop. But four
surfaces are *extensible*, contributors add entries to them, and a gap there ships broken
behavior silently. Each new entry arrives with a test:

- **Every stdlib action**: at least one test that executes it and asserts the artifact or fact it
  produces, not merely that a ceremony using it exits 0.
- **Every backend**: a test per trait method it implements, including the failure shape, not only
  the success path.
- **Every resolver diagnostic**: a test that the offending input produces it, at the right span.

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
cargo test -- --ignored       # hardware/manual tests (need devices)
cargo insta review            # accept/reject snapshot changes
```
