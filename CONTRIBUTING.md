# Contributing

Rite is early-stage and the design is still evolving. 
Pull requests are welcome, but opening an issue to discuss the change first is strongly preferred, it avoids wasted effort on both sides.

CLI behavior conventions are documented in `docs/development/cli-conventions.md`.
Runtime and frontend architecture is documented in `docs/development/runtime-and-frontend.md`,
crate layout in `docs/development/crate-layout.md`, and the testing strategy in
`docs/development/testing.md`.

## AI-assisted contributions

Contributions assisted by AI tools, including LLMs and coding agents, are not forbidden and are
not held to a different bar than any other contribution. The same rule applies either way: it
must follow every guideline in this document and in `docs/development/`, and a human must
carefully read, understand, and stand behind the change before opening an issue or PR.

Mentioning that AI tooling helped in the PR or issue description is welcome, as an additional
datapoint for any contribution, not as a compliance step.

## Development setup

Requires Rust 1.88+ and `libssl-dev` (OpenSSL headers).

```sh
cargo build -p rite --features openssl-vendored
cargo run -p rite -- check examples/showcase/demo.rite.yaml
cargo run -p rite -- run examples/showcase/demo.rite.yaml
```

## Local checks

Run these before pushing.

**Format check**:
```sh
cargo fmt --all -- --check
```

**Auto-fix formatting**:
```sh
cargo fmt --all
```

**Clippy**:
```sh
cargo clippy --workspace --all-targets -- -D warnings
```

**Tests**:
```sh
cargo test --workspace
```

**All at once**:
```sh
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

## Testing

A test earns its place by proving a property we care about, not by mirroring the shape of the
code or the fixtures. A test that only restates what the compiler already guarantees, or that
breaks on every benign edit, is a liability. This reflects the project itself: evidence over
execution.

What to test, at which level, and where it goes in the tree is set out in
`docs/development/testing.md`. Follow it when adding tests; reviewers hold PRs to it.
