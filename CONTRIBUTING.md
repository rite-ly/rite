# Contributing

Rite is early-stage and the design is still evolving. 
Pull requests are welcome, but opening an issue to discuss the change first is strongly preferred, it avoids wasted effort on both sides.

CLI behavior conventions are documented in `docs/development/cli-conventions.md`.
Runtime and frontend architecture is documented in `docs/development/runtime-and-frontend.md`,
crate layout in `docs/development/crate-layout.md`.

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
