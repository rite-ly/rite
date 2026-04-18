# Contributing

## Local checks

Run these before pushing — they mirror CI exactly.

**Format check** (read-only):
```sh
cargo fmt --all -- --check
```

**Auto-fix formatting**:
```sh
cargo fmt --all
```

**Clippy** (`-D warnings` promotes all warnings to errors, same as CI):
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
