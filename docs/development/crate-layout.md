# Crate layout

```mermaid
flowchart TD
    cli[rite<br/>binary]
    ls[rite-ls<br/>language server]
    tui[rite-tui<br/>TEA frontend]
    stdlib[rite-stdlib<br/>default action set]
    openssl[rite-openssl<br/>backend impl]
    runtime[rite-runtime<br/>protocol, executor, transcript]
    resolver[rite-resolver<br/>YAML → IR, diagnostics]
    render[rite-render<br/>document generation]
    model[rite-model<br/>IR + transcript schema]
    sdk[rite-sdk<br/>backend traits, key types]

    cli --> tui
    cli --> runtime
    cli --> stdlib
    cli --> openssl
    cli --> render
    cli --> resolver
    tui --> runtime
    ls --> resolver
    stdlib --> runtime
    openssl --> sdk
    runtime --> sdk
    runtime --> model
    render --> model
    resolver --> model
```

| Crate           | Purpose                                                                                                                                             |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `rite-sdk`      | Backend traits and key-material types. The boundary any external backend implements against.                                                        |
| `rite-model`    | DSL IR (`Ceremony`, `Step`, `Prompt`, …) and the durable transcript schema (`StepFact`, `ResponseRecord`, …). Carries no executor or channel types. |
| `rite-resolver` | YAML resolution and lowering, diagnostics, parameter checks.                                                                                        |
| `rite-runtime`  | Channel protocol, executor, reporter, transcript sink, action trait and registry.                                                                   |
| `rite-stdlib`   | Default action set (verification, attestation, crypto, PKI).                                                                                        |
| `rite-openssl`  | OpenSSL-backed `Backend` implementation.                                                                                                            |
| `rite-tui`      | TEA-based interactive frontend (ratatui + crossterm).                                                                                               |
| `rite`          | `rite` binary; hosts the console and headless drivers and wires every crate above together.                                                         |
| `rite-render`   | Document generation: ceremony scripts and post-ceremony reports (HTML/PDF).                                                                          |
| `rite-ls`       | Language server for editor integration.                                                                                                             |

## Boundary rules

- A third-party verifier only needs `rite-model` to parse a transcript;
  the executor and channel types stay in `rite-runtime` for that reason.
- `rite-sdk` is the only crate a new backend has to depend on. Adding a
  backend must not pull in the executor or any frontend crate.
- Frontends depend on `rite-runtime` for the protocol vocabulary
  (`ExecEvent`, `UiCommand`) and on `rite-model` for the persisted types
  they render. They never reach into `rite-stdlib` or backend crates.

## Path safety

A ceremony file is untrusted input: it may be downloaded and run by an
operator who never read it. Any string that originates in a ceremony and
reaches the filesystem — an artifact id that becomes an output filename, a
material's `path:` value — must be confined so it cannot escape the directory
it belongs in (`../../…` traversal, an absolute path, or a symlink planted at
the destination).

Do not hand-roll these checks. Route every ceremony-derived path through
[`rite_model::safe_path`](../../crates/rite-model/src/safe_path.rs):

- `validate_component` / `safe_join` for a value that must be a single
  filename (artifact and output ids). The resolver validates these at load
  time; `OutputConfig::artifact_path` re-checks at the filesystem boundary so
  a new code path cannot reintroduce a traversal.
- `confine` for a value that may legitimately be a relative subpath but must
  stay within a known root (material `path:` under the ceremony directory).

These helpers are purely lexical. When *creating* a file at a confined path,
also open it with `create_new` (see `executor::write_new_file`) so a
pre-planted symlink cannot redirect the write and an existing file is never
clobbered.

For the contract between the runtime and a frontend, see
[`runtime-and-frontend.md`](./runtime-and-frontend.md).
