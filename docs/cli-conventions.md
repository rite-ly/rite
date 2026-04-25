# CLI Conventions

Scope: `crates/rite-cli`.

## Exit codes

- `0`: success
- `1`: command/domain/runtime failure
- `2`: CLI usage and argument parsing errors

## Output channels

- `stdout`: successful user-consumable command output
- `stderr`: diagnostics, warnings, errors, and progress/status messages

## Input key normalization

- User-provided input keys should be normalized consistently across all input sources.
- This includes CLI flags (`--param`, `--role`, `--material`) and environment variables (`RITE_PARAM_*`, `RITE_ROLE_*`, `RITE_MATERIAL_*`).

## Interactive prompting

- Interactive prompts are enabled by default for interactive commands.
- Commands may provide explicit flags to disable prompting (for example `--no-prompt`).
