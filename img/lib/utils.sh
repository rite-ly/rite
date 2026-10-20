# shellcheck shell=bash
# img/lib/utils.sh
# Output helpers for the build scripts. They follow the rite CLI conventions in
# docs/development/cli-conventions.md: a command's result goes to stdout,
# progress and errors go to stderr, a usage error exits 2 and any other failure
# exits 1. Each script sets PROG to its command name before sourcing this file.

VERBOSE="${RITE_VERBOSE:-false}"

# A progress line.
note() { echo "$*" >&2; }

# An error that ends the command.
die() {
    echo "$PROG: $*" >&2
    exit 1
}

# A usage error.
usage_error() {
    echo "$PROG: $*" >&2
    echo "Run '$PROG --help' for usage." >&2
    exit 2
}

# Called as `need_value "$@"` from an option's case branch: a usage error when
# the option has no value.
need_value() {
    [[ $# -ge 2 && -n "$2" ]] || usage_error "$1 needs a value"
}

# Runs a tool whose output is detail. With --verbose the output goes to stderr;
# otherwise it is kept, and its end shown only if the tool fails.
quietly() {
    if [[ "$VERBOSE" == true ]]; then
        "$@" >&2 || die "$1 failed"
        return
    fi
    local log
    log=$(mktemp)
    if ! "$@" >"$log" 2>&1; then
        tail -n 40 "$log" >&2
        rm -f "$log"
        die "$1 failed (its last 40 lines are above; --verbose shows all of its output)"
    fi
    rm -f "$log"
}
