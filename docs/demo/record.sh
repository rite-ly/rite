#!/usr/bin/env bash
#
# Record the demo ceremony, driving the `rite run` TUI with tmux, and render
# the README GIF. Records only the TUI (no shell prompt); the recording ends
# on the completion screen, which shows the transcript fingerprint. Produces
# docs/demo/demo.cast (asciinema player on the site) and docs/demo/demo.gif.
# Run it from anywhere:
#
#     docs/demo/record.sh
#
# Requires: asciinema, tmux, agg. Uses the debug binary at target/debug/rite,
# so build it first: cargo build -p rite-cli.
#
# `rite` runs directly inside asciinema in a fixed-size tmux pane (no expect
# layer), so the recording size matches what the TUI renders. Keys are sent
# with `tmux send-keys`; `wait_for` polls the pane for the expected text before
# acting. Every step is gated by a "Press Enter to start step N" prompt
# answered on the Ceremony tab.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)

SESSION=rite-demo
RITE="$REPO/target/debug/rite"
CAST="$REPO/docs/demo/demo.cast"
GIF="$REPO/docs/demo/demo.gif"
COLS=100
ROWS=30
PAUSE=1.2   # seconds to read each prompt before acting; kept uniform for even pacing

if [ ! -x "$RITE" ]; then
  echo "rite binary not found at $RITE" >&2
  echo "build it first: cargo build -p rite-cli" >&2
  exit 1
fi

# Stage the ceremony in a temp dir so its output directory lands outside the
# repo. Cleaned up on exit along with the tmux session.
WORK=$(mktemp -d)
trap 'tmux kill-session -t "$SESSION" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/examples"
cp "$REPO/examples/demo.rite.yaml" "$WORK/examples/demo.rite.yaml"

# Block until the visible pane matches a regex.
wait_for() {
  local pat=$1 i=0
  until tmux capture-pane -pt "$SESSION" 2>/dev/null | grep -qE "$pat"; do
    sleep 0.2
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
      echo "timeout waiting for: $pat" >&2
      tmux capture-pane -pt "$SESSION" >&2 || true
      exit 1
    fi
  done
}

key() { tmux send-keys -t "$SESSION" "$@"; }

tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -x "$COLS" -y "$ROWS" -c "$WORK"
tmux set-option -t "$SESSION" status off

# Record only `rite run` (no shell). --quiet drops asciinema's banner.
key "asciinema rec --quiet --overwrite --command '$RITE run examples/demo.rite.yaml' $CAST" Enter
echo "started..."

# The waits below are coupled to examples/demo.rite.yaml: the step count,
# order, and the prompt substrings must match it, or wait_for hits its timeout.
#
# Launch lands on the Overview tab; the prompts live on the Ceremony tab.
wait_for "steps in this ceremony"; sleep "$PAUSE"; key Tab
wait_for "start the ceremony";     sleep "$PAUSE"; key Enter

# Step 1 - verify_air_gap
wait_for "start step 1";           sleep "$PAUSE"; key Enter
wait_for "network connections";    sleep "$PAUSE"; key "y"

# Steps 2-4 - keypair / CSR / certificate (run automatically)
wait_for "start step 2";           sleep "$PAUSE"; key Enter
wait_for "start step 3";           sleep "$PAUSE"; key Enter
wait_for "start step 4";           sleep "$PAUSE"; key Enter

# Step 5 - witness_attest: start, read the statement, type, pause, confirm.
wait_for "start step 5";           sleep "$PAUSE"; key Enter; sleep "$PAUSE"; key "attest"; sleep "$PAUSE"; key Enter

# Step 6 - officer_attest
wait_for "start step 6";           sleep "$PAUSE"; key Enter; sleep "$PAUSE"; key "attest"; sleep "$PAUSE"; key Enter

# Completion screen.
wait_for "fingerprint";            sleep "$PAUSE"; key Enter

tmux kill-session -t "$SESSION" 2>/dev/null || true
echo "wrote $CAST"

# Render the README GIF from the cast, then shrink it with gifsicle
if command -v agg >/dev/null 2>&1; then
  agg --quiet --theme github-dark --last-frame-duration 3 "$CAST" "$GIF"
  echo "wrote $GIF"
  if command -v gifsicle >/dev/null 2>&1; then
    gifsicle -O3 --colors 128 "$GIF" -o "$GIF"
    echo "optimized $GIF"
  else
    echo "gifsicle not found; skipping GIF optimization" >&2
  fi
else
  echo "agg not found" >&2
fi
