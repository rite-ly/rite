#!/usr/bin/env bash
#
# Render the showcase demo ceremony's printed script, transcript, and
# post-ceremony report to docs/demo/, committed alongside the GIF as viewable
# sample outputs. The ritely.io website copies these static files as needed.
# Kept separate from record.sh so the prints (cheap, no tmux) can be refreshed
# without re-recording the GIF. Run it from anywhere:
#
#     docs/demo/render-prints.sh
#
# Requires the debug binary at target/debug/rite, so build it first:
# cargo build -p rite. Regenerate whenever the showcase ceremony, the
# script/report templates, or the vendored logo change.
#
# The script and report are branded with the project name and the logo
# vendored at docs/demo/logo.svg (see BRAND_NAME / LOGO below).
#
# The transcript and report come from a single headless run, so they agree on
# the same fingerprint. Both embed that run's wall-clock timestamps, so each
# regeneration produces a fresh diff.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
RITE="$REPO/target/debug/rite"
CEREMONY="$REPO/examples/showcase/demo.rite.yaml"

# Branding embedded in the printed script and report headers. The logo is
# vendored beside this script and encoded into the HTML as a self-contained
# data: URI, so the outputs stay portable once copied elsewhere.
BRAND_NAME="Rite-ly"
LOGO="$SCRIPT_DIR/logo.svg"

if [ ! -x "$RITE" ]; then
  echo "rite binary not found at $RITE" >&2
  echo "build it first: cargo build -p rite" >&2
  exit 1
fi

# The run's output directory lands in a temp dir, cleaned up on exit.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Printed protocol participants follow by hand.
"$RITE" script "$CEREMONY" \
  --brand-name "$BRAND_NAME" \
  --logo "$LOGO" \
  -o "$SCRIPT_DIR/demo-script.html"
echo "wrote $SCRIPT_DIR/demo-script.html"

# A headless run produces the transcript; keep it and the report rendered from
# it so the two agree on the same fingerprint.
"$RITE" run --frontend headless -o "$WORK" "$CEREMONY" >/dev/null
OUT=$(ls -d "$WORK"/*/ | head -1)
cp "$OUT/transcript.jsonl" "$SCRIPT_DIR/demo-transcript.jsonl"
echo "wrote $SCRIPT_DIR/demo-transcript.jsonl"
"$RITE" report "$OUT" \
  --brand-name "$BRAND_NAME" \
  --logo "$LOGO" \
  -o "$SCRIPT_DIR/demo-report.html"
echo "wrote $SCRIPT_DIR/demo-report.html"
