#!/usr/bin/env bash
#
# Render the showcase demo ceremony's sample outputs to docs/demo/, committed
# alongside the GIF: the printed script, the evidence bundle of one run, its
# public disclosure, and the report of each. docs/demo/README.md describes
# them. The ritely.io website copies these static files as needed.
# Kept separate from record.sh so the prints (cheap, no tmux) can be refreshed
# without re-recording the GIF. Run it from anywhere:
#
#     docs/demo/render-prints.sh
#
# Requires Docker: the run happens in a container (container.sh). Regenerate
# after the release commit, whenever the showcase ceremony, the
# script/report templates, the transcript format, or the vendored logo change.
#
# The script and reports are branded with the project name and the logo
# vendored at docs/demo/logo.svg (see BRAND_NAME / LOGO below).
#
# The bundle, the disclosure and both reports come from a single headless run,
# so they agree on the same fingerprint. They embed that run's wall-clock
# timestamps and random values, so each regeneration produces a fresh diff.

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

# The run's output directory lands in a temp dir, cleaned up on exit.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# shellcheck source-path=SCRIPTDIR source=container.sh
. "$SCRIPT_DIR/container.sh"
build_demo_image
cp "$CEREMONY" "$WORK/demo.rite.yaml"

# Printed protocol participants follow by hand.
"$RITE" script "$CEREMONY" \
  --brand-name "$BRAND_NAME" \
  --logo "$LOGO" \
  -o "$SCRIPT_DIR/demo-script.html"
echo "wrote $SCRIPT_DIR/demo-script.html"

# One headless run, packed with the ceremony it ran from.
rite_in_container "$WORK" run --frontend headless -o out demo.rite.yaml >/dev/null
OUT=$(ls -d "$WORK"/out/*/ | head -1)
rm -rf "$SCRIPT_DIR/demo-bundle" "$SCRIPT_DIR/demo-disclosure"
"$RITE" bundle create "$OUT" --definition "$CEREMONY" -o "$SCRIPT_DIR/demo-bundle" >/dev/null
echo "wrote $SCRIPT_DIR/demo-bundle/"

# Its public disclosure: every fact above public withheld, same fingerprint.
"$RITE" bundle disclose "$SCRIPT_DIR/demo-bundle" --level public \
  -o "$SCRIPT_DIR/demo-disclosure" >/dev/null
echo "wrote $SCRIPT_DIR/demo-disclosure/"

# A report of each: the complete record, and what the public sees.
"$RITE" report "$SCRIPT_DIR/demo-bundle" \
  --brand-name "$BRAND_NAME" \
  --logo "$LOGO" \
  -o "$SCRIPT_DIR/demo-report.html"
echo "wrote $SCRIPT_DIR/demo-report.html"
"$RITE" report "$SCRIPT_DIR/demo-disclosure" \
  --brand-name "$BRAND_NAME" \
  --logo "$LOGO" \
  -o "$SCRIPT_DIR/demo-disclosure-report.html"
echo "wrote $SCRIPT_DIR/demo-disclosure-report.html"
