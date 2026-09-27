#!/usr/bin/env bash
#
# Set the workspace version for a release, and update every file that follows
# it: the workspace version and the internal crate requirements in Cargo.toml,
# the workspace entries of Cargo.lock, and the `$id` of the JSON Schemas under
# docs/schema/. Run it from anywhere:
#
#     scripts/set-version.sh 0.8.0
#
# It changes files only; review the diff and commit it as "Release <version>".

set -euo pipefail

VERSION=${1:-}
if [[ ! "$VERSION" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "usage: $0 <major.minor.patch>" >&2
  exit 1
fi
# Internal crates are published together at one version, so each requires the
# others at the current minor.
REQ="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

sed -i.bak \
  -e "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" \
  -e "/^rite-[a-z0-9]* = { path/s/version = \"[^\"]*\"/version = \"$REQ\"/" \
  Cargo.toml
rm Cargo.toml.bak

cargo update --workspace --quiet
RITE_UPDATE_SCHEMA=1 cargo test --quiet -p rite-model schema >/dev/null

git diff --stat
