#!/usr/bin/env bash
# CycloneDX SBOMs for the two binaries cargo-dist ships.
#
# cargo-dist 0.32.0's `cargo-cyclonedx = true` generates a GitHub Actions
# step that uploads `${{ steps.cargo-cyclonedx.output.paths }}`. The
# singular `output` is empty, so the `.cdx.xml` files never enter the
# artifact set; a sibling `find | mv` into its own search tree fails on
# GNU mv. Extra-artifacts go through dist's checksum/manifest/Release
# path instead, so we never take that generated step.
#
# Dist 0.32 also installs cargo-cyclonedx 0.5.5, which cannot parse
# Cargo.lock format version 4: the SBOM is written, hashes are omitted.
# 0.5.7 is the first release that reads v4; we pin 0.5.9.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo >/dev/null || {
  echo "generate-sboms.sh needs cargo on PATH" >&2
  exit 1
}

PIN=0.5.9
if ! cargo cyclonedx -V 2>/dev/null | grep -Fq "$PIN"; then
  curl --proto '=https' --tlsv1.2 -LsSf \
    "https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-${PIN}/cargo-cyclonedx-installer.sh" | sh
fi

# cargo-cyclonedx has no --package filter: it writes `{crate}.cdx.xml` next
# to every workspace member. Do not pass --override-filename; that stamps
# the same basename onto every crate.
cargo cyclonedx --format xml

outdir=target/sbom
mkdir -p "$outdir"

keep() {
  local src=$1 dest=$2
  [ -f "$src" ] || {
    echo "cargo-cyclonedx did not write $src" >&2
    exit 1
  }
  grep -q '<hash' "$src" || {
    echo "$src has no component hashes" >&2
    exit 1
  }
  mv "$src" "$dest"
}

keep crates/proxy/pgmask.cdx.xml "$outdir/pgmask.cdx.xml"
keep crates/classify/classify.cdx.xml "$outdir/classify.cdx.xml"

# Drop the members we do not ship so a local run is not a dirty tree.
find crates -name '*.cdx.xml' -delete
