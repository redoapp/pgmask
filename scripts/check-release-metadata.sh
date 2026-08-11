#!/usr/bin/env bash
# Check the three places a version is written agree, and that the changelog
# reads newest-first.
#
# `## 0.1.30` sat above every later entry for seven releases. Nothing looked:
# the gate runs fmt, clippy, audit, rustdoc and eighteen test suites, and none
# of them read prose. It is a small thing, but a changelog whose order cannot be
# trusted is one nobody reads, and this file is the project's audit trail.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
note() {
  echo "FAIL: $*"
  fail=1
}

cargo_version=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
changelog_top=$(grep -m1 '^## ' CHANGELOG.md | sed 's/^## \([0-9.]*\).*/\1/')
readme_version=$(grep -om1 '\*\*v[0-9][0-9.]*\*\*' README.md | tr -d '*v')

[ -n "$cargo_version" ] || note "no version in Cargo.toml"
[ "$changelog_top" = "$cargo_version" ] ||
  note "CHANGELOG leads with $changelog_top, Cargo.toml says $cargo_version"
[ "$readme_version" = "$cargo_version" ] ||
  note "README says v$readme_version, Cargo.toml says $cargo_version"

# Newest first. `sort -V -r` gives the order these should already be in, so any
# difference is a heading out of place.
versions=$(grep '^## ' CHANGELOG.md | sed 's/^## \([0-9.]*\).*/\1/')
if [ "$versions" != "$(echo "$versions" | sort -V -r)" ]; then
  note "CHANGELOG headings are not in descending order:"
  diff <(echo "$versions") <(echo "$versions" | sort -V -r) | head -10
fi

# Every heading has to parse as a version, or the comparison above silently
# compares empty strings and passes.
count=$(echo "$versions" | grep -c '^[0-9][0-9.]*$')
total=$(grep -c '^## ' CHANGELOG.md)
[ "$count" = "$total" ] ||
  note "$((total - count)) of $total CHANGELOG headings are not a bare version"

[ "$fail" = 0 ] && echo "release metadata ok: v$cargo_version, $total entries, descending"
exit "$fail"
