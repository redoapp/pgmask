#!/usr/bin/env bash
# Repository invariants nothing else looks at: version agreement, changelog
# order, and evidence that must not go untracked.
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

# proptest writes the seed of a failing case into a `.proptest-regressions`
# file, and those replay before any new case is generated — a defect found once
# stays pinned. An untracked one is a finding sitting on a single machine, which
# is what happened to the ROLLUP-alias seed for two releases after an ignore
# rule was added in the same commit as the first such file.
loose=$(git ls-files --others --exclude-standard '*.proptest-regressions')
if [ -n "$loose" ]; then
  note "proptest regression seeds are untracked, so they exist only here:"
  echo "$loose" | sed 's/^/  /'
fi

# Every `scripts/…` path the documentation names has to exist.
#
# Renaming a script is the realistic way documentation goes wrong here — this
# file was `check-release-metadata.sh` an hour ago. Deliberately narrow: a
# general "does every backticked path exist" check flags `pg_query.rs`, which is
# a crate name, and a check that cries wolf gets overridden wholesale.
for named in $(grep -rhoE 'scripts/[A-Za-z0-9_.-]+\.(sh|py)' README.md CONTRIBUTING.md docs/*.md crates 2>/dev/null | sort -u); do
  [ -e "$named" ] || note "documentation names $named, which does not exist"
done

# The README's suite count, against the gate's actual one.
#
# It said "thirteen suites ... 265 cargo tests" while the gate ran 20 and 505.
# Nobody noticed for seven releases, and it is the first number a reader meets:
# a front page that undercounts by a third is the same class of wrong as a test
# that does not run, just aimed at a person instead of a machine.
#
# Counted as: every `record "..."` that is not the `run()` helper's own, plus
# every `run "..."`. Written as a digit in the README so this can find it.
suites=$(( $(grep -oE 'record "[^"$][^"]*"' scripts/test-all.sh | wc -l) \
         + $(grep -oE '^[[:space:]]*run "[^"]*"' scripts/test-all.sh | wc -l) ))
claimed=$(grep -oE 'runs [0-9]+ suites' README.md | grep -oE '[0-9]+' | head -1)
[ "${claimed:-none}" = "$suites" ] ||
  note "README claims the gate runs ${claimed:-no stated number of} suites; it runs $suites."

# The disclosure count, against the tables it summarises.
#
# The README said "six disclosures" for four releases after there were nine, and
# when I wrote the sentence fixing it I asserted a channel count of fourteen
# without counting the rows. It is thirteen. Both are the same mistake this
# repository keeps finding, so both get a check rather than a promise.
channels=$(grep -cE '^\| ([1-9]|7[a-d]|9[ab]) \|' docs/safety-assessment.md)
claimed_readme=$(grep -oE '(the )?(six|seven|eight|nine|ten|[0-9]+) disclosures' README.md | head -1)
case "$claimed_readme" in
  *nine*) ;;
  "")     note "README no longer states a disclosure count; the tables list $channels channels." ;;
  *)      note "README says '$claimed_readme'; the tables list $channels channels under 9 numbers." ;;
esac
grep -qE "that is $channels, " docs/safety-assessment.md ||
  note "the assessment's channel count does not match its own tables ($channels rows)."

# Cargo.lock's copy of the workspace version.
#
# Nothing bumped it, so it trailed the real version by however many releases had
# happened since the last `cargo build` that someone remembered to commit. Not a
# correctness problem — cargo rewrites it on the next build — but it means a
# checkout's lockfile disagrees with its own manifest, and a reviewer cannot
# tell a stale lockfile from a deliberate pin.
locked=$(grep -A1 '^name = "pgmask"' Cargo.lock | grep -oE '"[0-9.]+"' | tr -d '"' | head -1)
[ "${locked:-none}" = "$cargo_version" ] ||
  note "Cargo.lock says pgmask ${locked:-nothing}; Cargo.toml says $cargo_version. Run cargo build."

[ "$fail" = 0 ] &&
  echo "repo invariants ok: v$cargo_version, $total entries, descending, seeds tracked"
exit "$fail"
