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
# Both documents that state the count, not just the README: the assessment said
# 17 while the gate ran 21, four releases after the README had been corrected.
for doc in README.md docs/safety-assessment.md; do
  claimed=$(grep -oE '(runs|—) [0-9]+ suites' "$doc" | grep -oE '[0-9]+' | head -1)
  [ "${claimed:-$suites}" = "$suites" ] ||
    note "$doc claims $claimed suites; the gate runs $suites."
done

# The disclosure count, against the tables it summarises.
#
# The README said "six disclosures" for four releases after there were nine, and
# when I wrote the sentence fixing it I asserted a channel count of fourteen
# without counting the rows. It is thirteen. Both are the same mistake this
# repository keeps finding, so both get a check rather than a promise.
# Both numbers are derived, not written down twice. The first version of this
# check hardcoded "nine" and a regex that could not match a two-digit
# disclosure, so adding number 10 would have left it passing while counting 13
# of 14 rows — a drift gate with the drift built in.
rows=$(grep -oE '^\| [0-9]+[a-d]? \|' docs/safety-assessment.md)
channels=$(printf '%s\n' "$rows" | grep -c .)
numbered=$(printf '%s\n' "$rows" | grep -oE '[0-9]+' | sort -un | grep -c .)
word() { case "$1" in
  6) echo six ;; 7) echo seven ;; 8) echo eight ;; 9) echo nine ;;
  10) echo ten ;; 11) echo eleven ;; 12) echo twelve ;; *) echo "$1" ;;
esac; }
expected_word=$(word "$numbered")
claimed_readme=$(grep -oE '(the )?(six|seven|eight|nine|ten|eleven|twelve|[0-9]+) disclosures' README.md | head -1)
case "$claimed_readme" in
  *"$expected_word"*) ;;
  "")     note "README no longer states a disclosure count; the tables list $numbered." ;;
  *)      note "README says '$claimed_readme'; the tables list $numbered ($expected_word), $channels channels." ;;
esac
grep -qE "that is $channels, " docs/safety-assessment.md ||
  note "the assessment's channel count does not match its own tables ($channels rows)."
grep -qE "\b$expected_word disclosures\b" docs/safety-assessment.md ||
  note "the assessment does not state '$expected_word disclosures'; its tables list $numbered."

# The TLS suite's check count, which the README quotes.
#
# It said 7 while the suite ran 18, having grown a downgrade section — and one
# of the original 7 had been failing for several commits while the README
# reported all of them passing. Count the call sites rather than the claim.
tls_checks=$(grep -cE '^ *(check|refute) ' scripts/test-tls.sh)
claimed_tls=$(grep -oE '[0-9]+ TLS,' README.md | grep -oE '[0-9]+')
[ "${claimed_tls:-$tls_checks}" = "$tls_checks" ] ||
  note "README says $claimed_tls TLS checks; test-tls.sh has $tls_checks."

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

# Every released version needs its tag.
#
# Tagging is a separate command from committing, and I stopped doing it after
# v0.1.52 without noticing for fourteen releases. The changelog said they had
# shipped and `git tag` disagreed, which makes `git describe` useless and any
# "what changed between X and Y" unanswerable.
#
# The newest entry is exempt: it is committed a moment before it is tagged, and
# failing there would make the check impossible to satisfy while releasing.
# What counts as released is "a commit carried this version in Cargo.toml", not
# "the changelog has a heading". Four headings never had a commit of their own —
# 0.1.17, 0.1.30, 0.1.50 and 0.1.51 were written alongside the release that
# followed them, deliberately in the last case — and demanding tags for those
# would invent releases that never happened. Derived rather than kept in a list
# here, so it cannot go stale the way the list it replaced would have.
released=$(git log -p --format='' -- Cargo.toml | grep -oE '^\+version = "[0-9][0-9.]*"' | cut -d'"' -f2 | sort -uV)
missing=""
for v in $released; do
  [ "$v" = "$cargo_version" ] && continue   # committed a moment before it is tagged
  [ "$v" = "0.0.0" ] && continue            # the scaffold's placeholder, never shipped
  git rev-parse -q --verify "refs/tags/v$v" >/dev/null || missing="$missing v$v"
done
[ -z "$missing" ] || note "released versions with no tag:$missing"

[ "$fail" = 0 ] &&
  echo "repo invariants ok: v$cargo_version, $total entries, descending, seeds tracked"
exit "$fail"
