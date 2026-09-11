#!/usr/bin/env bash
# Self-test for check-commit-messages.sh.
#
# WHY THIS EXISTS
# ---------------
# Every one of the cases below is a bug that actually shipped and was caught
# by a human in review rather than by CI:
#
#   advisory_warns_not_errors  advisory mode annotated with ::error::, so a
#                              non-blocking check showed contributors a red
#                              "error" beside a line saying it does not block.
#                              Fixed once, then REVERTED by a patch built on
#                              the wrong branch, and caught by a human twice.
#   unreadable_range_fails     `git log 2>/dev/null` with no `set -e` meant a
#                              failed git left SUBJECTS empty, indistinguishable
#                              from "no commits", so a REQUIRED gate passed
#                              having inspected nothing.
#   capitalised_bump_skipped   the exemption was [a-z@], so `Bump undici`
#                              skipped but `Bump Django` failed — and the
#                              Python repos bump Django, Pillow and PyYAML.
#
# A ten-line assertion would have caught all three. Hence this file.

set -uo pipefail
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-commit-messages.sh"
PASS=0; FAIL=0

# A throwaway repo so the script has real ranges to read.
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
git -C "$WORK" init -q
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "TRUS-1: base"
BASE="$(git -C "$WORK" rev-parse HEAD)"

# commit <subject...> ; echoes the new HEAD
commit() {
  git -C "$WORK" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "$1"
  git -C "$WORK" rev-parse HEAD
}

# run <mode> <author> <title> <base> <head> -> "<exit> <errors> <warnings>"
run() {
  local out rc
  out="$(cd "$WORK" && PR_AUTHOR="$2" PR_TITLE="$3" BASE_SHA="$4" HEAD_SHA="$5" \
        bash "$SCRIPT" "$1" 2>&1)"; rc=$?
  printf '%s %s %s' "$rc" \
    "$(printf '%s' "$out" | grep -c '::error::')" \
    "$(printf '%s' "$out" | grep -c '::warning::')"
}

expect() { # expect <name> <expected> <actual>
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  ok    %s\n' "$1"
  else FAIL=$((FAIL+1)); printf '  FAIL  %s — expected "%s", got "%s"\n' "$1" "$2" "$3"; fi
}

HEAD_OK="$(commit 'fix: does a thing (TRUS-2)')"
expect "compliant_passes"            "0 0 0" "$(run ticket dev 'fix: x (TRUS-9)' "$BASE" "$HEAD_OK")"

HEAD_BAD="$(commit 'update stuff')"
expect "missing_ref_blocks"          "1 1 0" "$(run ticket dev 'no ref here' "$BASE" "$HEAD_BAD")"

# THE REGRESSION THAT SHIPPED TWICE: advisory must warn, never error.
expect "advisory_warns_not_errors"   "1 0 1" "$(run style dev 'no type here' "$BASE" "$HEAD_BAD")"

expect "bot_author_exempt"           "0 0 0" "$(run ticket 'dependabot[bot]' 'bump x' "$BASE" "$HEAD_BAD")"

# THE FAIL-OPEN: a gate that cannot read history must not report success.
expect "unreadable_range_fails"      "2 1 0" \
  "$(run ticket dev 'fix: x (TRUS-9)' deadbeefdeadbeefdeadbeefdeadbeefdeadbeef "$HEAD_OK")"

# THE CASE BUG: Django/Pillow/PyYAML are capitalised.
HEAD_BUMP="$(commit 'Bump Django from 4 to 5')"
expect "capitalised_bump_skipped"    "0 0 0" "$(run ticket dev 'fix: x (TRUS-9)' "$HEAD_BAD" "$HEAD_BUMP")"

HEAD_MERGE="$(commit 'Revert "TRUS-3 thing"')"
expect "generated_subjects_skipped"  "0 0 0" "$(run ticket dev 'fix: x (TRUS-9)' "$HEAD_BUMP" "$HEAD_MERGE")"

# An empty range is legitimate; the PR title still has to carry a ref.
expect "empty_range_checks_title"    "1 1 0" "$(run ticket dev 'no ref' "$HEAD_MERGE" "$HEAD_MERGE")"

printf '\n  %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
