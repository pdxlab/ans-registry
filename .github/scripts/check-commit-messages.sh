#!/usr/bin/env bash
# Validate PR title + commit subjects. See .github/workflows/commit-messages.yml.
#
# Usage: check-commit-messages.sh ticket|style
set -uo pipefail

MODE="${1:?usage: $0 ticket|style}"

TICKET_RE='(TRUS|PSS1)-[0-9]+'
TYPE_RE='^(feat|fix|chore|docs|refactor|test|perf|ci|build|style|revert)(\([a-z0-9._/-]+\))?!?: .+'

case "$MODE" in
  ticket) PATTERN="$TICKET_RE"; MATCH="grep -Eq"
          WANT='a Jira ref, e.g. TRUS-1234'
          EXAMPLE='TRUS-1742: stop dropping job rows   |   fix: stop dropping rows (TRUS-1742)' ;;
  style)  PATTERN="$TYPE_RE";   MATCH="grep -Eq"
          WANT='a conventional type prefix'
          EXAMPLE='fix: stop dropping job rows (TRUS-1742)   |   feat(sdk): expose org id (TRUS-1888)' ;;
  *) echo "::error::unknown mode '$MODE'"; exit 2 ;;
esac

# BOTS ARE EXEMPT, AND NOT AS A CONVENIENCE.
# Dependabot opens a fifth of the PRs in some of these repos and cannot know a
# ticket number. Gating it would stop every dependency and security update,
# which is the fastest way to get a check like this switched off in anger.
if [[ "${PR_AUTHOR:-}" == *"[bot]" || "${PR_AUTHOR:-}" =~ ^(dependabot|renovate|github-actions) ]]; then
  echo "PR author '${PR_AUTHOR}' is a bot — skipping."
  exit 0
fi

# A subject git generated rather than a person wrote. Rejecting these would
# fail a PR for something the author did not type and cannot easily reword.
is_generated() {
  [[ "$1" =~ ^Merge\ (pull\ request|branch|remote-tracking) ]] ||
  [[ "$1" =~ ^Revert\ \" ]] ||
  [[ "$1" =~ ^(Bump|bump)\ [a-z@] ]]
}

failed=0
report() {  # report <label> <subject>
  printf '  %-8s %s\n' "$1" "$2"
}

echo "Mode: $MODE — requiring $WANT"
echo

# ── the PR title (what a squash merge commits) ───────────────────────────
if printf '%s' "${PR_TITLE:-}" | $MATCH "$PATTERN"; then
  report "ok" "PR title: ${PR_TITLE}"
else
  report "MISSING" "PR title: ${PR_TITLE}"
  failed=1
fi

# ── the individual commits (what a merge commit preserves) ───────────────
# base.sha is the merge-base recorded on the PR, so this is exactly the set of
# commits the PR adds — not everything since main moved.
mapfile -t SUBJECTS < <(git log --no-merges --format='%s' "${BASE_SHA}..${HEAD_SHA}" 2>/dev/null)

if [ "${#SUBJECTS[@]}" -eq 0 ]; then
  echo "  (no non-merge commits to check)"
else
  for subject in "${SUBJECTS[@]}"; do
    if is_generated "$subject"; then
      report "skip" "$subject"
    elif printf '%s' "$subject" | $MATCH "$PATTERN"; then
      report "ok" "$subject"
    else
      report "MISSING" "$subject"
      failed=1
    fi
  done
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "All subjects carry $WANT."
  exit 0
fi

{
  echo "### ❌ Commit messages need $WANT"
  echo
  echo "Fix the **PR title** (used by squash merge) and any commit subject listed \`MISSING\` above."
  echo
  echo '```'
  echo "$EXAMPLE"
  echo '```'
  if [ "$MODE" = "style" ]; then
    echo
    echo "_This check is **advisory** — it does not block merging._"
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$MODE" = "style" ]; then
  echo "::warning::Advisory only — this does not block the merge."
fi
echo "::error::Subjects missing $WANT. Expected e.g. $EXAMPLE"
exit 1
