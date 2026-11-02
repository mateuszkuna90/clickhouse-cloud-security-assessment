#!/usr/bin/env bash
# Guard for the secret-scanning exception used in Task 2.
#
# The insecure Dockerfile fixture contains two FAKE secret values copied from
# the assessment brief. Secret scanning still covers every file, including the
# fixture. The only exception is ci/checkov-secrets.baseline.json, which lists
# the SHA-1 of exact known fake values.
#
# checkov 3.4.2 matches baseline entries by secret hash and check ID only. It
# ignores the file path (verified locally), so on its own the exception would
# also hide the same value in another file. This script narrows it again:
#   1. the fixture still contains exactly the known fake values (pinned below
#      by SHA-1, so this script holds no secret-like plaintext);
#   2. those values appear in no other file of this task;
#   3. every hash in the baseline is one of the pinned known fake values, so
#      the baseline cannot be used to hide any other (possibly real) secret.
#
# Usage: bash tests/known-fake-secrets.sh   (from task-02-security-review/)
set -euo pipefail

cd "$(dirname "$0")/.."
FIXTURE="fixtures/example-insecure.Dockerfile"
BASELINE="ci/checkov-secrets.baseline.json"

# SHA-1 of the fake values from the brief (DB_PASSWORD and API_KEY in the fixture).
KNOWN_FAKE_SHA1=(
  375acd53569a434268a1a0301448340ada728ddb
  18c0337ada5836289b2ff1dd71b2fa4f6be5037d
)
failures=0

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failures=$((failures + 1)); }
is_known() { printf '%s\n' "${KNOWN_FAKE_SHA1[@]}" | grep -qxF -- "$1"; }

# 1. Read the fake values from the fixture's ENV lines.
mapfile -t fixture_values < <(sed -nE 's/^ENV (DB_PASSWORD|API_KEY)="([^"]*)"$/\2/p' "$FIXTURE")
if [[ "${#fixture_values[@]}" -eq "${#KNOWN_FAKE_SHA1[@]}" ]]; then
  pass "fixture has ${#fixture_values[@]} fake secret values (negative test input intact)"
else
  fail "expected ${#KNOWN_FAKE_SHA1[@]} fake secret values in ${FIXTURE}, found ${#fixture_values[@]}"
fi

for value in "${fixture_values[@]}"; do
  hash="$(printf '%s' "$value" | sha1sum | cut -d' ' -f1)"
  if is_known "$hash"; then
    pass "fixture value ${hash} is a pinned known fake value"
  else
    fail "fixture value ${hash} is NOT a known fake value (fixtures must never hold real secrets)"
  fi
  # 2. The value must not appear in any other file of this task.
  others="$(grep -rlF --exclude-dir=.terraform -- "$value" . | sed 's#^\./##' | grep -vxF "$FIXTURE" || true)"
  if [[ -z "$others" ]]; then
    pass "fake value ${hash} appears only in ${FIXTURE}"
  else
    fail "fake value ${hash} also appears in: $(echo "$others" | tr '\n' ' ')"
  fi
done

# 3. The baseline may only exempt pinned known fake values, as exact hashes.
mapfile -t baseline_hashes < <(grep -oE '"resource": *"[0-9a-f]{40}"' "$BASELINE" | grep -oE '[0-9a-f]{40}')
if [[ "${#baseline_hashes[@]}" -eq 0 ]]; then
  fail "no hashes found in ${BASELINE}"
fi
for hash in "${baseline_hashes[@]}"; do
  if is_known "$hash"; then
    pass "baseline hash ${hash} is a pinned known fake value"
  else
    fail "baseline hash ${hash} is not a known fake value"
  fi
done
if grep -E '"resource"' "$BASELINE" | grep -vqE '"resource": *"[0-9a-f]{40}"'; then
  fail "baseline contains a resource entry that is not an exact SHA-1 hash"
else
  pass "baseline contains only exact SHA-1 hash entries"
fi

echo
if [[ "$failures" -eq 0 ]]; then
  echo "All known-fake-secret checks passed."
else
  echo "${failures} check(s) failed."
  exit 1
fi
