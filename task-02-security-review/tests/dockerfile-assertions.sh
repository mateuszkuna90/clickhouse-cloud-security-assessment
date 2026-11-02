#!/usr/bin/env bash
# Lightweight offline assertions for the Task 2 Dockerfiles.
#
# NOT a replacement for hadolint, checkov or trivy; it only covers the
# findings fixed in this task, so they can be checked without extra tools.
# The hardened Dockerfile must pass every check. The original fixture must
# fail every check (negative test), which proves the checks can detect them.
#
# Usage: bash tests/dockerfile-assertions.sh   (from task-02-security-review/)
set -euo pipefail

cd "$(dirname "$0")/.."
HARDENED="docker/Dockerfile"
ORIGINAL="fixtures/example-insecure.Dockerfile"
failures=0

# Each check prints PASS or FAIL for one file. Comment lines are ignored.
check() {
  local file="$1" description="$2" expected="$3"; shift 3
  local result
  if grep -v '^[[:space:]]*#' "$file" | "$@" >/dev/null; then result="match"; else result="no-match"; fi
  local label="$description"
  if [[ "$file" == "$ORIGINAL" ]]; then
    label="negative test, original must violate: ${description}"
  fi
  if [[ "$result" == "$expected" ]]; then
    echo "PASS  ${file}: ${label}"
  else
    echo "FAIL  ${file}: ${label}"
    failures=$((failures + 1))
  fi
}

# check_both <description> <hardened-expected> <original-expected> <cmd...>
check_both() {
  local description="$1" hardened_expected="$2" original_expected="$3"; shift 3
  check "$HARDENED" "$description" "$hardened_expected" "$@"
  check "$ORIGINAL" "$description" "$original_expected" "$@"
}

check_both "D-1 no secret-like ENV/ARG"           no-match match    grep -Ei '^(ENV|ARG)[[:space:]].*(PASSWORD|SECRET|API_KEY|TOKEN)'
check_both "D-2 no root USER"                     no-match match    grep -E '^USER[[:space:]]+(root|0)([:[:space:]]|$)'
check_both "D-3 FROM pinned by sha256 digest"     match    no-match grep -E '^FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}([[:space:]]|$)'
check_both "D-3 no EOL ubuntu:18.04 base"         no-match match    grep -E '^FROM[[:space:]]+ubuntu:18\.04'
check_both "D-4 no world-writable permissions"    no-match match    grep -E '(chmod[[:space:]].*777|--chmod=0?777)'
check_both "D-6 no curl/vim/dnsutils installed"   no-match match    grep -Ew 'curl|vim|dnsutils'
check_both "D-8 exec-form CMD"                    match    no-match grep -E '^CMD[[:space:]]+\['

# The last USER instruction in the hardened file must be numeric and non-zero.
last_user="$(grep -E '^USER[[:space:]]' "$HARDENED" | tail -n 1 | awk '{print $2}' || true)"
if [[ "$last_user" =~ ^[1-9][0-9]*(:[1-9][0-9]*)?$ ]]; then
  echo "PASS  ${HARDENED}: D-2 final USER is numeric and non-root (${last_user})"
else
  echo "FAIL  ${HARDENED}: D-2 final USER is numeric and non-root (got '${last_user}')"
  failures=$((failures + 1))
fi

# Build-context exclusions must exist for the hardened Dockerfile (D-5).
for pattern in '.git' '**/.env' '**/*.env' '**/*.pem' '**/*.key'; do
  if grep -qxF -- "$pattern" docker/Dockerfile.dockerignore; then
    echo "PASS  docker/Dockerfile.dockerignore: D-5 excludes ${pattern}"
  else
    echo "FAIL  docker/Dockerfile.dockerignore: D-5 excludes ${pattern}"
    failures=$((failures + 1))
  fi
done

# Runtime secret files (README B.3) must be ignored by Git if created inside
# this task. Uses the real Git ignore rules; the files do not need to exist.
if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
  for path in runtime.env docker/runtime.env .env; do
    if git check-ignore -q --no-index -- "$path"; then
      echo "PASS  git: ${path} is ignored"
    else
      echo "FAIL  git: ${path} is ignored"
      failures=$((failures + 1))
    fi
  done
  if git check-ignore -q --no-index -- runtime.env.example; then
    echo "FAIL  git: runtime.env.example stays trackable"
    failures=$((failures + 1))
  else
    echo "PASS  git: runtime.env.example stays trackable"
  fi
else
  echo "SKIP  git ignore checks (not inside a Git work tree)"
fi

echo
if [[ "$failures" -eq 0 ]]; then
  echo "All Dockerfile assertions passed."
else
  echo "${failures} assertion(s) failed."
  exit 1
fi
