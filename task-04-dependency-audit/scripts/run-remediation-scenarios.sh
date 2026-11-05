#!/usr/bin/env bash
# Re-run the remediation scenarios in throwaway copies of app/ and keep the evidence.
#
#   bash scripts/run-remediation-scenarios.sh <new-evidence-dir>
#
# Safety:
#   * app/ is only read. Every scenario runs in a temp directory outside the repo.
#   * Lockfile-only resolution with --ignore-scripts: no node_modules/ is
#     created and no package lifecycle script runs (checked after each step).
#   * Refuses to write into an existing directory, so earlier evidence is never
#     overwritten.
#
# Scenarios:
#   baseline-reaudit   unchanged package.json + lockfile, audited again today
#   A-audit-fix        npm audit fix (no --force)
#   B-minor-pins       express 4.22.3 + lodash 4.18.1 (exact pins)
#   C-audit-fix-force  npm audit fix --force
#   D-force-then-mocha-11.0.0  C, then mocha 11.0.0 (npm's suggestion after C)
#
# Set NPM=npm.cmd if plain `npm` does not work in your shell.
set -euo pipefail

usage() { echo "usage: $0 <new-evidence-dir>" >&2; exit 2; }
[ $# -eq 1 ] || usage

TASK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$TASK_DIR/app"
NPM="${NPM:-npm}"
OUT="$1"

if [ -e "$OUT" ]; then
  echo "refusing to overwrite existing evidence: $OUT" >&2
  exit 2
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT
WORK_NAME="$(basename "$WORK")"

BASELINE_HASH_BEFORE="$(cd "$APP" && sha256sum package.json package-lock.json .npmrc)"

INFO="$OUT/run-info.txt"
{
  echo "started (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "node: $(node --version)"
  echo "npm: $("$NPM" --version)"
  echo "registry: $("$NPM" config get registry)"
  echo "os: $(uname -s -r)"
  echo "baseline sha256 (app/):"
  echo "$BASELINE_HASH_BEFORE" | sed 's/^/  /'
} > "$INFO"

# setup <scenario> <source dir>: copy manifest, lockfile and .npmrc into a work dir.
setup() {
  local s="$1" src="$2"
  mkdir -p "$WORK/$s" "$OUT/$s"
  cp "$src/package.json" "$src/package-lock.json" "$src/.npmrc" "$WORK/$s/"
  printf 'exit_code\tcommand\n' > "$OUT/$s/commands.tsv"
}

# step <scenario> <command...>: run in the work dir, record command and exit code.
# A non-zero exit is recorded, not fatal: npm audit exits 1 when it finds issues.
step() {
  local s="$1"; shift
  local rc=0
  (cd "$WORK/$s" && "$@") >> "$OUT/$s/npm-output.txt" 2>&1 || rc=$?
  printf '%s\t%s\n' "$rc" "$*" >> "$OUT/$s/commands.tsv"
  if [ -e "$WORK/$s/node_modules" ]; then
    echo "node_modules/ appeared in scenario $s; aborting" >&2
    exit 3
  fi
}

# audit <scenario>: npm audit --json into the evidence dir, exit code recorded.
audit() {
  local s="$1" rc=0
  (cd "$WORK/$s" && "$NPM" audit --json) > "$OUT/$s/npm-audit.json" \
    2> "$OUT/$s/npm-audit.stderr.txt" || rc=$?
  printf '%s\t%s\n' "$rc" "$NPM audit --json" >> "$OUT/$s/commands.tsv"
}

# finish <scenario>: consistency checks, then keep manifest, lockfile, hashes, versions.
finish() {
  local s="$1"
  step "$s" "$NPM" ls --package-lock-only --all
  step "$s" "$NPM" ci --dry-run --ignore-scripts --no-audit --no-fund
  audit "$s"
  cp "$WORK/$s/package.json" "$WORK/$s/package-lock.json" "$OUT/$s/"
  (cd "$OUT/$s" && sha256sum package.json package-lock.json npm-audit.json) > "$OUT/$s/sha256.txt"
  node -e '
    const l = require(process.argv[1]);
    const root = l.packages[""];
    const names = Object.keys({...root.dependencies, ...root.devDependencies}).sort();
    for (const n of names) console.log(n + " " + l.packages["node_modules/" + n].version);
  ' "$WORK/$s/package-lock.json" > "$OUT/$s/direct-versions.txt"
}

LOCK_ONLY=(--package-lock-only --ignore-scripts)
INSTALL_FLAGS=(--package-lock-only --ignore-scripts --no-audit --no-fund)

setup baseline-reaudit "$APP"
finish baseline-reaudit

setup A-audit-fix "$APP"
step A-audit-fix "$NPM" audit fix "${LOCK_ONLY[@]}"
finish A-audit-fix

setup B-minor-pins "$APP"
step B-minor-pins "$NPM" install express@4.22.3 lodash@4.18.1 --save-exact "${INSTALL_FLAGS[@]}"
finish B-minor-pins

setup C-audit-fix-force "$APP"
step C-audit-fix-force "$NPM" audit fix --force "${LOCK_ONLY[@]}"
finish C-audit-fix-force

setup D-force-then-mocha-11.0.0 "$WORK/C-audit-fix-force"
step D-force-then-mocha-11.0.0 "$NPM" install mocha@11.0.0 --save-dev --save-exact "${INSTALL_FLAGS[@]}"
finish D-force-then-mocha-11.0.0

# Keep local paths out of the evidence.
for f in "$OUT"/*/npm-output.txt "$OUT"/*/npm-audit.stderr.txt; do
  # Matches the temp dir in POSIX and Windows (long or 8.3) spelling; paths may contain spaces.
  sed -i -E "s#([A-Za-z]:)?[\\\\/][^\"']*${WORK_NAME}#<work>#g" "$f"
done

BASELINE_HASH_AFTER="$(cd "$APP" && sha256sum package.json package-lock.json .npmrc)"
{
  echo "finished (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$BASELINE_HASH_BEFORE" = "$BASELINE_HASH_AFTER" ]; then
    echo "baseline app/ unchanged: yes"
  else
    echo "baseline app/ unchanged: NO"
  fi
  [ -e "$APP/node_modules" ] && echo "app/node_modules present: YES" || echo "app/node_modules present: no"
} >> "$INFO"

[ "$BASELINE_HASH_BEFORE" = "$BASELINE_HASH_AFTER" ] || { echo "baseline changed!" >&2; exit 4; }
echo "evidence written to $OUT"
