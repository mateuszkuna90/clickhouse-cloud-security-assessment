#!/usr/bin/env bash
# Offline behaviour tests for files/startup.sh.
#
# Runs the REAL script with stub commands first on PATH (apt-get, dpkg-query,
# systemctl, curl, flock, timeout, sleep). Nothing is installed, no network is
# used, and nothing outside a temporary directory is touched. The `sleep` stub
# records requested delays instead of sleeping, so backoff is asserted exactly.
#
# Usage (from task-01-gcp-terraform/): bash tests/bootstrap/test_startup.sh
#
# Assertions are passed to check() as single-quoted strings and evaluated
# later, so variables in them (RC, OUT, first_mtime, ...) are expanded on
# purpose at check time.
# shellcheck disable=SC2016,SC2034
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARTUP="$(cd "$SCRIPT_DIR/../.." && pwd)/files/startup.sh"
[[ -f "$STARTUP" ]] || { echo "startup script not found: $STARTUP" >&2; exit 2; }

PASS=0
FAIL=0
SANDBOX=""
OUT=""
RC=0

new_sandbox() {
  SANDBOX="$(mktemp -d)"
  mkdir -p "$SANDBOX/bin" "$SANDBOX/state" "$SANDBOX/www"
  : >"$SANDBOX/calls"
  : >"$SANDBOX/sleeps"
  echo 0 >"$SANDBOX/apt_update_failures"

  cat >"$SANDBOX/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >>"$SANDBOX/calls"
case " $* " in
  *" update "*)
    n=$(cat "$SANDBOX/apt_update_failures")
    if [[ "$n" -gt 0 ]]; then echo $((n - 1)) >"$SANDBOX/apt_update_failures"; exit 100; fi
    exit 0 ;;
  *" install "*)
    touch "$SANDBOX/nginx_installed"; exit 0 ;;
esac
exit 0
EOF
  cat >"$SANDBOX/bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
echo "dpkg-query $*" >>"$SANDBOX/calls"
if [[ -f "$SANDBOX/nginx_installed" ]]; then printf 'install ok installed'; exit 0; fi
exit 1
EOF
  cat >"$SANDBOX/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$SANDBOX/calls"
# Models nginx unit state with files: nginx_active (running), nginx_enabled.
case "$1" in
  enable)
    [[ -f "$SANDBOX/systemctl_enable_fail" ]] && exit 1
    touch "$SANDBOX/nginx_enabled"
    [[ "${2:-}" == "--now" ]] && touch "$SANDBOX/nginx_active"
    exit 0 ;;
  stop) rm -f "$SANDBOX/nginx_active"; exit 0 ;;
  disable) rm -f "$SANDBOX/nginx_enabled"; exit 0 ;;
  is-active) [[ -f "$SANDBOX/nginx_active" ]] && exit 0; exit 3 ;;
esac
exit 0
EOF
  # curl succeeds only if nginx is "running" (and curl_fail is not set), so
  # the self-check really depends on the unit state.
  cat >"$SANDBOX/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >>"$SANDBOX/calls"
[[ -f "$SANDBOX/curl_fail" ]] && exit 7
[[ -f "$SANDBOX/nginx_active" ]] || exit 7
exit 0
EOF
  cat >"$SANDBOX/bin/flock" <<'EOF'
#!/usr/bin/env bash
echo "flock $*" >>"$SANDBOX/calls"
[[ -f "$SANDBOX/flock_fail" ]] && exit 1
exit 0
EOF
  cat >"$SANDBOX/bin/timeout" <<'EOF'
#!/usr/bin/env bash
echo "timeout $1" >>"$SANDBOX/calls"
shift
exec "$@"
EOF
  cat >"$SANDBOX/bin/sleep" <<'EOF'
#!/usr/bin/env bash
printf '%s ' "$1" >>"$SANDBOX/sleeps"
EOF
  chmod +x "$SANDBOX"/bin/*
}

run_startup() {
  OUT="$(
    env SANDBOX="$SANDBOX" PATH="$SANDBOX/bin:$PATH" \
      BOOTSTRAP_STATE_DIR="$SANDBOX/state" \
      BOOTSTRAP_WEB_ROOT="$SANDBOX/www" \
      BOOTSTRAP_LOCK_FILE="$SANDBOX/lock" \
      "$@" bash "$STARTUP" 2>&1
  )"
  RC=$?
}

check() {
  local name=$1 cond=$2
  if eval "$cond"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL [$name]: $cond"
    echo "  --- output ---"
    printf '%s\n' "$OUT" | sed 's/^/  | /'
  fi
}

count_calls() { grep -c -- "$1" "$SANDBOX/calls" || true; }
sleeps() { sed 's/ *$//' "$SANDBOX/sleeps"; }

# B-SH-1 happy path ----------------------------------------------------------
echo "B-SH-1 happy path"
new_sandbox
run_startup
check B-SH-1.rc '[[ $RC -eq 0 ]]'
check B-SH-1.ok-log '[[ "$OUT" == *"SECURE_WEB_BOOTSTRAP=OK"* ]]'
check B-SH-1.ok-marker '[[ -f "$SANDBOX/state/bootstrap.ok" ]]'
check B-SH-1.no-failed '[[ ! -f "$SANDBOX/state/bootstrap.failed" ]]'
check B-SH-1.one-update '[[ $(count_calls "apt-get .*update") -eq 1 ]]'
check B-SH-1.installs-nginx '[[ $(count_calls "install --no-install-recommends nginx") -eq 1 ]]'
check B-SH-1.timeout-120 '[[ $(count_calls "timeout 120") -eq 1 ]]'
check B-SH-1.lock-timeout 'grep -q "DPkg::Lock::Timeout=120" "$SANDBOX/calls"'
check B-SH-1.enable-now 'grep -q "systemctl enable --now nginx" "$SANDBOX/calls"'
check B-SH-1.flock 'grep -q "flock -w 600 9" "$SANDBOX/calls"'
check B-SH-1.curl-local 'grep -q "curl .*http://127.0.0.1/" "$SANDBOX/calls"'
check B-SH-1.index '[[ -f "$SANDBOX/www/index.html" ]] && grep -q "served by nginx" "$SANDBOX/www/index.html"'
check B-SH-1.no-sleep '[[ -z "$(sleeps)" ]]'
check B-SH-1.nginx-running-enabled '[[ -f "$SANDBOX/nginx_active" && -f "$SANDBOX/nginx_enabled" ]]'
check B-SH-1.no-stop '! grep -qE "systemctl (stop|disable)" "$SANDBOX/calls"'
rm -rf "$SANDBOX"

# B-SH-2 transient failure then success ---------------------------------------
echo "B-SH-2 transient apt failure (2 failures, then success)"
new_sandbox
echo 2 >"$SANDBOX/apt_update_failures"
run_startup
check B-SH-2.rc '[[ $RC -eq 0 ]]'
check B-SH-2.three-attempts '[[ $(count_calls "apt-get .*update") -eq 3 ]]'
check B-SH-2.backoff '[[ "$(sleeps)" == "10 20" ]]'
check B-SH-2.ok-marker '[[ -f "$SANDBOX/state/bootstrap.ok" ]]'
rm -rf "$SANDBOX"

# B-SH-3 permanent failure -----------------------------------------------------
echo "B-SH-3 permanent apt failure"
new_sandbox
echo 999 >"$SANDBOX/apt_update_failures"
run_startup
check B-SH-3.rc-nonzero '[[ $RC -ne 0 ]]'
check B-SH-3.five-attempts '[[ $(count_calls "apt-get .*update") -eq 5 ]]'
check B-SH-3.backoff '[[ "$(sleeps)" == "10 20 40 80" ]]'
check B-SH-3.failed-marker 'grep -q "^step=install " "$SANDBOX/state/bootstrap.failed"'
check B-SH-3.failed-log '[[ "$OUT" == *"SECURE_WEB_BOOTSTRAP=FAILED step=install"* ]]'
check B-SH-3.no-ok '[[ ! -f "$SANDBOX/state/bootstrap.ok" ]]'
check B-SH-3.nginx-not-started '! grep -q "systemctl enable" "$SANDBOX/calls"'
rm -rf "$SANDBOX"

# B-SH-4 idempotency ----------------------------------------------------------
echo "B-SH-4 idempotency (nginx preinstalled, two runs)"
new_sandbox
touch "$SANDBOX/nginx_installed"
run_startup
check B-SH-4.first-rc '[[ $RC -eq 0 ]]'
cp "$SANDBOX/www/index.html" "$SANDBOX/index.first"
first_mtime="$(stat -c %Y "$SANDBOX/www/index.html")"
run_startup
check B-SH-4.second-rc '[[ $RC -eq 0 ]]'
check B-SH-4.no-apt '[[ $(count_calls "apt-get") -eq 0 ]]'
check B-SH-4.skip-log '[[ "$OUT" == *"nginx already installed; skipping package install"* ]]'
check B-SH-4.index-unchanged-log '[[ "$OUT" == *"index.html unchanged"* ]]'
check B-SH-4.index-same '[[ "$(stat -c %Y "$SANDBOX/www/index.html")" == "$first_mtime" ]] && cmp -s "$SANDBOX/index.first" "$SANDBOX/www/index.html"'
check B-SH-4.ok-marker '[[ -f "$SANDBOX/state/bootstrap.ok" ]]'
rm -rf "$SANDBOX"

# B-SH-5 self-check failure ---------------------------------------------------
echo "B-SH-5 self-check failure (nginx not answering)"
new_sandbox
touch "$SANDBOX/curl_fail"
run_startup
check B-SH-5.rc-nonzero '[[ $RC -ne 0 ]]'
check B-SH-5.failed-log '[[ "$OUT" == *"SECURE_WEB_BOOTSTRAP=FAILED step=self_check"* ]]'
check B-SH-5.marker 'grep -q "^step=self_check " "$SANDBOX/state/bootstrap.failed"'
check B-SH-5.bounded '[[ $(count_calls "^curl") -eq 5 && "$(sleeps)" == "2 2 2 2" ]]'
rm -rf "$SANDBOX"

# B-SH-6 override clamps ------------------------------------------------------
echo "B-SH-6 override clamps (attempts <= 10, backoff base <= 60, junk ignored)"
new_sandbox
echo 999 >"$SANDBOX/apt_update_failures"
run_startup BOOTSTRAP_MAX_ATTEMPTS=1000 BOOTSTRAP_BACKOFF_BASE_SECONDS=1000
check B-SH-6.rc-nonzero '[[ $RC -ne 0 ]]'
check B-SH-6.max-10 '[[ $(count_calls "apt-get .*update") -eq 10 ]]'
check B-SH-6.base-60 '[[ "$(sleeps)" == 60\ 120\ * ]]'
rm -rf "$SANDBOX"
new_sandbox
echo 999 >"$SANDBOX/apt_update_failures"
run_startup BOOTSTRAP_MAX_ATTEMPTS=abc BOOTSTRAP_BACKOFF_BASE_SECONDS=-1
check B-SH-6.junk-defaults '[[ $(count_calls "apt-get .*update") -eq 5 && "$(sleeps)" == "10 20 40 80" ]]'
rm -rf "$SANDBOX"

# B-SH-7 recovery after a failed run -----------------------------------------
echo "B-SH-7 recovery (failed run, then successful run)"
new_sandbox
echo 999 >"$SANDBOX/apt_update_failures"
run_startup
check B-SH-7.first-failed '[[ $RC -ne 0 && -f "$SANDBOX/state/bootstrap.failed" ]]'
echo 0 >"$SANDBOX/apt_update_failures"
: >"$SANDBOX/sleeps"
run_startup
check B-SH-7.second-ok '[[ $RC -eq 0 && -f "$SANDBOX/state/bootstrap.ok" && ! -f "$SANDBOX/state/bootstrap.failed" ]]'
rm -rf "$SANDBOX"

# B-SH-8 service start failure -----------------------------------------------
echo "B-SH-8 systemctl enable failure"
new_sandbox
touch "$SANDBOX/systemctl_enable_fail"
run_startup
check B-SH-8.rc-nonzero '[[ $RC -ne 0 ]]'
check B-SH-8.failed-log '[[ "$OUT" == *"SECURE_WEB_BOOTSTRAP=FAILED step=service"* ]]'
rm -rf "$SANDBOX"

# --- Fail-closed regression tests (Codex final review, Medium 1) -------------
# Each starts from a previously healthy VM: nginx installed or running and
# enabled, plus a stale bootstrap.ok from an earlier boot.
seed_previously_healthy() {
  touch "$SANDBOX/nginx_active" "$SANDBOX/nginx_enabled"
  date >"$SANDBOX/state/bootstrap.ok"
}
fail_closed_checks() {
  local id=$1 step=$2
  check "$id.rc-nonzero" '[[ $RC -ne 0 ]]'
  check "$id.failed-marker" "grep -q '^step=$step ' \"\$SANDBOX/state/bootstrap.failed\""
  check "$id.failed-log" "[[ \"\$OUT\" == *'SECURE_WEB_BOOTSTRAP=FAILED step=$step'* ]]"
  check "$id.stale-ok-removed" '[[ ! -f "$SANDBOX/state/bootstrap.ok" ]]'
  check "$id.stop-called" 'grep -q "^systemctl stop nginx$" "$SANDBOX/calls"'
  check "$id.disable-called" 'grep -q "^systemctl disable nginx$" "$SANDBOX/calls"'
  check "$id.nginx-not-running" '[[ ! -f "$SANDBOX/nginx_active" ]]'
  check "$id.nginx-not-enabled" '[[ ! -f "$SANDBOX/nginx_enabled" ]]'
  check "$id.fail-closed-log" '[[ "$OUT" == *"nginx stopped (fail closed)"* ]]'
}

# B-SH-10 nginx already running, package installation fails ------------------
echo "B-SH-10 fail closed: nginx already active, package install fails"
new_sandbox
seed_previously_healthy
echo 999 >"$SANDBOX/apt_update_failures"
run_startup
fail_closed_checks B-SH-10 install
check B-SH-10.bounded '[[ $(count_calls "apt-get .*update") -eq 5 && "$(sleeps)" == "10 20 40 80" ]]'
rm -rf "$SANDBOX"

# B-SH-11 nginx installed and running, content generation fails --------------
echo "B-SH-11 fail closed: nginx installed and active, content step fails"
new_sandbox
seed_previously_healthy
touch "$SANDBOX/nginx_installed"
: >"$SANDBOX/not-a-directory" # web root path is a file -> mkdir/install fails
run_startup BOOTSTRAP_WEB_ROOT="$SANDBOX/not-a-directory"
fail_closed_checks B-SH-11 content
check B-SH-11.no-apt '[[ $(count_calls "apt-get") -eq 0 ]]'
rm -rf "$SANDBOX"

# B-SH-12 nginx running, final self-check fails --------------------------------
echo "B-SH-12 fail closed: nginx active, final self-check fails"
new_sandbox
seed_previously_healthy
touch "$SANDBOX/nginx_installed" "$SANDBOX/curl_fail"
run_startup
fail_closed_checks B-SH-12 self_check
check B-SH-12.bounded '[[ $(count_calls "^curl") -eq 5 && "$(sleeps)" == "2 2 2 2" ]]'
rm -rf "$SANDBOX"

# B-SH-13 lock not acquired: must NOT stop nginx owned by another run ---------
echo "B-SH-13 lock not held: failure recorded, nginx left to the lock owner"
new_sandbox
seed_previously_healthy
touch "$SANDBOX/nginx_installed" "$SANDBOX/flock_fail"
run_startup
check B-SH-13.rc-nonzero '[[ $RC -ne 0 ]]'
check B-SH-13.failed-marker 'grep -q "^step=lock " "$SANDBOX/state/bootstrap.failed"'
check B-SH-13.stale-ok-removed '[[ ! -f "$SANDBOX/state/bootstrap.ok" ]]'
check B-SH-13.no-stop '! grep -qE "^systemctl (stop|disable)" "$SANDBOX/calls"'
check B-SH-13.nginx-untouched '[[ -f "$SANDBOX/nginx_active" && -f "$SANDBOX/nginx_enabled" ]]'
check B-SH-13.log '[[ "$OUT" == *"lock not held; leaving nginx state to the lock owner"* ]]'
rm -rf "$SANDBOX"

# B-SH-14 successful retry after a fail-closed run restores readiness ---------
echo "B-SH-14 recovery: fail closed, then a successful run restores nginx"
new_sandbox
seed_previously_healthy
echo 999 >"$SANDBOX/apt_update_failures"
run_startup
check B-SH-14.first-failed-closed '[[ $RC -ne 0 && ! -f "$SANDBOX/nginx_active" && ! -f "$SANDBOX/nginx_enabled" ]]'
echo 0 >"$SANDBOX/apt_update_failures"
: >"$SANDBOX/calls"
: >"$SANDBOX/sleeps"
run_startup
check B-SH-14.rc '[[ $RC -eq 0 ]]'
check B-SH-14.ok-log '[[ "$OUT" == *"SECURE_WEB_BOOTSTRAP=OK"* ]]'
check B-SH-14.markers '[[ -f "$SANDBOX/state/bootstrap.ok" && ! -f "$SANDBOX/state/bootstrap.failed" ]]'
check B-SH-14.nginx-restored '[[ -f "$SANDBOX/nginx_active" && -f "$SANDBOX/nginx_enabled" ]]'
check B-SH-14.no-stop '! grep -qE "^systemctl (stop|disable)" "$SANDBOX/calls"'
rm -rf "$SANDBOX"

# B-SH-15 repeated successful runs stay idempotent and never stop nginx -------
echo "B-SH-15 three successful runs in a row"
new_sandbox
run_startup
rc1=$RC
run_startup
rc2=$RC
run_startup
check B-SH-15.all-rc0 '[[ $rc1 -eq 0 && $rc2 -eq 0 && $RC -eq 0 ]]'
check B-SH-15.install-once '[[ $(count_calls "apt-get .*update") -eq 1 ]]'
check B-SH-15.content-unchanged '[[ "$OUT" == *"index.html unchanged"* ]]'
check B-SH-15.never-stopped '! grep -qE "^systemctl (stop|disable)" "$SANDBOX/calls"'
check B-SH-15.ready '[[ -f "$SANDBOX/state/bootstrap.ok" && -f "$SANDBOX/nginx_active" && -f "$SANDBOX/nginx_enabled" ]]'
rm -rf "$SANDBOX"

# B-SH-9 no credentials in the script ----------------------------------------
echo "B-SH-9 no credential-like content in startup.sh"
OUT=""
check B-SH-9.no-secrets '! grep -Eiq "(BEGIN [A-Z ]*PRIVATE KEY|password[[:space:]]*=|token[[:space:]]*=|api[_-]?key|secret[[:space:]]*=|AKIA[0-9A-Z]{16}|\"type\": *\"service_account\")" "$STARTUP"'

echo
echo "startup.sh tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
