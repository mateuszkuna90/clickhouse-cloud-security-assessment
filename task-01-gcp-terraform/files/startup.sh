#!/usr/bin/env bash
# Bootstrap for the Task 1 backend VM: install nginx and serve a static page
# on port 80 for the load balancer and its health check.
#
# Runs as root via the Compute Engine guest agent on EVERY boot, so every step
# is idempotent. Contains no credentials and reads no secrets.
#
# Result signals:
#   success: /var/lib/secure-web/bootstrap.ok, log "SECURE_WEB_BOOTSTRAP=OK", exit 0
#   failure: FAIL CLOSED. Any stale bootstrap.ok is removed,
#            /var/lib/secure-web/bootstrap.failed records the step, and log
#            "SECURE_WEB_BOOTSTRAP=FAILED step=<step>" is written. If this run
#            holds the bootstrap lock, nginx is stopped AND disabled, even if it
#            was already running from an earlier boot, so the health check on
#            port 80 fails and the load balancer stops sending traffic. Exit is
#            non-zero. The next successful run re-enables and starts nginx.
set -Eeuo pipefail

# Test-only overrides. They are unset on Compute Engine and change paths and
# timing only, never what is installed.
STATE_DIR="${BOOTSTRAP_STATE_DIR:-/var/lib/secure-web}"
WEB_ROOT="${BOOTSTRAP_WEB_ROOT:-/var/www/html}"
LOCK_FILE="${BOOTSTRAP_LOCK_FILE:-/run/secure-web-bootstrap.lock}"
MAX_ATTEMPTS="${BOOTSTRAP_MAX_ATTEMPTS:-5}"
BACKOFF_BASE_SECONDS="${BOOTSTRAP_BACKOFF_BASE_SECONDS:-10}"

readonly HARD_MAX_ATTEMPTS=10
readonly HARD_MAX_BACKOFF_BASE_SECONDS=60
readonly ATTEMPT_TIMEOUT_SECONDS=120
readonly LOCK_WAIT_SECONDS=600
readonly SELF_CHECK_ATTEMPTS=5
readonly SELF_CHECK_DELAY_SECONDS=2

# Clamp overrides so the retry loop is always bounded.
if ! [[ "$MAX_ATTEMPTS" =~ ^[0-9]+$ ]] || [[ "$MAX_ATTEMPTS" -lt 1 ]]; then
  MAX_ATTEMPTS=5
fi
if [[ "$MAX_ATTEMPTS" -gt "$HARD_MAX_ATTEMPTS" ]]; then
  MAX_ATTEMPTS="$HARD_MAX_ATTEMPTS"
fi
if ! [[ "$BACKOFF_BASE_SECONDS" =~ ^[0-9]+$ ]]; then
  BACKOFF_BASE_SECONDS=10
fi
if [[ "$BACKOFF_BASE_SECONDS" -gt "$HARD_MAX_BACKOFF_BASE_SECONDS" ]]; then
  BACKOFF_BASE_SECONDS="$HARD_MAX_BACKOFF_BASE_SECONDS"
fi

export DEBIAN_FRONTEND=noninteractive
CURRENT_STEP="init"
LOCK_HELD=0

log() {
  echo "secure-web-bootstrap: $*"
}

# Withdraw backend readiness. Only the run that holds the lock may do this, so
# a run that merely failed to get the lock cannot stop a healthy bootstrap
# owned by another run.
withdraw_readiness() {
  if [[ "$LOCK_HELD" -ne 1 ]]; then
    log "lock not held; leaving nginx state to the lock owner"
    return 0
  fi
  if systemctl stop nginx; then
    log "nginx stopped (fail closed)"
  else
    log "WARNING: systemctl stop nginx failed"
  fi
  # Disable too, so a reboot does not bring nginx (and a passing health check)
  # back before this script has succeeded again.
  if systemctl disable nginx; then
    log "nginx disabled until the next successful bootstrap"
  else
    log "WARNING: systemctl disable nginx failed"
  fi
}

on_error() {
  local rc=$?
  trap - ERR
  set +e # best effort from here: never abort the failure path half-way
  [[ "$rc" -eq 0 ]] && rc=1
  mkdir -p "$STATE_DIR"
  rm -f "$STATE_DIR/bootstrap.ok"
  printf 'step=%s exit=%s time=%s\n' "$CURRENT_STEP" "$rc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"$STATE_DIR/bootstrap.failed"
  withdraw_readiness
  log "SECURE_WEB_BOOTSTRAP=FAILED step=$CURRENT_STEP exit=$rc"
  exit "$rc"
}
trap on_error ERR

# retry_backoff CMD...: up to MAX_ATTEMPTS tries, sleeping
# BACKOFF_BASE_SECONDS * 2^(n-1) between them (10, 20, 40, 80 s by default).
retry_backoff() {
  local attempt=1 delay
  while true; do
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
      log "step=$CURRENT_STEP gave up after $attempt attempts"
      return 1
    fi
    delay=$((BACKOFF_BASE_SECONDS * (1 << (attempt - 1))))
    log "step=$CURRENT_STEP attempt $attempt/$MAX_ATTEMPTS failed; retrying in ${delay}s"
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

# retry_fixed ATTEMPTS DELAY CMD...: bounded retries with a fixed delay.
retry_fixed() {
  local max=$1 delay=$2 attempt=1
  shift 2
  while true; do
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -ge "$max" ]]; then
      log "step=$CURRENT_STEP gave up after $attempt attempts"
      return 1
    fi
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

nginx_installed() {
  # shellcheck disable=SC2016 # ${Status} is a dpkg-query format field, not a shell variable.
  dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q "install ok installed"
}

# One attempt = apt-get update + install, bounded by a single timeout.
install_nginx_once() {
  timeout "$ATTEMPT_TIMEOUT_SECONDS" sh -c '
    apt-get -q -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 update &&
    apt-get -q -y -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 install --no-install-recommends nginx
  '
}

write_index() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'HTML'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>secure-web</title></head>
<body><p>OK: served by nginx on a private Compute Engine VM.</p></body>
</html>
HTML
  if [[ -f "$WEB_ROOT/index.html" ]] && cmp -s "$tmp" "$WEB_ROOT/index.html"; then
    rm -f "$tmp"
    log "index.html unchanged"
    return 0
  fi
  mkdir -p "$WEB_ROOT"
  install -m 0644 "$tmp" "$WEB_ROOT/index.html"
  rm -f "$tmp"
  log "index.html written"
}

http_ok() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -o /dev/null --max-time 5 http://127.0.0.1/
  else
    # Fallback if the image has no curl.
    local status
    exec 3<>/dev/tcp/127.0.0.1/80 || return 1
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
    IFS= read -r -t 5 status <&3 || status=""
    exec 3<&- 3>&-
    [[ "$status" == *" 200 "* ]]
  fi
}

self_check() {
  systemctl is-active --quiet nginx && http_ok
}

main() {
  mkdir -p "$STATE_DIR"

  CURRENT_STEP="lock"
  exec 9>"$LOCK_FILE"
  flock -w "$LOCK_WAIT_SECONDS" 9
  LOCK_HELD=1

  # A success marker from an earlier run must not survive into this run.
  rm -f "$STATE_DIR/bootstrap.ok"

  CURRENT_STEP="install"
  if nginx_installed; then
    log "nginx already installed; skipping package install"
  else
    retry_backoff install_nginx_once
  fi

  CURRENT_STEP="content"
  write_index

  CURRENT_STEP="service"
  systemctl enable --now nginx

  CURRENT_STEP="self_check"
  retry_fixed "$SELF_CHECK_ATTEMPTS" "$SELF_CHECK_DELAY_SECONDS" self_check

  CURRENT_STEP="done"
  date -u +%Y-%m-%dT%H:%M:%SZ >"$STATE_DIR/bootstrap.ok"
  rm -f "$STATE_DIR/bootstrap.failed"
  log "SECURE_WEB_BOOTSTRAP=OK"
}

main "$@"
