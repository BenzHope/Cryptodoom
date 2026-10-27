#!/usr/bin/env bash
# ops/log.sh — dashcam. Sourced by runbook.sh, never executed.
# shellcheck shell=bash

LOG_DIR="${LOG_DIR:-logs}"

log_run() {
  local name="$1"; shift
  mkdir -p "$LOG_DIR"
  local stamp file
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  file="$LOG_DIR/${stamp}_${name}.log"

  {
    printf '# run      %s\n' "$name"
    printf '# utc      %s\n' "$stamp"
    printf '# network  %s\n' "${NETWORK:-unset}"
    printf '# chain    %s\n' "${LIVE_CHAIN:-unset}"
    printf '# target   %s\n' "${LIVE_TARGET:-unset}"
    printf '# max_txs  %s\n' "${MAX_TXS:-unset}"
    printf '# cmd      %s\n\n' "$*"
  } > "$file"

  local rc=0
  set +e
  "$@" 2>&1 | tee -a "$file"
  rc="${PIPESTATUS[0]}"
  set -e

  printf '\n# exit=%s\n' "$rc" >> "$file"
  printf 'log: %s\n' "$file"
  return "$rc"
}

list_logs() {
  [ -d "$LOG_DIR" ] || { echo "no logs yet"; return 0; }
  ls -lt "$LOG_DIR"/*.log 2>/dev/null | head -20 || echo "no logs yet"
}
