#!/usr/bin/env bash
# ops/gates.sh — precondition checks. Sourced by runbook.sh, never executed.
# shellcheck shell=bash

ENV_FILE="${ENV_FILE:-.env}"

die()  { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
warn() { printf 'warn: %s\n' "$*" >&2; }

load_env() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE missing — cp .env.example .env"
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
}

need() {
  local name="$1" want="${2:-}"
  local val="${!name:-}"
  [ -n "$val" ] || die "$name is empty (set it in $ENV_FILE)"
  if [ -n "$want" ] && [ "$val" != "$want" ]; then
    die "$name must be exactly '$want' (got '$val')"
  fi
}

need_int() {
  local name="$1" val="${!1:-}"
  case "$val" in
    ''|*[!0-9]*) die "$name must be a positive integer (got '$val')" ;;
  esac
  [ "$val" -ge 1 ] || die "$name must be >= 1"
}

# --- the permission slip is load-bearing -------------------------------
auth_covers() {
  local chain="$1" target="$2"
  need AUTH_FILE
  [ -f "$AUTH_FILE" ] || die "$AUTH_FILE missing"
  grep -qi -- "$chain" "$AUTH_FILE" \
    || die "$AUTH_FILE does not mention chain '$chain'"
  local short="${target:0:12}"
  grep -qi -- "$short" "$AUTH_FILE" \
    || die "$AUTH_FILE does not mention target $short..."
  grep -qi -- 'approved' "$AUTH_FILE" \
    || warn "$AUTH_FILE has no 'Approved' line"
}

# --- ladder rungs ------------------------------------------------------
gate_selftest() { :; }
gate_plan()     { :; }

gate_target() {
  need LIVE_CHAIN
  need LIVE_TARGET
  case "$LIVE_TARGET" in 0x*) ;; *) die "LIVE_TARGET must be 0x-prefixed" ;; esac
  [ "${#LIVE_TARGET}" -eq 42 ] || die "LIVE_TARGET must be 42 chars"
  case "$LIVE_TARGET" in
    *[!0-9a-fA-Fx]*) die "LIVE_TARGET has non-hex characters" ;;
  esac
}

gate_live() {
  gate_target
  need AUTHORIZED yes
  need CONFIRM_LIVE I_UNDERSTAND
  need MAX_TXS
  need_int MAX_TXS
  [ "$MAX_TXS" -le 5 ] || warn "MAX_TXS=$MAX_TXS is large for a first run"
  auth_covers "$LIVE_CHAIN" "$LIVE_TARGET"
  need PK_OR_PRIVATE_KEY 2>/dev/null || true
  if [ -z "${PRIVATE_KEY:-}" ]; then die "PRIVATE_KEY is empty"; fi
}

gate_mainnet() {
  gate_live
  if [ "${NETWORK:-}" = "mainnet" ]; then
    need MAINNET_ACK I_HAVE_WRITTEN_MAINNET_SCOPE
    need TARGET_ALLOWLIST
    printf '%s' "$TARGET_ALLOWLIST" | tr ',' '\n' \
      | sed 's/^ *//;s/ *$//' | grep -qix -- "$LIVE_TARGET" \
      || die "LIVE_TARGET not present in TARGET_ALLOWLIST"
    printf 'MAINNET CONFIRMED: %s on %s, max %s tx\n' \
      "$LIVE_TARGET" "$LIVE_CHAIN" "$MAX_TXS"
  fi
}

gate_auto() {
  gate_live
  need LIVE_AUTO yes
  need ALLOW_AUTOMATION yes
  case "${NETWORK:-}" in
    fork|testnet) ;;
    *) die "live-auto is fork/testnet only (NETWORK=${NETWORK:-unset})" ;;
  esac
}

print_gates() {
  printf '\n--- resolved gates ---\n'
  printf 'network      %s\n' "${NETWORK:-unset}"
  printf 'chain        %s\n' "${LIVE_CHAIN:-unset}"
  printf 'target       %s\n' "${LIVE_TARGET:-unset}"
  printf 'max txs      %s\n' "${MAX_TXS:-unset}"
  printf 'authorized   %s\n' "${AUTHORIZED:-unset}"
  printf 'auth file    %s\n' "${AUTH_FILE:-unset}"
  printf 'wallet       %s\n' "${WALLET_ADDRESS:-unset}"
  printf '----------------------\n\n'
}
