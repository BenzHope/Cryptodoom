#!/usr/bin/env bash
# ops/runbook.sh — the launcher. All policy lives here.
# The engine never reads .env, never prompts, never writes logs.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

# shellcheck source=ops/gates.sh
. ops/gates.sh
# shellcheck source=ops/log.sh
. ops/log.sh

usage() {
  cat <<'EOF'
usage: ./ops/runbook.sh <command>

ladder (safest first):
  selftest         no network, no money. hashes, disassembler, rules, boundary
  plan             read-only discovery + ranking across PLAN_CHAINS
  simulate         analyse LIVE_TARGET, simulate steps, send nothing
  status           re-read LIVE_TARGET state, read only

live (needs AUTHORIZED=yes and a written AUTHORIZATION.md):
  arm              print resolved gates, ask for confirmation
  live             arm + fire, bounded by MAX_TXS
  live-auto        fire with no prompt. fork/testnet only

housekeeping:
  logs             list recent dashcam files
  doctor           print resolved gates without running anything
  help
EOF
}

require_venv() {
  [ -d "$ROOT/.venv" ] || die ".venv missing — run: bash scripts/install.sh"
  # shellcheck disable=SC1091
  . "$ROOT/.venv/bin/activate"
}

# engine wrapper: engine never sees the environment, only flags
engine() {
  local args=()
  [ -n "${PRIVATE_KEY:-}" ] && args+=(--pk "$PRIVATE_KEY")
  [ -n "${API_KEY:-}" ]     && args+=(--api-key "$API_KEY")
  [ -n "${RPC_ETHEREUM:-}" ] && args+=(--rpc "ethereum=$RPC_ETHEREUM")
  [ -n "${RPC_BSC:-}" ]      && args+=(--rpc "bsc=$RPC_BSC")
  [ -n "${RPC_POLYGON:-}" ]  && args+=(--rpc "polygon=$RPC_POLYGON")
  [ -n "${RPC_ARBITRUM:-}" ] && args+=(--rpc "arbitrum=$RPC_ARBITRUM")
  [ -n "${RPC_BASE:-}" ]     && args+=(--rpc "base=$RPC_BASE")
  [ -n "${RPC_OPTIMISM:-}" ] && args+=(--rpc "optimism=$RPC_OPTIMISM")
  [ -n "${RPC_AVALANCHE:-}" ] && args+=(--rpc "avalanche=$RPC_AVALANCHE")
  [ -n "${RPC_FANTOM:-}" ]   && args+=(--rpc "fantom=$RPC_FANTOM")
  python "$ROOT/v6.py" "${args[@]}" "$@"
}

wallet_address() {
  python - <<'PY'
import os
from eth_account import Account
print(Account.from_key(os.environ["PRIVATE_KEY"]).address)
PY
}

cmd_selftest() {
  require_venv
  python "$ROOT/verify.py"
  python "$ROOT/v6.py" --self-test
  python "$ROOT/v6_offline.py" --seed 1337
  python -m pytest "$ROOT/tests" -q
}

cmd_plan() {
  require_venv; load_env
  engine --plan \
    --chains "${PLAN_CHAINS:-arbitrum,base}" \
    --age "${PLAN_AGE:-1-6}" \
    --min-tvl "${MIN_TVL:-0.05}" \
    --min-profit "${MIN_PROFIT:-0.0004}" \
    --max-targets "${MAX_TARGETS:-40}"
}

cmd_simulate() {
  require_venv; load_env; gate_target
  WALLET_ADDRESS="$(wallet_address)"
  engine --target "$LIVE_TARGET" --chain "$LIVE_CHAIN" --max "${MAX_TXS:-1}"
}

cmd_status() {
  require_venv; load_env; gate_target
  engine --target "$LIVE_TARGET" --chain "$LIVE_CHAIN" --max 0
}

cmd_arm() {
  require_venv; load_env; gate_mainnet
  WALLET_ADDRESS="$(wallet_address)"
  export WALLET_ADDRESS
  print_gates
  local bal
  bal="$(python - "$LIVE_CHAIN" "$WALLET_ADDRESS" <<'PY'
import sys
sys.path.insert(0, ".")
import v6
chain, addr = sys.argv[1], sys.argv[2]
w3 = v6.Rpc().get(chain)
print(f"{w3.eth.get_balance(v6.Web3.to_checksum_address(addr)) / 1e18:.6f}")
PY
)"
  printf 'gas balance  %s %s\n\n' "$bal" "${LIVE_CHAIN^^}"
  printf 'Type I_UNDERSTAND to fire: '
  local got
  read -r got
  [ "$got" = "I_UNDERSTAND" ] || die "you typed '$got'"
}

cmd_live() {
  require_venv; load_env
  cmd_arm
  log_run "live_${LIVE_CHAIN}" \
    python "$ROOT/v6.py" \
      --pk "$PRIVATE_KEY" ${API_KEY:+--api-key "$API_KEY"} \
      --target "$LIVE_TARGET" --chain "$LIVE_CHAIN" \
      --execute --max "$MAX_TXS"
}

cmd_live_auto() {
  require_venv; load_env; gate_auto
  log_run "auto_${LIVE_CHAIN}" \
    python "$ROOT/v6.py" \
      --pk "$PRIVATE_KEY" ${API_KEY:+--api-key "$API_KEY"} \
      --target "$LIVE_TARGET" --chain "$LIVE_CHAIN" \
      --execute --max "$MAX_TXS"
}

cmd_doctor() { load_env; WALLET_ADDRESS="$(wallet_address 2>/dev/null || echo unset)"; print_gates; }

cmd="${1:-help}"; shift || true
case "$cmd" in
  selftest)   cmd_selftest ;;
  plan)       cmd_plan ;;
  simulate)   log_run "simulate_${LIVE_CHAIN:-x}" cmd_simulate ;;
  status)     cmd_status ;;
  arm)        cmd_arm ;;
  live)       cmd_live ;;
  live-auto)  cmd_live_auto ;;
  logs)       list_logs ;;
  doctor)     cmd_doctor ;;
  help|-h|--help) usage ;;
  *) usage; die "unknown command: $cmd" ;;
esac
