#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLI_REPO=${COPPICE_CLI_REPO:-"$ROOT/../coppice-cli"}
CLI=${COPPICE_CLI:-"$CLI_REPO/target/release/coppice-cli"}
WALLET_DIR=${COPPICE_WALLET_DIR:-"$ROOT/.coppice-testnet-v0"}
IDENTITY="$WALLET_DIR/age-identity.txt"
ADDRESS_FILE="$WALLET_DIR/unified-address.txt"
ACTIVATION=4288414

if [[ ! -x "$CLI" ]]; then
  cargo build --release --manifest-path "$CLI_REPO/Cargo.toml"
fi

initialize() {
  if [[ ! -f "$WALLET_DIR/keys.toml" ]]; then
    mkdir -p "$WALLET_DIR"
    printf '\n' | "$CLI" wallet --wallet-dir "$WALLET_DIR" init \
      --name coppice-testnet-v0 --identity "$IDENTITY" \
      --birthday "$ACTIVATION" --network test
  fi
  if [[ ! -f "$ADDRESS_FILE" ]]; then
    "$CLI" wallet --wallet-dir "$WALLET_DIR" generate-address \
      | sed -n 's/^ *Address: //p' | head -1 > "$ADDRESS_FILE"
  fi
}

wallet_sync() {
  "$CLI" wallet --wallet-dir "$WALLET_DIR" sync
  "$CLI" coppice --wallet-dir "$WALLET_DIR" sync
}

balance_json() {
  "$CLI" wallet --wallet-dir "$WALLET_DIR" balance --min-confirmations 1 --json
}

status() {
  local balance
  balance=$(balance_json)
  "$CLI" coppice --wallet-dir "$WALLET_DIR" status
  printf 'address: %s\n' "$(cat "$ADDRESS_FILE")"
  printf 'wallet: %s\n' "$balance"
}

funding_help() {
  printf '\nWallet needs testnet ZEC.\n\nAddress:\n%s\n\nGet TAZ from:\nhttps://zcashfaucet.jinolabs.xyz/\n\nAfter funding, run:\n./coppice-playground.sh sync\n' "$(cat "$ADDRESS_FILE")"
}

run_action() {
  local verb=$1 name=$2
  local output
  shift 2
  wallet_sync
  if ! output=$("$CLI" coppice --wallet-dir "$WALLET_DIR" "$verb" "$name" "$@" --identity "$IDENTITY" 2>&1); then
    printf '%s\n' "$output" >&2
    if [[ "$output" == *"Insufficient"* || "$output" == *"needs an unlocked Ironwood note"* ]]; then
      funding_help
    fi
    return 1
  fi
  printf '%s\n' "$output"
}

interactive() {
  wallet_sync
  while true; do
    printf '\nCoppice Testnet V0\nNetwork: Zcash testnet\nActivation height: 4,288,414\n'
    status
    printf '\n[r] Register  [u] Update  [x] Release  [l] Resolve  [n] Names  [p] Pending  [k] Owner key  [w] Watch  [q] Quit\n> '
    read -r choice
    case "$choice" in
      r) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua; run_action register "$name" "$ua" ;;
      u) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua; run_action update "$name" "$ua" ;;
      x) read -r -p 'Name: ' name; run_action release "$name" ;;
      l) read -r -p 'Name: ' name; "$CLI" coppice --wallet-dir "$WALLET_DIR" resolve "$name" || true ;;
      n) "$CLI" coppice --wallet-dir "$WALLET_DIR" names ;;
      p) "$CLI" coppice --wallet-dir "$WALLET_DIR" pending ;;
      k) "$CLI" coppice --wallet-dir "$WALLET_DIR" owner-key --identity "$IDENTITY" ;;
      w) "$CLI" coppice --wallet-dir "$WALLET_DIR" watch ;;
      q) return ;;
    esac
  done
}

initialize
case "${1:-}" in
  register|update) [[ $# -eq 3 ]] || { echo "usage: $0 $1 NAME UA" >&2; exit 2; }; run_action "$1" "$2" "$3" ;;
  release) [[ $# -eq 2 ]] || { echo "usage: $0 release NAME" >&2; exit 2; }; run_action release "$2" ;;
  resolve) [[ $# -eq 2 ]] || { echo "usage: $0 resolve NAME" >&2; exit 2; }; wallet_sync; "$CLI" coppice --wallet-dir "$WALLET_DIR" resolve "$2" ;;
  watch) "$CLI" coppice --wallet-dir "$WALLET_DIR" watch ;;
  sync) wallet_sync ;;
  status) status ;;
  names) wallet_sync; "$CLI" coppice --wallet-dir "$WALLET_DIR" names ;;
  pending) "$CLI" coppice --wallet-dir "$WALLET_DIR" pending ;;
  owner-key) "$CLI" coppice --wallet-dir "$WALLET_DIR" owner-key --identity "$IDENTITY" ;;
  "") interactive ;;
  *) echo "usage: $0 [register NAME UA|update NAME UA|release NAME|resolve NAME|names|pending|owner-key|watch|sync|status]" >&2; exit 2 ;;
esac
