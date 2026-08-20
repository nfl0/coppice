#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEVTOOL_REPO=${ZCASH_DEVTOOL_REPO:-"$ROOT/../zcash-devtool"}
DEVTOOL=${ZCASH_DEVTOOL:-"$DEVTOOL_REPO/target/release/zcash-devtool"}
WALLET_DIR=${COPPICE_WALLET_DIR:-"$ROOT/.coppice-testnet-v0"}
IDENTITY="$WALLET_DIR/age-identity.txt"
ADDRESS_FILE="$WALLET_DIR/unified-address.txt"
ACTIVATION=4288414

if [[ ! -x "$DEVTOOL" ]]; then
  cargo build --release --manifest-path "$DEVTOOL_REPO/Cargo.toml"
fi

initialize() {
  if [[ ! -f "$WALLET_DIR/keys.toml" ]]; then
    mkdir -p "$WALLET_DIR"
    printf '\n' | "$DEVTOOL" wallet --wallet-dir "$WALLET_DIR" init \
      --name coppice-testnet-v0 --identity "$IDENTITY" \
      --birthday "$ACTIVATION" --network test
  fi
  if [[ ! -f "$ADDRESS_FILE" ]]; then
    "$DEVTOOL" wallet --wallet-dir "$WALLET_DIR" generate-address \
      | sed -n 's/^ *Address: //p' | head -1 > "$ADDRESS_FILE"
  fi
}

wallet_sync() {
  "$DEVTOOL" wallet --wallet-dir "$WALLET_DIR" sync
  "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" sync
}

balance_json() {
  "$DEVTOOL" wallet --wallet-dir "$WALLET_DIR" balance --min-confirmations 1 --json
}

status() {
  local balance
  balance=$(balance_json)
  "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" status
  printf 'address: %s\n' "$(cat "$ADDRESS_FILE")"
  printf 'wallet: %s\n' "$balance"
}

funding_help() {
  printf '\nWallet needs testnet ZEC.\n\nAddress:\n%s\n\nGet TAZ from:\nhttps://zcashfaucet.jinolabs.xyz/\n\nAfter funding, run:\n./coppice-playground.sh sync\n' "$(cat "$ADDRESS_FILE")"
}

run_action() {
  local verb=$1 name=$2
  shift 2
  wallet_sync
  if ! "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" "$verb" "$name" "$@" --identity "$IDENTITY"; then
    funding_help
    return 1
  fi
}

interactive() {
  wallet_sync
  while true; do
    printf '\nCoppice Testnet V0\nNetwork: Zcash testnet\nActivation height: 4,288,414\n'
    status
    printf '\n[r] Register  [u] Update  [x] Release  [l] Resolve  [w] Watch  [q] Quit\n> '
    read -r choice
    case "$choice" in
      r) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua; run_action register "$name" "$ua" ;;
      u) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua; run_action update "$name" "$ua" ;;
      x) read -r -p 'Name: ' name; run_action release "$name" ;;
      l) read -r -p 'Name: ' name; "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" resolve "$name" || true ;;
      w) "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" watch ;;
      q) return ;;
    esac
  done
}

initialize
case "${1:-}" in
  register|update) [[ $# -eq 3 ]] || { echo "usage: $0 $1 NAME UA" >&2; exit 2; }; run_action "$1" "$2" "$3" ;;
  release) [[ $# -eq 2 ]] || { echo "usage: $0 release NAME" >&2; exit 2; }; run_action release "$2" ;;
  resolve) [[ $# -eq 2 ]] || { echo "usage: $0 resolve NAME" >&2; exit 2; }; wallet_sync; "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" resolve "$2" ;;
  watch) "$DEVTOOL" coppice --wallet-dir "$WALLET_DIR" watch ;;
  sync) wallet_sync ;;
  status) status ;;
  "") interactive ;;
  *) echo "usage: $0 [register NAME UA|update NAME UA|release NAME|resolve NAME|watch|sync|status]" >&2; exit 2 ;;
esac
