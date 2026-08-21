#!/usr/bin/env bash
# POC-only, deterministic multi-wallet exercise. The script advances the chain
# only at the explicit confirmation boundaries below; there is no background
# or interval miner.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PLAYGROUND="$ROOT/scripts/regtest-playground.sh"
DEVTOOL=${ZCASH_DEVTOOL:-"$ROOT/../zcash-devtool/target/release/zcash-devtool"}
STATE=${COPPICE_REGTEST_DIR:-"$ROOT/.coppice-regtest"}
SERVER=${COPPICE_REGTEST_SERVER:-127.0.0.1:28137}
LOG_DIR=${COPPICE_REGTEST_LOG_DIR:-"$ROOT/logs"}

mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/regtest-multiwallet-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1

say() { printf '\n==> %s\n' "$*"; }
controlled_mine() {
  local count=$1
  say "mining $count explicit block(s)"
  "$PLAYGROUND" mine "$count"
}
wallet_dir() { printf '%s/wallet-%s' "$STATE" "$1"; }
identity() { printf '%s/age-identity.txt' "$(wallet_dir "$1")"; }
wallet() { local n=$1; shift; "$DEVTOOL" wallet --wallet-dir "$(wallet_dir "$n")" "$@"; }
coppice() { local n=$1; shift; "$DEVTOOL" coppice --wallet-dir "$(wallet_dir "$n")" "$@"; }
ua() { wallet "$1" list-addresses --receiver unified | sed -n 's/^     Default Address: //p'; }
taddr() { wallet "$1" list-addresses --receiver transparent | sed -n 's/^Receiver(transparent): //p' | head -1; }

[[ "${1:-}" == "--reset" ]] || {
  echo "usage: $0 --reset"
  echo "This removes only the disposable local Z3 regtest volumes and .coppice-regtest state."
  exit 2
}
[[ -x "$DEVTOOL" ]] || { echo "missing zcash-devtool: $DEVTOOL"; exit 1; }

say "resetting local regtest"
"$PLAYGROUND" reset
sleep 20

say "starting services with the disposable bootstrap miner"
"$PLAYGROUND" start
controlled_mine 2
"$PLAYGROUND" start

say "creating one wallet 1 coinbase reward"
controlled_mine 1

# Move mining to wallet 3 before mining confirmations. This avoids the generic
# transparent-input selector repeatedly choosing a newly created wallet-1
# coinbase while preparing its initial shielded notes.
ALT_MINER=$(taddr 3)
[[ -n "$ALT_MINER" ]] || { echo "wallet 3 has no transparent receiver"; exit 1; }
say "maturing wallet 1 funds while wallet 3 mines"
"$PLAYGROUND" stop
sleep 20
COPPICE_REGTEST_MINER_ADDRESS="$ALT_MINER" "$PLAYGROUND" start
controlled_mine 101

say "shielding wallet 1 funds into real Ironwood notes"
wallet 1 shield --identity "$(identity 1)" --server "$SERVER"
controlled_mine 3

say "committing alice registration from wallet 1"
ALICE_UA=$(ua 1)
[[ -n "$ALICE_UA" ]] || { echo "wallet 1 has no unified address"; exit 1; }
coppice 1 register alice "$ALICE_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
say "revealing alice registration from wallet 1"
coppice 1 register alice "$ALICE_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
coppice 1 resolve alice
coppice 2 resolve alice

say "updating alice from wallet 1"
coppice 1 update alice "$ALICE_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
coppice 2 resolve alice

say "multi-wallet smoke test reached the registered and updated state"
echo "log: $LOG"
