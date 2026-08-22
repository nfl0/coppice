#!/usr/bin/env bash
# Test-only, deterministic multi-wallet exercise. The script advances the chain
# only at the explicit confirmation boundaries below; there is no background
# or interval miner.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PLAYGROUND="$ROOT/scripts/regtest-playground.sh"
CLI=${COPPICE_CLI:-"$ROOT/../coppice-cli/target/release/coppice-cli"}
STATE=${COPPICE_REGTEST_DIR:-"$ROOT/.coppice-regtest"}
SERVER=${COPPICE_REGTEST_SERVER:-127.0.0.1:28137}
LOG_DIR=${COPPICE_REGTEST_LOG_DIR:-"$ROOT/logs"}
BOND_NOTE_VALUE=120000000
FEE_NOTE_VALUE=20000000

mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/regtest-multiwallet-$(date -u +%Y%m%dT%H%M%SZ).log"
# Podman's configured-driver warning is a host-storage issue, not a Coppice
# result. Keep it visible outside this harness if Podman is invoked directly,
# but omit it from the durable scenario log.
exec > >(sed -u '/User-selected graph driver .* overwritten by graph driver .* from database/d' | tee -a "$LOG") 2>&1

say() { printf '\n==> %s\n' "$*"; }
controlled_mine() {
  local count=$1
  say "mining $count explicit block(s)"
  "$PLAYGROUND" mine "$count"
}
wallet_dir() { printf '%s/wallet-%s' "$STATE" "$1"; }
identity() { printf '%s/age-identity.txt' "$(wallet_dir "$1")"; }
wallet() { local n=$1; shift; "$CLI" wallet --wallet-dir "$(wallet_dir "$n")" "$@"; }
coppice() { local n=$1; shift; "$CLI" coppice --wallet-dir "$(wallet_dir "$n")" "$@"; }
ua() { wallet "$1" list-addresses --receiver unified | sed -n 's/^     Default Address: //p'; }
taddr() { wallet "$1" list-addresses --receiver transparent | sed -n 's/^Receiver(transparent): //p' | head -1; }
assert_resolve() {
  local observer=$1 name=$2 expected=$3 result
  result=$(coppice "$observer" resolve "$name" --server "$SERVER")
  printf '%s\n' "$result"
  [[ "$result" == *"$expected"* ]] || {
    echo "unexpected resolution for $name: expected '$expected'"
    exit 1
  }
}

[[ "${1:-}" == "--reset" ]] || {
  echo "usage: $0 --reset"
  echo "This removes only the disposable local Z3 regtest volumes and .coppice-regtest state."
  exit 2
}
[[ -x "$CLI" ]] || { echo "missing coppice-cli: $CLI"; exit 1; }

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
say "maturing the funding reward while wallet 3 mines"
"$PLAYGROUND" stop
sleep 20
COPPICE_REGTEST_MINER_ADDRESS="$ALT_MINER" "$PLAYGROUND" start
controlled_mine 100

say "shielding the funding wallet into real Ironwood notes"
wallet 1 shield --identity "$(identity 1)" --server "$SERVER"
controlled_mine 3

say "distributing separate Ironwood bond and fee notes to wallets 2 and 3"
WALLET_2_UA=$(ua 2)
WALLET_3_UA=$(ua 3)
[[ -n "$WALLET_2_UA" && -n "$WALLET_3_UA" ]] || {
  echo "participant wallet is missing a unified address"
  exit 1
}
wallet 1 send --identity "$(identity 1)" --server "$SERVER" \
  --address "$WALLET_2_UA" --value "$BOND_NOTE_VALUE" --min-confirmations 1
wallet 1 send --identity "$(identity 1)" --server "$SERVER" \
  --address "$WALLET_2_UA" --value "$FEE_NOTE_VALUE" --min-confirmations 1
wallet 1 send --identity "$(identity 1)" --server "$SERVER" \
  --address "$WALLET_3_UA" --value "$BOND_NOTE_VALUE" --min-confirmations 1
wallet 1 send --identity "$(identity 1)" --server "$SERVER" \
  --address "$WALLET_3_UA" --value "$FEE_NOTE_VALUE" --min-confirmations 1
# Three confirmations are the wallet's minimum trusted-note spend policy used
# by the Coppice registration builder.
controlled_mine 3

say "committing alice registration from wallet 1"
ALICE_UA=$(ua 1)
[[ -n "$ALICE_UA" ]] || { echo "wallet 1 has no unified address"; exit 1; }
OWNER_KEY=$(coppice 1 owner-key --identity "$(identity 1)")
[[ "$OWNER_KEY" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid Coppice owner key"; exit 1; }
coppice 1 register alice "$ALICE_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
PENDING=$(coppice 1 pending --server "$SERVER")
printf '%s\n' "$PENDING"
[[ "$PENDING" == *$'alice\tReadyToReveal'* ]] || { echo "alice reveal is not ready"; exit 1; }
say "revealing alice registration from wallet 1"
coppice 1 register alice "$ALICE_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
assert_resolve 1 alice "alice: Active $ALICE_UA"
assert_resolve 2 alice "alice: Active $ALICE_UA"
assert_resolve 3 alice "alice: Active $ALICE_UA"
NAMES=$(coppice 2 names --server "$SERVER")
printf '%s\n' "$NAMES"
[[ "$NAMES" == *$'alice\tActive'* ]] || { echo "alice missing from name inventory"; exit 1; }
[[ "$(coppice 1 pending --server "$SERVER")" == "No pending Coppice registrations." ]] || {
  echo "completed alice registration remains pending"
  exit 1
}

say "updating alice from wallet 1"
coppice 1 update alice "$WALLET_3_UA" --identity "$(identity 1)" --server "$SERVER"
controlled_mine 1
assert_resolve 3 alice "alice: Active $WALLET_3_UA"

say "committing bob registration from wallet 2"
coppice 2 register bob "$WALLET_2_UA" --identity "$(identity 2)" --server "$SERVER"
controlled_mine 1
PENDING=$(coppice 2 pending --server "$SERVER")
printf '%s\n' "$PENDING"
[[ "$PENDING" == *$'bob\tReadyToReveal'* ]] || { echo "bob reveal is not ready"; exit 1; }

say "revealing bob registration from wallet 2"
coppice 2 register bob "$WALLET_2_UA" --identity "$(identity 2)" --server "$SERVER"
controlled_mine 1
assert_resolve 3 bob "bob: Active $WALLET_2_UA"

say "releasing bob from wallet 2"
coppice 2 release bob --identity "$(identity 2)" --server "$SERVER"
controlled_mine 1
assert_resolve 1 bob "bob: Released"
assert_resolve 3 bob "bob: Released"

say "multi-wallet lifecycle passed: alice registered/updated; bob registered/released"
echo "log: $LOG"
