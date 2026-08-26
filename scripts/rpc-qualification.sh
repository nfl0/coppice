#!/usr/bin/env bash
# Native Zcash JSON-RPC qualification against disposable pinned Zakura Regtest.
#
# This is deliberately separate from the historical Names Phases 1-7 harness.
# Zaino is started only for the final CompactBlock differential; the native
# checkpoint/replay/restart/reorg path talks to Zakura directly.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_DIR="$(cd "$ROOT_DIR/.." && pwd)"
ZAKURA_BIN="${ZAKURA_BIN:-$STACK_DIR/bin/zakurad}"
ZAINO_BIN="${ZAINO_BIN:-$STACK_DIR/bin/zainod}"
DEVTOOL_BIN="${DEVTOOL_BIN:-$STACK_DIR/bin/zcash-devtool}"
WORK_DIR="${COPPICE_RPC_QUALIFICATION_DIR:-$(mktemp -d /tmp/coppice-rpc-qualification.XXXXXX)}"
RPC_ADDR="127.0.0.1:19232"
P2P_ADDR="127.0.0.1:19233"
GRPC_ADDR="127.0.0.1:19337"
RPC_URL="http://$RPC_ADDR"
GRPC_URL="http://$GRPC_ADDR"
ZAKURA_PID=""
ZAINO_PID=""

cleanup() {
    local status=$?
    set +e
    [[ -z "$ZAINO_PID" ]] || kill "$ZAINO_PID" 2>/dev/null || true
    [[ -z "$ZAKURA_PID" ]] || kill "$ZAKURA_PID" 2>/dev/null || true
    [[ -z "$ZAINO_PID" ]] || wait "$ZAINO_PID" 2>/dev/null || true
    [[ -z "$ZAKURA_PID" ]] || wait "$ZAKURA_PID" 2>/dev/null || true
    if (( status == 0 )); then
        printf '[PASS] native RPC qualification evidence: %s\n' "$WORK_DIR"
    else
        printf '[FAIL] native RPC qualification evidence: %s\n' "$WORK_DIR" >&2
    fi
}
trap cleanup EXIT

for command in cargo curl jq timeout; do
    command -v "$command" >/dev/null
done
for executable in "$ZAKURA_BIN" "$ZAINO_BIN" "$DEVTOOL_BIN"; do
    [[ -x "$executable" ]] || { printf 'missing executable: %s\n' "$executable" >&2; exit 2; }
done

mkdir -p "$WORK_DIR/state" "$WORK_DIR/zaino"
MINER_UA="$($DEVTOOL_BIN wallet derive-address \
    --mnemonic 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art' \
    --network regtest | sed -n 's/^Unified Address: //p')"
[[ -n "$MINER_UA" ]]

cat >"$WORK_DIR/zakura.toml" <<EOF
[network]
network = "Regtest"
listen_addr = "$P2P_ADDR"
p2p_stack = "legacy"
cache_dir = false
identity_dir = "$WORK_DIR/state/identity"
initial_testnet_peers = []
max_connections_per_ip = 10
peerset_initial_target_size = 1

[network.testnet_parameters]
lockbox_disbursements = [{ address = "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2", amount = 0 }]
[network.testnet_parameters.activation_heights]
Overwinter = 1
Sapling = 1
Blossom = 1
Heartwood = 1
Canopy = 1
"NU5" = 2
"NU6" = 2
"NU6.1" = 2
"NU6.2" = 2
"NU6.3" = 2
[state]
cache_dir = "$WORK_DIR/state/chain"
ephemeral = false
delete_old_database = true
storage_mode = "archive"
[rpc]
listen_addr = "$RPC_ADDR"
cookie_dir = "$WORK_DIR/state/rpc"
enable_cookie_auth = false
[mining]
internal_miner = false
miner_address = "$MINER_UA"
[tracing]
filter = "info"
use_color = false
EOF

cat >"$WORK_DIR/zaino.toml" <<EOF
backend = "rpc"
zebra_db_path = "$WORK_DIR/zaino/zebra-db"
ephemeral_finalised_state = false
network = "Regtest"
[grpc_settings]
listen_address = "$GRPC_ADDR"
[validator_settings]
validator_grpc_listen_address = "127.0.0.1:19230"
validator_jsonrpc_listen_address = "$RPC_ADDR"
validator_user = "xxxxxx"
validator_password = "xxxxxx"
[storage.database]
path = "$WORK_DIR/zaino/database"
EOF

"$ZAKURA_BIN" --config "$WORK_DIR/zakura.toml" start >"$WORK_DIR/zakura.log" 2>&1 &
ZAKURA_PID=$!
for _ in {1..60}; do
    response="$(curl --silent --show-error --connect-timeout 2 --max-time 5 \
        -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' "$RPC_URL" 2>/dev/null || true)"
    if jq -e '.error == null and .result.chain == "test"' >/dev/null <<<"$response"; then break; fi
    sleep 1
done
jq -e '.error == null and .result.chain == "test"' >/dev/null <<<"$response"

curl --silent --show-error --connect-timeout 2 --max-time 30 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":2,"method":"generate","params":[12]}' "$RPC_URL" \
    | tee "$WORK_DIR/generate.json" | jq -e '.error == null and (.result | length == 12)' >/dev/null

(cd "$ROOT_DIR" && cargo run -p coppice-zcash-rpc --bin rpc-probe -- "$RPC_URL" 10 \
    | tee "$WORK_DIR/rpc-probe.txt")
(cd "$ROOT_DIR" && COPPICE_RPC_LIVE_ENDPOINT="$RPC_URL" \
    cargo test -p coppice-zcash-rpc --test live_regtest \
        zakura_rpc_checkpoint_reconciliation_restart_and_reorg -- --ignored --nocapture \
    | tee "$WORK_DIR/native-reorg.txt")

"$ZAINO_BIN" start --config "$WORK_DIR/zaino.toml" >"$WORK_DIR/zaino.log" 2>&1 &
ZAINO_PID=$!
for _ in {1..90}; do
    if (cd "$ROOT_DIR" && COPPICE_RPC_LIVE_ENDPOINT="$RPC_URL" \
        COPPICE_ZAINO_GRPC_ENDPOINT="$GRPC_URL" \
        cargo test -q -p coppice-zcash-rpc --test live_regtest \
            zakura_rpc_compact_facts_match_zaino -- --ignored) >"$WORK_DIR/differential.txt" 2>&1; then
        break
    fi
    sleep 1
done
rg -q 'test result: ok' "$WORK_DIR/differential.txt"

{
    git -C "$ROOT_DIR" rev-parse HEAD
    git -C "$STACK_DIR/zakura" rev-parse HEAD
    git -C "$STACK_DIR/zaino" rev-parse HEAD
    cat "$WORK_DIR/rpc-probe.txt"
    cat "$WORK_DIR/native-reorg.txt"
    cat "$WORK_DIR/differential.txt"
} >"$WORK_DIR/evidence.txt"
