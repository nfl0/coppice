#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
Z3_DIR=${Z3_DIR:-"$ROOT/../z3"}
CLI_DIR=${COPPICE_CLI_REPO:-"$ROOT/../coppice-cli"}
CLI=${COPPICE_CLI:-"$CLI_DIR/target/release/coppice-cli"}
STATE=${COPPICE_REGTEST_DIR:-"$ROOT/.coppice-regtest"}
SERVER=${COPPICE_REGTEST_SERVER:-127.0.0.1:28137}
ACTIVATION=10
WALLET_COUNT=3
RPC=http://127.0.0.1:29232
# This disposable address is used only to mine the first two activation blocks
# before a local wallet exists. It has no associated wallet key.
BOOTSTRAP_MINER=${COPPICE_REGTEST_BOOTSTRAP_MINER_ADDRESS:-tmEdBeYYmDnzJ2R2tFdzzgpKNPzQg48j1TV}
# Z3 currently pins Zaino 0.6, whose gRPC enum predates Ironwood. Keep Z3's
# service configuration but select the first public Zaino release with the
# Ironwood compact-sync protocol used by this workspace.
export Z3_ZEBRA_IMAGE=${Z3_ZEBRA_IMAGE:-docker.io/zfnd/zebra:6.2.3}
export Z3_ZAINO_IMAGE=${Z3_ZAINO_IMAGE:-docker.io/zingodevops/zainod:0.8.0-no-tls}
export Z3_ZALLET_IMAGE=${Z3_ZALLET_IMAGE:-docker.io/zodlinc/zallet:v0.1.0-beta.1@sha256:1849b4469875dc0165942c06d15fa6a7da76b2d43bade578cc8e5903a639869d}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 is required"; }

require_layout() {
  need podman
  need podman-compose
  need python3
  need curl
  [[ -f "$Z3_DIR/.env.regtest" ]] || die "clone external Z3 at $Z3_DIR (https://github.com/ZcashFoundation/z3)"
  [[ -f "$CLI_DIR/Cargo.toml" ]] || die "coppice-cli not found at $CLI_DIR"
}

compose() {
  local generated="$Z3_DIR/.coppice-podman.yml" status=0
  "$ROOT/scripts/z3-podman-compose.py" \
    "$Z3_DIR/docker-compose.yml" "$Z3_DIR/docker-compose.regtest.yml" "$generated"
  (
    cd "$Z3_DIR"
    podman-compose --env-file "$Z3_DIR/.env.regtest" -f "$generated" "$@"
  ) || status=$?
  return "$status"
}

# Adapter used only while running Z3's own idempotent regtest initializer.
make_docker_shim() {
  local shim_dir=$1
  cat >"$shim_dir/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == compose ]]; then
  shift
  if [[ "\${1:-}" == version ]]; then echo 2.24.4; exit 0; fi
  args=()
  while (( \$# )); do
    if [[ "\$1" == --env-file ]]; then shift 2; else args+=("\$1"); shift; fi
  done
  exec "$ROOT/scripts/regtest-playground.sh" _compose "\${args[@]}"
fi
args=("\$@")
for i in "\${!args[@]}"; do
  [[ "\${args[\$i]}" == busybox ]] && args[\$i]=docker.io/library/busybox
done
exec podman "\${args[@]}"
EOF
  chmod +x "$shim_dir/docker"
}

rpc() {
  local method=$1 params=${2:-'[]'}
  curl -fsS -u zebra:zebra -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" "$RPC"
}

wait_for_rpc() {
  local i
  for i in {1..90}; do rpc getblockchaininfo >/dev/null 2>&1 && return; sleep 2; done
  die "Zebra RPC did not become ready"
}

wait_for_zaino() {
  local target i info
  target=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  for i in {1..90}; do
    info=$("$CLI" wallet --wallet-dir "$(wallet_dir 1)" get-info --server "$SERVER" 2>/dev/null || true)
    [[ "$info" == *"\"chain_tip_height\":$target"* ]] && return
    sleep 1
  done
  die "Zaino did not index height $target"
}

build_cli() {
  if [[ ! -x "$CLI" ]] \
    || ! "$CLI" wallet init --help 2>&1 | grep -q activation-heights \
    || find "$CLI_DIR/src" "$CLI_DIR/Cargo.toml" -newer "$CLI" -print -quit | grep -q .; then
    cargo build --release --features regtest_support --manifest-path "$CLI_DIR/Cargo.toml"
  fi
}

write_activation_heights() {
  mkdir -p "$STATE"
  cat >"$STATE/activation-heights.toml" <<'EOF'
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 2
nu6 = 2
nu6_1 = 2
nu6_2 = 2
nu6_3 = 2
EOF
}

initialize_z3() {
  [[ -f "$STATE/z3-initialized" ]] && return
  local shim
  shim=$(mktemp -d)
  make_docker_shim "$shim"
  # Z3's full initializer mines activation blocks before this playground has
  # created a wallet mining receiver. Prepare only its local config; this
  # harness owns service startup and deterministic wallet funding below.
  PATH="$shim:$PATH" "$Z3_DIR/scripts/regtest-init.sh" --prepare-only
  rm -rf "$shim"
  touch "$STATE/z3-initialized"
}

wallet_dir() { printf '%s/wallet-%s' "$STATE" "$1"; }
identity() { printf '%s/age-identity.txt' "$(wallet_dir "$1")"; }

wallet() {
  local index=$1; shift
  "$CLI" wallet --wallet-dir "$(wallet_dir "$index")" "$@"
}

coppice() {
  local index=$1; shift
  "$CLI" coppice --wallet-dir "$(wallet_dir "$index")" "$@"
}

initialize_wallets() {
  local i dir
  build_cli
  write_activation_heights
  for i in $(seq 1 "$WALLET_COUNT"); do
    dir=$(wallet_dir "$i")
    if [[ ! -f "$dir/keys.toml" ]]; then
      mkdir -p "$dir"
      printf '\n' | wallet "$i" init --name "coppice-regtest-$i" \
        --identity "$(identity "$i")" --birthday 2 --network regtest \
        --activation-heights "$STATE/activation-heights.toml" --server "$SERVER"
      wallet "$i" generate-address >"$dir/address.txt"
    fi
  done
}

configure_wallet_miner() {
  local miner
  if [[ -n "${COPPICE_REGTEST_MINER_ADDRESS:-}" ]]; then
    export ZEBRA_MINING__MINER_ADDRESS=$COPPICE_REGTEST_MINER_ADDRESS
    return
  fi
  if [[ ! -f "$(wallet_dir 1)/keys.toml" ]]; then
    export ZEBRA_MINING__MINER_ADDRESS=$BOOTSTRAP_MINER
    return
  fi
  miner=$(wallet 1 list-addresses --receiver transparent | sed -n 's/^Receiver(transparent): //p' | head -1)
  [[ -n "$miner" ]] || die "wallet 1 has no transparent mining receiver"
  export ZEBRA_MINING__MINER_ADDRESS=$miner
}

sync_wallets() {
  local i attempt height
  wait_for_zaino
  height=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  for i in $(seq 1 "$WALLET_COUNT"); do
    [[ -f "$(wallet_dir "$i")/keys.toml" ]] || continue
    for attempt in {1..10}; do
      if wallet "$i" sync --server "$SERVER" \
        && { (( height < ACTIVATION )) || coppice "$i" sync --server "$SERVER"; }; then
        break
      fi
      (( attempt < 10 )) || die "wallet $i did not sync after mining"
      sleep 1
    done
  done
}

start() {
  require_layout
  mkdir -p "$STATE"
  write_activation_heights
  initialize_z3
  configure_wallet_miner
  compose --profile indexer up -d zebra cookie-permissions zallet zaino
  wait_for_rpc
  local height
  height=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  if (( height < 2 )); then
    printf 'Regtest is at height %s. Mine 2 blocks manually, then run start again to create wallets.\n' "$height"
    return
  fi
  initialize_wallets
  # Wallets now exist, so restart Zebra with wallet 1 as the default mining
  # address. No blocks are mined here; callers advance the chain explicitly.
  configure_wallet_miner
  compose --profile indexer up -d --force-recreate zebra
  wait_for_rpc
  wait_for_zaino
  printf 'Coppice regtest ready (activation %s, Zaino %s). Mine blocks manually.\n' "$ACTIVATION" "$SERVER"
}

stop() {
  require_layout
  compose --profile indexer down >/dev/null 2>&1 || true
  rm -f "$Z3_DIR/.coppice-podman.yml"
}

reset() {
  require_layout
  compose --profile indexer down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$Z3_DIR/.coppice-podman.yml"
  [[ "$STATE" == "$ROOT/.coppice-regtest" ]] || die "refusing to remove non-default state path"
  rm -rf "$STATE"
  printf 'Coppice regtest state removed.\n'
}

mine() {
  local count=${1:-1} before expected height i
  [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "mine count must be positive"
  wait_for_rpc
  before=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  expected=$((before + count))
  rpc generate "[$count]" >/dev/null
  for i in {1..30}; do
    height=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
    (( height >= expected )) && break
    sleep 1
  done
  (( height >= expected )) || die "Zebra did not reach mined height $expected"
  if [[ -f "$(wallet_dir 1)/keys.toml" ]]; then
    wait_for_zaino
    sync_wallets
  fi
  printf 'Mined %s block(s).\n' "$count"
}

status() {
  require_layout
  compose ps || true
  if rpc getblockchaininfo >/dev/null 2>&1; then
    printf '\nchain height: %s\nactivation height: %s\nZaino: %s\n' \
      "$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')" "$ACTIVATION" "$SERVER"
  fi
  local i
  for i in $(seq 1 "$WALLET_COUNT"); do
    [[ -f "$(wallet_dir "$i")/keys.toml" ]] || continue
    printf '\nwallet %s\n' "$i"
    wallet "$i" balance --min-confirmations 1 --json || true
    coppice "$i" status || true
  done
}

play() {
  start
  [[ -f "$(wallet_dir 1)/keys.toml" ]] || {
    die "mine two bootstrap blocks with '$0 mine 2', then run play again"
  }
  local selected=1 choice name ua
  while true; do
    printf '\nCoppice Regtest V1 (wallet %s)\n[r] Register [u] Update [x] Release [l] Resolve [n] Names [p] Pending [k] Owner key [m] Mine [s] Switch wallet [q] Quit\n> ' "$selected"
    read -r choice
    case "$choice" in
      r|u) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua
        [[ "$choice" == r ]] && verb=register || verb=update
        coppice "$selected" "$verb" "$name" "$ua" --identity "$(identity "$selected")" --server "$SERVER" ;;
      x) read -r -p 'Name: ' name; coppice "$selected" release "$name" --identity "$(identity "$selected")" --server "$SERVER" ;;
      l) read -r -p 'Name: ' name; coppice "$selected" resolve "$name" --server "$SERVER" || true ;;
      n) coppice "$selected" names --server "$SERVER" ;;
      p) coppice "$selected" pending --server "$SERVER" ;;
      k) coppice "$selected" owner-key --identity "$(identity "$selected")" ;;
      m) mine 1 ;;
      s) read -r -p 'Wallet (1-3): ' selected; [[ "$selected" =~ ^[123]$ ]] || selected=1 ;;
      q) return ;;
    esac
  done
}

automatic_test() (
  # Always stop the disposable stack, including when the lifecycle test fails
  # or the caller interrupts it.
  trap '"$ROOT/scripts/regtest-playground.sh" stop >/dev/null 2>&1 || true' EXIT
  "$ROOT/scripts/regtest-multiwallet-test.sh" --reset
)

case "${1:-test}" in
  _compose) shift; compose "$@" ;;
  test) automatic_test ;;
  start) start ;;
  stop) stop ;;
  reset) reset ;;
  mine) shift; mine "${1:-1}" ;;
  status) status ;;
  sync) start; sync_wallets ;;
  play) play ;;
  *) die "usage: $0 {test|start|stop|reset|mine [COUNT]|status|sync|play}" ;;
esac
