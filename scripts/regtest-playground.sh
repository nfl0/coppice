#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
Z3_DIR=${Z3_DIR:-"$ROOT/../z3"}
DEVTOOL_DIR=${ZCASH_DEVTOOL_REPO:-"$ROOT/../zcash-devtool"}
DEVTOOL=${ZCASH_DEVTOOL:-"$DEVTOOL_DIR/target/release/zcash-devtool"}
STATE=${COPPICE_REGTEST_DIR:-"$ROOT/.coppice-regtest"}
SERVER=${COPPICE_REGTEST_SERVER:-127.0.0.1:28137}
ACTIVATION=10
WALLET_COUNT=3
RPC=http://127.0.0.1:29232
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
  [[ -f "$DEVTOOL_DIR/Cargo.toml" ]] || die "zcash-devtool not found at $DEVTOOL_DIR"
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
    info=$("$DEVTOOL" wallet --wallet-dir "$(wallet_dir 1)" get-info --server "$SERVER" 2>/dev/null || true)
    [[ "$info" == *"\"chain_tip_height\":$target"* ]] && return
    sleep 1
  done
  die "Zaino did not index height $target"
}

build_devtool() {
  if [[ ! -x "$DEVTOOL" ]] \
    || ! "$DEVTOOL" wallet init --help 2>&1 | grep -q activation-heights \
    || find "$DEVTOOL_DIR/src" "$DEVTOOL_DIR/Cargo.toml" -newer "$DEVTOOL" -print -quit | grep -q .; then
    cargo build --release --features regtest_support --manifest-path "$DEVTOOL_DIR/Cargo.toml"
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
  PATH="$shim:$PATH" "$Z3_DIR/scripts/regtest-init.sh"
  rm -rf "$shim"
  touch "$STATE/z3-initialized"
}

ensure_chain_height() {
  local height needed
  height=$(rpc getblockcount | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  needed=$((ACTIVATION - height))
  (( needed <= 0 )) || rpc generate "[$needed]" >/dev/null
}

wallet_dir() { printf '%s/wallet-%s' "$STATE" "$1"; }
identity() { printf '%s/age-identity.txt' "$(wallet_dir "$1")"; }

wallet() {
  local index=$1; shift
  "$DEVTOOL" wallet --wallet-dir "$(wallet_dir "$index")" "$@"
}

coppice() {
  local index=$1; shift
  "$DEVTOOL" coppice --wallet-dir "$(wallet_dir "$index")" "$@"
}

initialize_wallets() {
  local i dir
  build_devtool
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
  [[ -f "$(wallet_dir 1)/keys.toml" ]] || return
  miner=$(wallet 1 list-addresses --receiver transparent | sed -n 's/^Receiver(transparent): //p' | head -1)
  [[ -n "$miner" ]] || die "wallet 1 has no transparent mining receiver"
  export ZEBRA_MINING__MINER_ADDRESS=$miner
}

fund_wallet_one() {
  [[ -f "$STATE/wallet-1-funded" ]] && return
  configure_wallet_miner
  # Recreate Zebra once so subsequent coinbase rewards belong to wallet 1,
  # then mature the first reward immediately on the tiny local chain.
  compose --profile indexer up -d zebra cookie-permissions zallet zaino
  wait_for_rpc
  rpc generate '[101]' >/dev/null
  wait_for_zaino
  touch "$STATE/wallet-1-funded"
}

sync_wallets() {
  local i
  wait_for_zaino
  for i in $(seq 1 "$WALLET_COUNT"); do
    wallet "$i" sync --server "$SERVER"
    coppice "$i" sync --server "$SERVER"
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
  ensure_chain_height
  initialize_wallets
  fund_wallet_one
  printf 'Coppice regtest ready (activation %s, Zaino %s).\n' "$ACTIVATION" "$SERVER"
}

stop() {
  require_layout
  compose --profile '*' down
  rm -f "$Z3_DIR/.coppice-podman.yml"
}

reset() {
  require_layout
  compose --profile '*' down -v --remove-orphans || true
  rm -f "$Z3_DIR/.coppice-podman.yml"
  [[ "$STATE" == "$ROOT/.coppice-regtest" ]] || die "refusing to remove non-default state path"
  rm -rf "$STATE"
  printf 'Coppice regtest state removed.\n'
}

mine() {
  local count=${1:-1}
  [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "mine count must be positive"
  wait_for_rpc
  rpc generate "[$count]" >/dev/null
  wait_for_zaino
  sync_wallets
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
  local selected=1 choice name ua
  while true; do
    printf '\nCoppice Regtest V0 (wallet %s)\n[r] Register [u] Update [x] Release [l] Resolve [m] Mine [s] Switch wallet [q] Quit\n> ' "$selected"
    read -r choice
    case "$choice" in
      r|u) read -r -p 'Name: ' name; read -r -p 'Unified Address: ' ua
        [[ "$choice" == r ]] && verb=register || verb=update
        coppice "$selected" "$verb" "$name" "$ua" --identity "$(identity "$selected")" --server "$SERVER" ;;
      x) read -r -p 'Name: ' name; coppice "$selected" release "$name" --identity "$(identity "$selected")" --server "$SERVER" ;;
      l) read -r -p 'Name: ' name; coppice "$selected" resolve "$name" || true ;;
      m) mine 1 ;;
      s) read -r -p 'Wallet (1-3): ' selected; [[ "$selected" =~ ^[123]$ ]] || selected=1 ;;
      q) return ;;
    esac
  done
}

case "${1:-play}" in
  _compose) shift; compose "$@" ;;
  start) start ;;
  stop) stop ;;
  reset) reset ;;
  mine) shift; mine "${1:-1}" ;;
  status) status ;;
  sync) start; sync_wallets ;;
  play) play ;;
  *) die "usage: $0 {start|stop|reset|mine [COUNT]|status|sync|play}" ;;
esac
