# Coppice v1 qualification

The deterministic qualification suite covers canonical encoding, hostile-input
parsing, BondProof generation and verification, bounded snapshot/reorg replay,
wallet lock reconstruction, carrier construction boundaries, and canonical
chain reconciliation. `crates/coppice/tests/fuzz_properties.rs` additionally
feeds 10,000 deterministic arbitrary inputs through the operation and indexed
carrier parsers; rejection is permitted, panics are not.

## Live Zakura → Zaino qualification

The current local qualification uses Zakura with the pinned Z3 regtest upgrade
schedule (NU5 through NU6.3 at height 2), the patched Zaino Ironwood compact
block/subtree APIs, and `zcash-devtool` built from the committed Coppice
runtime. Coppice is exercised through the general `CoreRuntime` and the
Names-v1 application composition; Zcash remains the host-selected canonical
ordering and fork-choice authority.

The live phases cover ordinary Ironwood transactions, the complete Names
COMMIT/REVEAL/UPDATE/RELEASE lifecycle, bond spends and protection, restart and
fresh-wallet recovery, shallow reorgs, and multi-account isolation. Phase 7
also mines an abandoned branch containing an application transition, advances
that branch beyond the configured 121-block rewind horizon, replaces it with
an equal-length canonical suffix, and verifies that the runtime rebuild and an
independently initialized same-seed wallet produce the same tip, Names state,
protection locks, and serialized runtime snapshot.

These are local qualification results for the development/regtest stack. They
do not claim a public Zcash Testnet or Mainnet deployment, production release,
or independent security audit. The Ironwood APIs are required for every live
run; no fallback omits canonical Ironwood effects or weakens replay validation.
