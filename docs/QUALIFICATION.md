# Coppice v1 qualification

The deterministic qualification suite covers canonical encoding, hostile-input
parsing, BondProof generation and verification, bounded snapshot/reorg replay,
wallet lock reconstruction, carrier construction boundaries, and canonical
chain reconciliation. `crates/coppice/tests/fuzz_properties.rs` additionally
feeds 10,000 deterministic arbitrary inputs through the operation and indexed
carrier parsers; rejection is permitted, panics are not.

## Live Z3 boundary

The 2026-08-22 local qualification used Zebra 6.2.3 with the Z3 regtest upgrade
schedule (NU5 through NU6.3 at height 2) and Zaino 0.6.0. Zebra activated
NU6.3 and mined the test chain. A fresh `zcash-devtool` wallet initialized
against the lightwalletd-compatible endpoint, but sync stopped before Coppice
replay because Zaino returned `Invalid shielded protocol value` for the
Ironwood subtree-root request. No protocol fallback is permitted: a host
indexer must expose the pinned librustzcash Ironwood compact-block and subtree
APIs before the real carrier, bond lifecycle, reorg, and same-seed live cases
can be qualified end to end.

This is an integration-capability failure, not permission to omit Ironwood
effects, use Orchard state, or weaken canonical reducer validation.
