<p align="center">
  <img src="coppice.png" alt="Coppice — Zcash Naming Protocol" width="1086">
</p>

# Coppice 🪵

**Coppice**. A native privacy-preserving naming protocol for Zcash. Zcash.

Coppice is a cryptographically self-verifying Zcash namespace, built from private bond proofs, public nullifier liveness, and deterministic state derivation.

Wallets independently derive name state from ordered Ironwood effects and txid-tagged bulletin
carriers in Zcash history.

## Core design

- **Private bonds.** A registration includes a Halo2 `BondProof` that privately proves control of
  a sufficiently valuable Ironwood note. The note, value, commitment, position, and nullifier stay
  hidden.
- **Public liveness.** When the bonded note is spent, Zcash publishes its nullifier. Coppice derives
  the matching `bond_tag` and automatically marks the name inactive.
- **Deterministic replay.** Wallets process Ironwood effects from the activation height, fetch full
  transactions only for txid-tagged candidates, decrypt public bulletin memos, and derive the same
  authenticated `NameTree` and `SpentTagTree`.
- **Local verification.** Resolution comes from locally derived state; a resolver never accepts a
  bond tag or registry answer as an external authority.

## Current protocol actions

`COMMIT` / `REVEAL` registers a name with a private bond; `UPDATE` changes its Unified Address;
`RELEASE` makes it available again; and `TRANSFER_WITH_NEW_BOND` changes ownership while replacing
the bond. A transfer to the same owner is the canonical rebond operation.

## Status

Experimental reference implementation. The protocol has been exercised with real Zcash
v6/Ironwood transactions and testnet/regtest tooling, but it is not production software and has
not received an independent security audit.

## Documentation

| Document | Purpose |
| --- | --- |
| [Protocol and developer guide](PROTOCOL.md) | Architecture, trust model, validation, development, playgrounds, and regtest workflow. |
| [Reference semantics](REFERENCE.md) | Exact encodings, hash domains, replay rules, tree semantics, and state commitments. |
| [Dependency patches](DEPENDENCY_PATCHES.md) | Required non-consensus Orchard and wallet-layer API changes. |
| [Test vectors](test-vectors/reference-v0.json) | Stable exact-byte compatibility vectors. |

## Quick start

```bash
git clone https://github.com/nfl0/coppice.git
git clone https://github.com/nfl0/coppice-cli.git
cd coppice
cargo test --workspace
./coppice-playground.sh
```

The playground uses `coppice-cli` for testnet wallet operation and the `coppice` crate for all
protocol logic. It creates or reuses a dedicated testnet wallet, replays from the fixed activation
height, and supports registration, resolution, updates, releases, local inventory, and activity
watching.

For a local three-wallet exercise against Z3, see the [regtest guide](PROTOCOL.md#local-z3-regtest-playground).

## Scope

Current work focuses on a small, privacy-preserving name lifecycle: registration, update, release,
bond replacement, and automatic bond-spend invalidation. Recursive history proofs, PIR, FROST,
subnames, governance, auctions, and production wallet UX are intentionally deferred.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
