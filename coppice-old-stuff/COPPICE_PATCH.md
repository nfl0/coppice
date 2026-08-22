# Coppice Orchard patch

The root [`DEPENDENCY_PATCHES.md`](../../DEPENDENCY_PATCHES.md) documents this patch alongside the
separate librustzcash wallet-layer hook required by carrier construction.

This directory is Orchard 0.15.3 with the smallest API/circuit refactor required by the Coppice
BondCircuit POC. Upstream Orchard 0.15.3 does not expose a reusable circuit proving the private
old-note relations Coppice needs.

The Coppice-specific changes are limited to:

- `src/circuit.rs`: factor Action synthesis so the application-only `circuit::bond::BondCircuit`
  can reuse the existing note commitment, Merkle membership, key, value, and nullifier constraints;
  expose the constrained old-note nullifier, value, and validating-key cells to that circuit.
- `src/keys.rs`: expose `SpendAuthorizingKey::to_scalar` for the constrained ownership relation.
- `src/note.rs`: expose `Rho::from_nf_old` for constructing the circuit's dummy output note.

The ordinary Orchard consensus `Circuit` continues to call the same synthesis path with all normal
public effect constraints enabled. The BondCircuit is not referenced by transaction validation.
This patch changes no transaction encoding, consensus rule, verification key, or proof semantics.

The workspace root selects this fork through `[patch.crates-io]`.
