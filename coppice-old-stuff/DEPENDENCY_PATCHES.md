# Coppice dependency patches

Coppice currently uses one narrowly scoped, non-consensus Orchard library change. It is an
application integration dependency, not a change to the Zcash protocol or transaction validity
rules.

## Summary

| Library | Coppice dependency | Location | Consensus behavior changed? |
| --- | --- | --- | --- |
| Orchard 0.15.3 | Reusable constrained primitives and the POC BondCircuit | `vendor/orchard` | No |

## Orchard 0.15.3

The published Orchard API does not expose the constrained old-note relations required by the
Coppice BondCircuit. Coppice therefore vendors Orchard 0.15.3 and changes three source files:

- `vendor/orchard/src/circuit.rs` factors Action synthesis into reusable logic, exposes the
  constrained old-note nullifier, value, and validating-key cells, and contains the
  application-only `circuit::bond::BondCircuit`.
- `vendor/orchard/src/keys.rs` makes `SpendAuthorizingKey::to_scalar` public so the BondCircuit can
  constrain possession of the note's spend authority.
- `vendor/orchard/src/note.rs` makes `Rho::from_nf_old` public so the circuit can construct the
  nullifier-linked dummy output note used by the reused Action constraints.

The ordinary Orchard consensus `Circuit` still invokes the same Action constraints with its normal
public effects enabled. The Coppice BondCircuit is not used by Zcash transaction validation. The
patch does not alter Orchard transaction encoding, verification keys, consensus rules, or the
validity of ordinary Orchard/Ironwood proofs.

Cargo selects this copy using the workspace's `[patch.crates-io]` entry. The shorter patch note next
to the vendored code is at `vendor/orchard/COPPICE_PATCH.md`.

Longer term, the preferable split is for Orchard to expose generic reusable Action/note/nullifier
gadgets while the Coppice-specific BondCircuit remains entirely in the `coppice` crate. Until such
an API exists, wallets that build the current Coppice crate use this pinned Orchard copy.

## librustzcash

Coppice no longer requires a librustzcash fork. Every carrier is an ordinary payment to the fixed
public rendez-vous receiver with its memo set during normal transaction construction. Replayers
trial-decrypt compact Ironwood actions with the public rendez-vous UIVK and fetch full transactions
only when that succeeds. The superseded txid-prefix grinder and its pre-I/O-finalization wallet hook
are not part of the protocol.

## Integration consequence

Wallet integrations currently need only the Orchard gadget patch for BondProof construction and
verification:

```text
modified Zcash consensus rules: no
modified transaction formats:   no
modified Orchard proof validity: no
wallet/library API patches:      yes, one
```

This pin should remain exact and documented until equivalent public Orchard APIs exist.
