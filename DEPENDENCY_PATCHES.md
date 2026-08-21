# Coppice dependency patches

Coppice currently uses two narrowly scoped, non-consensus library changes. They are application
integration dependencies, not changes to the Zcash protocol or transaction validity rules.

## Summary

| Library | Coppice dependency | Location | Consensus behavior changed? |
| --- | --- | --- | --- |
| Orchard 0.15.3 | Reusable constrained primitives and the POC BondCircuit | `vendor/orchard` | No |
| librustzcash | Pre-I/O-finalization PCZT extension point | [`nfl0/librustzcash@2c2fca32bc`](https://github.com/nfl0/librustzcash/commit/2c2fca32bc7a143f32817b7be374bb820331584e) | No |

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

## librustzcash PCZT lifecycle hook

The wallet-layer function `zcash_client_backend::data_api::wallet::create_pczt_from_proposal`
normally constructs a PCZT and immediately runs `IoFinalizer`. For Ironwood padding actions,
`IoFinalizer` creates spend authorization signatures and consumes their temporary dummy signing
keys. Coppice must select its memo-dependent txid before any authorization is generated; changing
the memo afterward changes the shielded sighash and invalidates those signatures.

The fork is based exactly on upstream librustzcash revision
[`6c07e5f329`](https://github.com/zcash/librustzcash/commit/6c07e5f3297febf469e5cc8d0b91321e0767cdd7).
Commit [`2c2fca32bc`](https://github.com/nfl0/librustzcash/commit/2c2fca32bc7a143f32817b7be374bb820331584e)
changes only `zcash_client_backend/src/data_api/wallet.rs`:

- adds `create_pczt_from_proposal_with_io_finalizer`, which accepts a wallet-layer callback after
  effecting-data construction and before I/O finalization;
- keeps `create_pczt_from_proposal` as the existing convenience API, delegating through the new
  function with the original `IoFinalizer::finalize_io` behavior.

`coppice-cli` uses the hook for this lifecycle:

```text
construct effecting data
-> grind encrypted Coppice memos and txid
-> finalize I/O once
-> prove once
-> sign once
-> extract and broadcast
```

This is an additive wallet API. It does not modify transaction serialization, sighash definitions,
proof systems, consensus validation, or the behavior of existing callers. Because Cargo treats Git
sources as distinct dependency sources, `coppice-cli` pins the related librustzcash workspace
crates to the same fork revision even though only `zcash_client_backend` contains a code change.

The standalone `coppice` protocol crate does not itself patch librustzcash with this commit; the
patch is needed by wallet transaction construction in `coppice-cli` and by another wallet that
wants to create ground Coppice carriers through the same high-level proposal API.

## Integration consequence

The current Vizor/POC integration must pin both dependencies. This is library composability and
maintenance friction, but it is not a consensus fork:

```text
modified Zcash consensus rules: no
modified transaction formats:   no
modified Orchard proof validity: no
wallet/library API patches:      yes, two
```

These pins should remain exact and documented until equivalent public upstream APIs exist.
