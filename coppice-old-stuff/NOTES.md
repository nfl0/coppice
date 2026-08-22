# Current Ironwood API map

The reference POC was migrated from `librustzcash` revision
`a09e37e6a6f3657c077a6399011327138e478082`. The standalone `Cargo.lock` pins the resolved crate
versions; the required Orchard 0.15.3 circuit API refactor is vendored and documented separately.

| Requirement | Current upstream API |
|---|---|
| V6 transaction representation | `zcash_primitives::transaction::TransactionData::from_parts_v6` |
| V6 parsing / serialization / txid | `Transaction::read`, `Transaction::write`, `Transaction::txid`; `transaction::txid::TxIdDigester` |
| ZIP-244 / ZIP-229 digests | `zcash_primitives::transaction::txid::{TxIdDigester, BlockTxCommitmentDigester}` |
| Ironwood bundle / action | `TransactionData::ironwood_bundle`; `orchard::bundle::Bundle`, `orchard::Action` |
| Ironwood action wire parsing | `transaction::components::orchard::read_v6_bundle`, `read_action_without_auth`, `read_nullifier`, `read_cmx` |
| Ironwood note commitments / nullifiers | `orchard::note::ExtractedNoteCommitment`, `orchard::note::Nullifier`; action accessors |
| memo encryption / decryption | `orchard::note_encryption::IronwoodDomain`, `zcash_note_encryption::try_note_decryption` |
| Orchard receiver / IVK | `orchard::keys::{SpendingKey, FullViewingKey, IncomingViewingKey}` and `FullViewingKey::address_at` |
| PCZT Ironwood | `pczt::roles::{creator,io_finalizer,prover,signer,tx_extractor}`; tested in `pczt/tests/end_to_end.rs` |
| compact Ironwood actions | `orchard::note_encryption::CompactAction`, `zcash_client_backend::scanning::compact` |
| transaction builder | `zcash_primitives::transaction::builder::{Builder, BuildConfig, BundlePadding}` |

## Rendez-vous discovery

Each deployment fixes a public rendez-vous Orchard receiver and incoming viewing key. Compact
Ironwood Actions contain the data needed for incoming-note trial decryption. A wallet
trial-decrypts those compact Actions with the public UIVK and fetches the full transaction only
when a rendez-vous output is detected. Carrier memos are set during ordinary transaction
construction; no txid tag or grinding lifecycle is required.

## Non-consensus BondCircuit refactor

The vendored Orchard crate factors the existing Action synthesis into a reusable path that can
return constrained old-note nullifier, value, and validating-key cells while conditionally omitting
only the normal public effect constraints. The existing consensus `Circuit` always selects the
original path and retains the same anchor, `cv`, nullifier, `rk`, `cmx`, and flag constraints.
`circuit::bond::BondCircuit` is application-only. It adds ask possession, a 64-bit minimum-value
check, private Poseidon bond-tag derivation, and owner/context binding. The nullifier and commitment
are not instance values. No transaction parser, verifier, bundle, or consensus rule uses this new
circuit.
