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

## Pre-authorization memo dependency experiment

`tests/preauth_grind.rs` builds a genuine V6 Ironwood PCZT, replaces only a memo plaintext,
uses `IoFinalizer` to encrypt it, computes `Pczt::into_effects()` / `TxIdDigester`, then proves
and authorizes only the selected candidate. It parses and decrypts the final transaction.

| Field | Changes with memo | Why |
|---|---|---|
| output note / rseed / rho | No | note construction does not contain memo |
| cmx | No | commitment is over note fields, not memo |
| cv_net | No | derived from value and `rcv` |
| nullifier / rk / anchor / flags | No | spend/effecting data fixed before loop |
| ephemeral key | No | derives from fixed note encryption key material |
| `encCiphertext[0..52]` | No | fixed note-plaintext prefix |
| memo ciphertext region and tag | Yes | AEAD encrypts changed memo plaintext |
| `outCiphertext` | No | output recovery encryption excludes memo |
| Action circuit statement | No | asserted equal for anchor, cv, nf, rk, cmx, flags |
| txid / shielded sighash | Yes | V6 txid commits encrypted ciphertext; sighash commits txid digests |
| Halo2 proof | No reproof needed during loop | proof is created only for winner |
| spendAuthSig / bindingSig | No signatures in loop | made once after winner, over winner sighash |

This distinguishes cryptography from APIs: PCZT's public `Redactor` method
`replace_enc_ciphertext_with_memo_plaintext`, `IoFinalizer`, and `into_effects` express this
lifecycle without a consensus or wallet-layer patch. The final txid equals the pre-authorization
winning txid because proof and signatures are authorizing data, not effecting data.

## Non-consensus BondCircuit refactor

The vendored Orchard crate factors the existing Action synthesis into a reusable path that can
return constrained old-note nullifier, value, and validating-key cells while conditionally omitting
only the normal public effect constraints. The existing consensus `Circuit` always selects the
original path and retains the same anchor, `cv`, nullifier, `rk`, `cmx`, and flag constraints.
`circuit::bond::BondCircuit` is application-only. It adds ask possession, a 64-bit minimum-value
check, private Poseidon bond-tag derivation, and owner/context binding. The nullifier and commitment
are not instance values. No transaction parser, verifier, bundle, or consensus rule uses this new
circuit.
