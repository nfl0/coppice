//! Panic-free adaptation of hostile protobuf CompactBlocks into canonical Coppice inputs.
//!
//! [`FullTransactionSource`] is untrusted transport. Bytes returned for a requested
//! txid become authoritative only after the core runtime parses them under the
//! canonical branch ID and verifies their txid and compact/full Ironwood effects.

use std::fmt::Debug;

use coppice_core::{
    carrier,
    identity::{ValidatedCoreRuntimeParameters, ZcashNetwork},
    replay::{CoreCanonicalBlockInput, CoreCanonicalTransactionInput},
};
use orchard::note_encryption::CompactAction;
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactTx};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType, Parameters},
    constants::MAX_BLOCK_BYTES,
};

/// The cumulative candidate-byte budget is the consensus maximum serialized
/// Zcash block size. It bounds bytes retained before Core parses any candidate.
pub const MAX_CANDIDATE_FULL_TX_BYTES: usize = MAX_BLOCK_BYTES;

pub use coppice_core::runtime::CanonicalRuntime;

/// Supplies raw serialized transactions only when compact public rendezvous
/// detection makes the full transaction mandatory.
pub trait FullTransactionSource {
    type Error: Debug;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error>;
}

#[derive(Debug)]
pub enum CompactBlockAdapterError<SourceError: Debug> {
    NetworkMismatch,
    InvalidBlockHeight,
    InvalidBlockHash,
    InvalidPrevBlockHash,
    NonSequentialHeight {
        expected: u32,
        actual: u32,
    },
    PredecessorMismatch,
    InvalidTxIndex {
        transaction: usize,
    },
    InvalidTxid {
        transaction: usize,
    },
    NonCanonicalTxOrder,
    InvalidIronwoodCompactAction {
        tx_index: u32,
        action_index: usize,
    },
    CandidateDetection {
        tx_index: u32,
        action_index: usize,
    },
    FullTransactionSource(SourceError),
    RequiredFullTransactionMissing {
        txid: [u8; 32],
        tx_index: u32,
    },
    CandidateFullTransactionTooLarge {
        txid: [u8; 32],
        tx_index: u32,
        len: usize,
        limit: usize,
    },
    CandidateFullTransactionBudgetExceeded {
        txid: [u8; 32],
        tx_index: u32,
        attempted: usize,
        limit: usize,
    },
}

#[derive(Debug)]
pub enum CompactBlockApplyError<SourceError: Debug, RuntimeError: Debug> {
    Prepare(CompactBlockAdapterError<SourceError>),
    Runtime(RuntimeError),
}

struct ValidatedCompactTx {
    input: CoreCanonicalTransactionInput,
    candidate: bool,
}

fn exact_32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn validate_transaction<SourceError: Debug, R: CanonicalRuntime>(
    transaction: usize,
    compact_tx: &CompactTx,
    runtime: &R,
) -> Result<ValidatedCompactTx, CompactBlockAdapterError<SourceError>> {
    let tx_index = u32::try_from(compact_tx.index)
        .map_err(|_| CompactBlockAdapterError::InvalidTxIndex { transaction })?;
    let txid =
        exact_32(&compact_tx.txid).ok_or(CompactBlockAdapterError::InvalidTxid { transaction })?;
    let mut ironwood_nullifiers = Vec::with_capacity(compact_tx.ironwood_actions.len());
    let mut ironwood_commitments = Vec::with_capacity(compact_tx.ironwood_actions.len());
    let mut candidate = false;

    for (action_index, encoded) in compact_tx.ironwood_actions.iter().enumerate() {
        let action = CompactAction::try_from(encoded).map_err(|_| {
            CompactBlockAdapterError::InvalidIronwoodCompactAction {
                tx_index,
                action_index,
            }
        })?;
        ironwood_nullifiers.push(action.nullifier().to_bytes());
        ironwood_commitments.push(action.cmx().to_bytes());
        let hit = carrier::compact_action_is_rendezvous(
            &action,
            &runtime.core_parameters().parameters().rendezvous_ivk,
        )
        .map_err(|_| CompactBlockAdapterError::CandidateDetection {
            tx_index,
            action_index,
        })?;
        candidate |= hit;
    }

    Ok(ValidatedCompactTx {
        input: CoreCanonicalTransactionInput {
            tx_index,
            txid,
            ironwood_nullifiers,
            ironwood_commitments,
            full_tx_required: candidate,
            candidate_full_tx: None,
        },
        candidate,
    })
}

/// Validates an entire compact block before making the first external fetch,
/// then fetches each candidate transaction exactly once in canonical order.
pub fn prepare_canonical_block<P, R, S>(
    params: &P,
    runtime: &R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
) -> Result<CoreCanonicalBlockInput, CompactBlockAdapterError<S::Error>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
{
    if !network_matches(params.network_type(), runtime.core_parameters()) {
        return Err(CompactBlockAdapterError::NetworkMismatch);
    }
    let height = u32::try_from(compact_block.height)
        .map_err(|_| CompactBlockAdapterError::InvalidBlockHeight)?;
    let block_hash =
        exact_32(&compact_block.hash).ok_or(CompactBlockAdapterError::InvalidBlockHash)?;
    let prev_block_hash =
        exact_32(&compact_block.prev_hash).ok_or(CompactBlockAdapterError::InvalidPrevBlockHash)?;
    let expected_height = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(CompactBlockAdapterError::InvalidBlockHeight)?;
    if height != expected_height {
        return Err(CompactBlockAdapterError::NonSequentialHeight {
            expected: expected_height,
            actual: height,
        });
    }
    if prev_block_hash != runtime.tip().block_hash {
        return Err(CompactBlockAdapterError::PredecessorMismatch);
    }

    // Phase A: validate and classify every represented transaction before any fetch.
    let mut validated = Vec::with_capacity(compact_block.vtx.len());
    for (transaction, compact_tx) in compact_block.vtx.iter().enumerate() {
        let tx = validate_transaction(transaction, compact_tx, runtime)?;
        if validated
            .last()
            .is_some_and(|prior: &ValidatedCompactTx| prior.input.tx_index >= tx.input.tx_index)
        {
            return Err(CompactBlockAdapterError::NonCanonicalTxOrder);
        }
        validated.push(tx);
    }

    // Phase B: fetch raw bytes only for compact rendezvous hits.
    let mut candidate_bytes = 0usize;
    for tx in &mut validated {
        if tx.candidate {
            let bytes = full_tx_source
                .full_transaction(tx.input.txid)
                .map_err(CompactBlockAdapterError::FullTransactionSource)?
                .ok_or(CompactBlockAdapterError::RequiredFullTransactionMissing {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                })?;
            if bytes.len() > MAX_CANDIDATE_FULL_TX_BYTES {
                return Err(CompactBlockAdapterError::CandidateFullTransactionTooLarge {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                    len: bytes.len(),
                    limit: MAX_CANDIDATE_FULL_TX_BYTES,
                });
            }
            let attempted = candidate_bytes.checked_add(bytes.len()).ok_or(
                CompactBlockAdapterError::CandidateFullTransactionBudgetExceeded {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                    attempted: usize::MAX,
                    limit: MAX_CANDIDATE_FULL_TX_BYTES,
                },
            )?;
            if attempted > MAX_CANDIDATE_FULL_TX_BYTES {
                return Err(
                    CompactBlockAdapterError::CandidateFullTransactionBudgetExceeded {
                        txid: tx.input.txid,
                        tx_index: tx.input.tx_index,
                        attempted,
                        limit: MAX_CANDIDATE_FULL_TX_BYTES,
                    },
                );
            }
            candidate_bytes = attempted;
            tx.input.candidate_full_tx = Some(bytes);
        }
    }

    Ok(CoreCanonicalBlockInput {
        height,
        block_hash,
        prev_block_hash,
        branch_id: BranchId::for_height(params, BlockHeight::from_u32(height)),
        transactions: validated.into_iter().map(|tx| tx.input).collect(),
    })
}

/// Prepares the complete block first and delegates the sole state mutation to
/// the atomic core runtime.
pub fn apply_compact_block<P, R, S>(
    params: &P,
    runtime: &mut R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
) -> Result<R::BlockOutput, CompactBlockApplyError<S::Error, R::ApplyError>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
{
    let input = prepare_canonical_block(params, runtime, compact_block, full_tx_source)
        .map_err(CompactBlockApplyError::Prepare)?;
    runtime
        .apply_canonical_block(&input)
        .map_err(CompactBlockApplyError::Runtime)
}

fn network_matches(network: NetworkType, parameters: &ValidatedCoreRuntimeParameters) -> bool {
    matches!(
        (network, parameters.parameters().zcash_network),
        (NetworkType::Main, ZcashNetwork::Main)
            | (NetworkType::Test, ZcashNetwork::Test)
            | (NetworkType::Regtest, ZcashNetwork::Regtest)
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use coppice::{
        carrier as names_carrier,
        config::{DeploymentParameters, REGTEST, Rendezvous},
        constants::REGTEST_ACTIVATION_HEIGHT,
        names_runtime::{
            CoreReplayActivationCheckpoint, CoreReplayError, IronwoodFrontier, NamesRuntime,
            NamesRuntimeError, NamesTransactionOutcome,
        },
    };
    use orchard::{
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::proto::compact_formats::{CompactOrchardAction, CompactTx};
    use zcash_note_encryption::Domain;
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId, NetworkType},
        local_consensus::LocalNetwork,
    };

    use super::*;

    fn params() -> LocalNetwork {
        let active = Some(BlockHeight::from_u32(1));
        LocalNetwork {
            overwinter: active,
            sapling: active,
            blossom: active,
            heartwood: active,
            canopy: active,
            nu5: active,
            nu6: active,
            nu6_1: active,
            nu6_2: active,
            nu6_3: active,
        }
    }

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST.network_id.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_ACTIVATION_HEIGHT,
            minimum_bond_value: REGTEST.minimum_bond_value,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous {
                orchard_ivk: REGTEST.rendezvous.orchard_ivk,
                orchard_receiver: REGTEST.rendezvous.orchard_receiver,
            },
        }
    }

    fn runtime() -> NamesRuntime {
        let deployment = deployment();
        NamesRuntime::new(
            deployment.clone(),
            CoreReplayActivationCheckpoint {
                height: deployment.activation_height - 1,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn real_rendezvous_action() -> CompactOrchardAction {
        let recipient =
            orchard::Address::from_raw_address_bytes(&REGTEST.rendezvous.orchard_receiver).unwrap();
        let nf = Nullifier::from_bytes(&[0; 32]).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = (0u8..=u8::MAX)
            .find_map(|byte| Option::from(RandomSeed::from_bytes([byte; 32], &rho)))
            .unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(0),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [0; 512]);
        let ciphertext = encryptor.encrypt_note_plaintext();
        CompactOrchardAction {
            nullifier: nf.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment())
                .to_bytes()
                .to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0.to_vec(),
            ciphertext: ciphertext[..52].to_vec(),
        }
    }

    fn noncandidate_action() -> CompactOrchardAction {
        let mut action = real_rendezvous_action();
        action.ciphertext[0] ^= 1;
        action
    }

    fn compact_tx(index: u64, id: u8, actions: Vec<CompactOrchardAction>) -> CompactTx {
        CompactTx {
            index,
            txid: vec![id; 32],
            ironwood_actions: actions,
            ..Default::default()
        }
    }

    fn block(runtime: &NamesRuntime, transactions: Vec<CompactTx>) -> CompactBlock {
        CompactBlock {
            height: u64::from(runtime.tip().height + 1),
            hash: vec![7; 32],
            prev_hash: runtime.tip().block_hash.to_vec(),
            vtx: transactions,
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct Source {
        calls: Vec<[u8; 32]>,
        values: BTreeMap<[u8; 32], Result<Option<Vec<u8>>, &'static str>>,
    }

    impl FullTransactionSource for Source {
        type Error = &'static str;

        fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.calls.push(txid);
            self.values.remove(&txid).unwrap_or(Ok(None))
        }
    }

    #[test]
    fn real_public_rendezvous_detector_distinguishes_a_foreign_compact_action() {
        let hit = CompactAction::try_from(&real_rendezvous_action()).unwrap();
        assert!(names_carrier::compact_action_is_bulletin(&hit, REGTEST.rendezvous).unwrap());
        let miss = CompactAction::try_from(&noncandidate_action()).unwrap();
        assert!(!names_carrier::compact_action_is_bulletin(&miss, REGTEST.rendezvous).unwrap());
    }

    #[test]
    fn malformed_container_fields_are_panic_free_and_do_not_fetch() {
        let runtime = runtime();
        let mut source = Source::default();

        let mut cases = vec![];
        let mut invalid_height = block(&runtime, vec![]);
        invalid_height.height = u64::from(u32::MAX) + 1;
        cases.push(invalid_height);
        for length in [31, 33] {
            let mut invalid_hash = block(&runtime, vec![]);
            invalid_hash.hash = vec![0; length];
            cases.push(invalid_hash);
        }
        let mut invalid_prev = block(&runtime, vec![]);
        invalid_prev.prev_hash = vec![0; 31];
        cases.push(invalid_prev);
        let mut invalid_index = block(&runtime, vec![compact_tx(0, 1, vec![])]);
        invalid_index.vtx[0].index = u64::from(u32::MAX) + 1;
        cases.push(invalid_index);
        for length in [31, 33] {
            let mut invalid_txid = block(&runtime, vec![compact_tx(0, 1, vec![])]);
            invalid_txid.vtx[0].txid = vec![0; length];
            cases.push(invalid_txid);
        }

        for malformed in cases {
            assert!(prepare_canonical_block(&params(), &runtime, &malformed, &mut source).is_err());
        }
        assert!(source.calls.is_empty());
    }

    #[test]
    fn every_compact_action_field_is_checked_before_fetch() {
        let runtime = runtime();
        let valid = real_rendezvous_action();
        let mut malformed = Vec::new();
        for length in [31, 33] {
            let mut action = valid.clone();
            action.nullifier = vec![0; length];
            malformed.push(action);
        }
        let mut action = valid.clone();
        action.nullifier = vec![0xff; 32];
        malformed.push(action);
        for length in [31, 33] {
            let mut action = valid.clone();
            action.cmx = vec![0; length];
            malformed.push(action);
        }
        let mut action = valid.clone();
        action.cmx = vec![0xff; 32];
        malformed.push(action);
        let mut action = valid.clone();
        action.ephemeral_key = vec![0; 31];
        malformed.push(action);
        for length in [51, 53] {
            let mut action = valid.clone();
            action.ciphertext = vec![0; length];
            malformed.push(action);
        }

        let mut source = Source::default();
        for action in malformed {
            let input = block(&runtime, vec![compact_tx(2, 1, vec![action])]);
            assert!(matches!(
                prepare_canonical_block(&params(), &runtime, &input, &mut source),
                Err(CompactBlockAdapterError::InvalidIronwoodCompactAction { .. })
            ));
        }
        assert!(source.calls.is_empty());
    }

    #[test]
    fn static_validation_precedes_fetch_and_sparse_order_is_accepted() {
        let runtime = runtime();
        let candidate = real_rendezvous_action();
        let malformed = CompactOrchardAction {
            nullifier: vec![0; 31],
            ..candidate.clone()
        };
        let invalid_late = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![candidate.clone()]),
                compact_tx(7, 2, vec![malformed]),
            ],
        );
        let mut source = Source::default();
        assert!(prepare_canonical_block(&params(), &runtime, &invalid_late, &mut source).is_err());
        assert!(source.calls.is_empty());

        for indices in [[2, 11, 7], [2, 2, 11]] {
            let input = block(
                &runtime,
                indices
                    .into_iter()
                    .enumerate()
                    .map(|(id, index)| compact_tx(index, id as u8, vec![]))
                    .collect(),
            );
            assert!(matches!(
                prepare_canonical_block(&params(), &runtime, &input, &mut source),
                Err(CompactBlockAdapterError::NonCanonicalTxOrder)
            ));
        }

        let sparse = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![]),
                compact_tx(7, 2, vec![]),
                compact_tx(11, 3, vec![]),
            ],
        );
        let prepared = prepare_canonical_block(&params(), &runtime, &sparse, &mut source).unwrap();
        assert_eq!(
            prepared
                .transactions
                .iter()
                .map(|tx| tx.tx_index)
                .collect::<Vec<_>>(),
            vec![2, 7, 11]
        );
    }

    #[test]
    fn candidates_fetch_once_per_transaction_in_canonical_order() {
        let runtime = runtime();
        let candidate = real_rendezvous_action();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![candidate.clone(), candidate.clone()]),
                compact_tx(7, 2, vec![noncandidate_action()]),
                compact_tx(11, 3, vec![candidate]),
            ],
        );
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![1])));
        source.values.insert([3; 32], Ok(Some(vec![3])));
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(source.calls, vec![[1; 32], [3; 32]]);
        assert!(prepared.transactions[0].full_tx_required);
        assert!(!prepared.transactions[1].full_tx_required);
        assert_eq!(prepared.transactions[1].candidate_full_tx, None);
    }

    #[test]
    fn zero_and_three_candidate_fetch_counts_are_exact() {
        let runtime = runtime();
        let no_hits = block(
            &runtime,
            vec![compact_tx(2, 1, vec![noncandidate_action()])],
        );
        let mut source = Source::default();
        prepare_canonical_block(&params(), &runtime, &no_hits, &mut source).unwrap();
        assert!(source.calls.is_empty());

        let hit = real_rendezvous_action();
        let three = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![hit.clone()]),
                compact_tx(7, 2, vec![hit.clone()]),
                compact_tx(11, 3, vec![hit]),
            ],
        );
        for id in 1..=3 {
            source.values.insert([id; 32], Ok(Some(vec![id])));
        }
        prepare_canonical_block(&params(), &runtime, &three, &mut source).unwrap();
        assert_eq!(source.calls, vec![[1; 32], [2; 32], [3; 32]]);
    }

    #[test]
    fn candidate_bytes_are_bounded_before_core_parsing() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
        );
        let mut source = Source::default();
        source
            .values
            .insert([1; 32], Ok(Some(vec![0; MAX_CANDIDATE_FULL_TX_BYTES + 1])));
        assert!(matches!(
            prepare_canonical_block(&params(), &runtime, &input, &mut source),
            Err(CompactBlockAdapterError::CandidateFullTransactionTooLarge {
                txid,
                len,
                limit: MAX_CANDIDATE_FULL_TX_BYTES,
                ..
            }) if txid == [1; 32] && len == MAX_CANDIDATE_FULL_TX_BYTES + 1
        ));
    }

    #[test]
    fn cumulative_candidate_bytes_are_bounded_in_canonical_fetch_order() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![real_rendezvous_action()]),
                compact_tx(7, 2, vec![real_rendezvous_action()]),
            ],
        );
        let each = MAX_CANDIDATE_FULL_TX_BYTES / 2 + 1;
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![0; each])));
        source.values.insert([2; 32], Ok(Some(vec![0; each])));
        assert!(matches!(
            prepare_canonical_block(&params(), &runtime, &input, &mut source),
            Err(CompactBlockAdapterError::CandidateFullTransactionBudgetExceeded {
                txid,
                attempted,
                limit: MAX_CANDIDATE_FULL_TX_BYTES,
                ..
            }) if txid == [2; 32] && attempted == each * 2
        ));
        assert_eq!(source.calls, vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn preflight_and_late_source_failure_do_not_apply() {
        let mut runtime = runtime();
        let mut wrong_predecessor = block(
            &runtime,
            vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
        );
        wrong_predecessor.prev_hash = vec![8; 32];
        let mut source = Source::default();
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &wrong_predecessor, &mut source),
            Err(CompactBlockApplyError::Prepare(
                CompactBlockAdapterError::PredecessorMismatch
            ))
        ));
        assert!(source.calls.is_empty());

        let hit = real_rendezvous_action();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![hit.clone()]),
                compact_tx(7, 2, vec![hit]),
            ],
        );
        source.values.insert([1; 32], Ok(Some(vec![1])));
        source.values.insert([2; 32], Err("late transport"));
        let before_tip = runtime.tip();
        let before_root = runtime.ironwood_frontier().root();
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &input, &mut source),
            Err(CompactBlockApplyError::Prepare(
                CompactBlockAdapterError::FullTransactionSource("late transport")
            ))
        ));
        assert_eq!(source.calls, vec![[1; 32], [2; 32]]);
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
    }

    #[test]
    fn missing_or_failed_fetch_never_advances_runtime() {
        for value in [Ok(None), Err("transport")] {
            let mut runtime = runtime();
            let before_tip = runtime.tip();
            let before_state = runtime.state().clone();
            let before_root = runtime.ironwood_frontier().root();
            let before_checkpoints = runtime.ironwood_checkpoints().clone();
            let input = block(
                &runtime,
                vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
            );
            let mut source = Source::default();
            source.values.insert([1; 32], value);
            assert!(apply_compact_block(&params(), &mut runtime, &input, &mut source).is_err());
            assert_eq!(runtime.tip(), before_tip);
            assert_eq!(runtime.state(), &before_state);
            assert_eq!(runtime.ironwood_frontier().root(), before_root);
            assert_eq!(runtime.ironwood_checkpoints(), &before_checkpoints);
        }
    }

    #[test]
    fn noncandidate_effects_apply_without_fetch_and_branch_is_parameter_derived() {
        let mut runtime = runtime();
        let action = noncandidate_action();
        let expected_nf: CompactAction = (&action).try_into().unwrap();
        let input = block(&runtime, vec![compact_tx(7, 1, vec![action])]);
        let mut source = Source::default();
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(
            prepared.branch_id,
            BranchId::for_height(&params(), BlockHeight::from_u32(prepared.height))
        );
        assert_eq!(
            prepared.transactions[0].ironwood_nullifiers,
            vec![expected_nf.nullifier().to_bytes()]
        );
        assert_eq!(
            prepared.transactions[0].ironwood_commitments,
            vec![expected_nf.cmx().to_bytes()]
        );
        let applied = apply_compact_block(&params(), &mut runtime, &input, &mut source).unwrap();
        assert!(source.calls.is_empty());
        assert_eq!(
            applied.names.transaction_outcomes,
            vec![NamesTransactionOutcome::NoOperation]
        );
        assert_eq!(applied.core.ironwood_checkpoint().tree_size, 1);
    }

    #[test]
    fn branch_id_changes_with_consensus_parameters() {
        let runtime = runtime();
        let input = block(&runtime, vec![]);
        let mut before_nu6_3 = params();
        before_nu6_3.nu6_3 = None;
        let mut source = Source::default();
        let prepared =
            prepare_canonical_block(&before_nu6_3, &runtime, &input, &mut source).unwrap();
        assert_eq!(prepared.branch_id, BranchId::Nu6_2);
        assert_ne!(prepared.branch_id, BranchId::Nu6_3);
    }

    #[test]
    fn malformed_fetched_transaction_is_runtime_fatal_and_atomic() {
        let mut runtime = runtime();
        let before_tip = runtime.tip();
        let before_state = runtime.state().clone();
        let before_root = runtime.ironwood_frontier().root();
        let before_checkpoints = runtime.ironwood_checkpoints().clone();
        let input = block(
            &runtime,
            vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
        );
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![0; 4])));
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &input, &mut source),
            Err(CompactBlockApplyError::Runtime(NamesRuntimeError::Core(
                CoreReplayError::InvalidFullTransaction
            )))
        ));
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.state(), &before_state);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
        assert_eq!(runtime.ironwood_checkpoints(), &before_checkpoints);
    }
}
