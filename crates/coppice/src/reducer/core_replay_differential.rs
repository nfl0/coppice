use super::*;
use crate::config::Rendezvous;
use coppice_core::replay::{
    CandidateTransactionStatus, CoreBlockContext, CoreIronwoodCheckpoint, CoreReplay,
    CoreReplayConfiguration, CoreReplayConfigurationError, CoreReplayError, CoreReplayTip,
    CoreRewindError,
};
use orchard::{note::Nullifier, tree::MerkleHashOrchard};
use std::collections::BTreeMap;
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_protocol::consensus::{BlockHeight, NetworkType};

const ACTIVATION_HEIGHT: u32 = 100;
const ACTIVATION_HASH: [u8; 32] = [9; 32];
type NormalizedTip = (u32, [u8; 32]);
type RetainedTip = (u32, Option<NormalizedTip>);

fn deployment() -> DeploymentParameters {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../test-vectors/deployment.json")).unwrap();
    let input = &fixture["input"];
    DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: ACTIVATION_HEIGHT,
        minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    }
}

fn replay_pair() -> (Reducer, CoreReplay) {
    let deployment = deployment();
    let retention = required_reorg_retention_blocks(&deployment).unwrap();
    let checkpoint = ActivationCheckpoint {
        height: ACTIVATION_HEIGHT - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    };
    let legacy = Reducer::new(deployment, checkpoint.clone()).unwrap();
    let core = CoreReplay::new(
        CoreReplayConfiguration::new(ACTIVATION_HEIGHT, retention).unwrap(),
        checkpoint,
    )
    .unwrap();
    (legacy, core)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedReplayObservation {
    tip: NormalizedTip,
    frontier: IronwoodFrontier,
    checkpoints: Vec<(u32, [u8; 32], u32)>,
    oldest_rewind_height: u32,
    retained_tips: Vec<RetainedTip>,
    rewind_availability: Vec<(u32, bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LegacyFullObservation {
    state: CoppiceState,
    frontier: IronwoodFrontier,
    checkpoints: BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
    tip: ReplayTip,
    state_root: [u8; 32],
    history: BTreeMap<u32, ReducerUndo>,
}

fn legacy_full_observation(reducer: &Reducer) -> LegacyFullObservation {
    LegacyFullObservation {
        state: reducer.state.clone(),
        frontier: reducer.ironwood_tree.clone(),
        checkpoints: reducer.ironwood_checkpoints.clone(),
        tip: reducer.tip,
        state_root: reducer.state_root,
        history: reducer.history.clone(),
    }
}

fn legacy_core_observation(reducer: &Reducer) -> NormalizedReplayObservation {
    let start = reducer.deployment.activation_height - 1;
    let tip = reducer.tip;
    NormalizedReplayObservation {
        tip: (tip.height, tip.block_hash),
        frontier: reducer.ironwood_tree.clone(),
        checkpoints: reducer
            .ironwood_checkpoints
            .values()
            .map(|checkpoint| (checkpoint.height, checkpoint.root, checkpoint.tree_size))
            .collect(),
        oldest_rewind_height: reducer.oldest_rewind_height(),
        retained_tips: (start..=tip.height)
            .map(|height| {
                (
                    height,
                    reducer
                        .retained_tip_at(height)
                        .map(|tip| (tip.height, tip.block_hash)),
                )
            })
            .collect(),
        rewind_availability: (start..=tip.height)
            .map(|height| (height, reducer.has_rewind_snapshot(height)))
            .collect(),
    }
}

fn core_observation(replay: &CoreReplay) -> NormalizedReplayObservation {
    let start = replay.configuration().activation_height() - 1;
    let tip = replay.tip();
    NormalizedReplayObservation {
        tip: (tip.height, tip.block_hash),
        frontier: replay.ironwood_frontier().clone(),
        checkpoints: replay
            .ironwood_checkpoints()
            .values()
            .map(|checkpoint| (checkpoint.height, checkpoint.root, checkpoint.tree_size))
            .collect(),
        oldest_rewind_height: replay.oldest_rewind_height(),
        retained_tips: (start..=tip.height)
            .map(|height| {
                (
                    height,
                    replay
                        .retained_tip_at(height)
                        .map(|tip| (tip.height, tip.block_hash)),
                )
            })
            .collect(),
        rewind_availability: (start..=tip.height)
            .map(|height| (height, replay.has_rewind_snapshot(height)))
            .collect(),
    }
}

fn assert_replay_equivalent(legacy: &Reducer, core: &CoreReplay) {
    assert_eq!(legacy_core_observation(legacy), core_observation(core));
}

fn map_core_error(error: CoreReplayError) -> FatalReducerError {
    match error {
        CoreReplayError::InvalidActivationCheckpoint => {
            FatalReducerError::InvalidActivationCheckpoint
        }
        CoreReplayError::NonSequentialHeight => FatalReducerError::NonSequentialHeight,
        CoreReplayError::PredecessorMismatch => FatalReducerError::PredecessorMismatch,
        CoreReplayError::NonCanonicalTxOrder => FatalReducerError::NonCanonicalTxOrder,
        CoreReplayError::CandidateFlagMismatch => FatalReducerError::CandidateFlagMismatch,
        CoreReplayError::RequiredFullTransactionMissing => {
            FatalReducerError::RequiredFullTransactionMissing
        }
        CoreReplayError::OversizedTransaction => FatalReducerError::OversizedTransaction,
        CoreReplayError::InvalidFullTransaction => FatalReducerError::InvalidFullTransaction,
        CoreReplayError::TxidMismatch => FatalReducerError::TxidMismatch,
        CoreReplayError::IronwoodEffectsMismatch => FatalReducerError::IronwoodEffectsMismatch,
        CoreReplayError::NonCanonicalNullifier => FatalReducerError::NonCanonicalNullifier,
        CoreReplayError::InvalidIronwoodCommitment => FatalReducerError::InvalidIronwoodCommitment,
        CoreReplayError::IronwoodAppendFailure => FatalReducerError::IronwoodAppendFailure,
        CoreReplayError::ArithmeticOverflow => FatalReducerError::ArithmeticOverflow,
    }
}

fn assert_context(block: &CanonicalBlockInput, legacy: &AppliedBlock, context: &CoreBlockContext) {
    assert_eq!(context.height(), block.height);
    assert_eq!(context.block_hash(), block.block_hash);
    assert_eq!(context.prev_block_hash(), block.prev_block_hash);
    assert_eq!(context.branch_id(), block.branch_id);
    assert_eq!(context.transactions().len(), block.transactions.len());
    assert_eq!(legacy.transaction_outcomes.len(), block.transactions.len());
    let checkpoint = context.ironwood_checkpoint();
    assert_eq!(
        (checkpoint.height, checkpoint.root, checkpoint.tree_size),
        (
            legacy.ironwood_checkpoint.height,
            legacy.ironwood_checkpoint.root,
            legacy.ironwood_checkpoint.tree_size,
        )
    );

    for (input, transaction) in block.transactions.iter().zip(context.transactions()) {
        assert_eq!(transaction.height(), block.height);
        assert_eq!(transaction.block_hash(), block.block_hash);
        assert_eq!(transaction.tx_index(), input.tx_index);
        assert_eq!(transaction.txid(), input.txid);
        assert_eq!(
            transaction.ironwood_effects().nullifiers(),
            input.ironwood_nullifiers
        );
        assert_eq!(
            transaction.ironwood_effects().commitments(),
            input.ironwood_commitments
        );
        match (
            input.full_tx_required,
            transaction.candidate_status(),
            input.candidate_full_tx.as_deref(),
        ) {
            (false, CandidateTransactionStatus::NotCandidate, None) => {}
            (
                true,
                CandidateTransactionStatus::ValidatedFullTransaction(validated),
                Some(bytes),
            ) => {
                assert_eq!(validated.bytes(), bytes);
                let parsed_txid: [u8; 32] = validated.transaction().txid().into();
                assert_eq!(parsed_txid, input.txid);
            }
            status => panic!("unexpected candidate status: {status:?}"),
        }
    }
}

fn apply_success(
    legacy: &mut Reducer,
    core: &mut CoreReplay,
    block: &CanonicalBlockInput,
) -> CoreBlockContext {
    let legacy_applied = legacy.apply_block(block).unwrap();
    let context = core.apply_block(block).unwrap();
    assert_context(block, &legacy_applied, &context);
    assert_replay_equivalent(legacy, core);
    context
}

fn apply_error(
    legacy: &mut Reducer,
    core: &mut CoreReplay,
    block: &CanonicalBlockInput,
    expected: FatalReducerError,
) {
    let legacy_before = legacy_full_observation(legacy);
    let core_before = core_observation(core);
    assert_eq!(legacy.apply_block(block), Err(expected.clone()));
    let core_error = core.apply_block(block).unwrap_err();
    assert_eq!(map_core_error(core_error), expected);
    assert_eq!(legacy_full_observation(legacy), legacy_before);
    assert_eq!(core_observation(core), core_before);
    assert_replay_equivalent(legacy, core);
}

fn empty_block(
    height: u32,
    block_hash: [u8; 32],
    prev_block_hash: [u8; 32],
) -> CanonicalBlockInput {
    CanonicalBlockInput {
        height,
        block_hash,
        prev_block_hash,
        branch_id: BranchId::Nu6_3,
        transactions: vec![],
    }
}

fn empty_transaction(index: u32) -> CanonicalTxInput {
    CanonicalTxInput {
        tx_index: index,
        txid: [index as u8; 32],
        ironwood_nullifiers: vec![],
        ironwood_commitments: vec![],
        full_tx_required: false,
        candidate_full_tx: None,
    }
}

fn valid_nullifier(marker: u8) -> [u8; 32] {
    for suffix in 0..=u8::MAX {
        let mut candidate = [marker; 32];
        candidate[31] = suffix;
        if Option::<Nullifier>::from(Nullifier::from_bytes(&candidate)).is_some() {
            return candidate;
        }
    }
    panic!("test marker must yield a canonical nullifier")
}

fn valid_commitment(marker: u8) -> [u8; 32] {
    for suffix in 0..=u8::MAX {
        let mut candidate = [marker; 32];
        candidate[31] = suffix;
        if Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&candidate)).is_some() {
            return candidate;
        }
    }
    panic!("test marker must yield a canonical commitment")
}

fn empty_v6_transaction() -> (Vec<u8>, [u8; 32]) {
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(ACTIVATION_HEIGHT),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .unwrap();
    let txid = transaction.txid().into();
    let mut bytes = vec![];
    transaction.write(&mut bytes).unwrap();
    (bytes, txid)
}

fn generated_block(
    height: u32,
    prev_block_hash: [u8; 32],
    branch_marker: u8,
) -> CanonicalBlockInput {
    let marker = branch_marker.wrapping_add(height as u8);
    let mut block_hash = [marker; 32];
    block_hash[..4].copy_from_slice(&height.to_be_bytes());
    let has_effects = height.is_multiple_of(3) || height.is_multiple_of(5);
    let transactions = if has_effects {
        vec![
            CanonicalTxInput {
                tx_index: 1,
                txid: [marker; 32],
                ironwood_nullifiers: height
                    .is_multiple_of(5)
                    .then(|| valid_nullifier(marker))
                    .into_iter()
                    .collect(),
                ironwood_commitments: height
                    .is_multiple_of(3)
                    .then(|| valid_commitment(marker))
                    .into_iter()
                    .collect(),
                full_tx_required: false,
                candidate_full_tx: None,
            },
            empty_transaction(7),
        ]
    } else {
        vec![]
    };
    CanonicalBlockInput {
        height,
        block_hash,
        prev_block_hash,
        branch_id: BranchId::Nu6_3,
        transactions,
    }
}

#[test]
fn replay_configuration_and_activation_validation_are_differential() {
    assert_eq!(
        CoreReplayConfiguration::new(0, 1),
        Err(CoreReplayConfigurationError::ZeroActivationHeight)
    );
    assert_eq!(
        CoreReplayConfiguration::new(1, 0),
        Err(CoreReplayConfigurationError::ZeroRetention)
    );
    assert_eq!(
        MAX_TRANSACTION_LEN,
        coppice_core::replay::MAX_FULL_TRANSACTION_LEN
    );

    let deployment = deployment();
    let retention = required_reorg_retention_blocks(&deployment).unwrap();
    assert_eq!(retention, 121);
    let checkpoint = ActivationCheckpoint {
        height: ACTIVATION_HEIGHT,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    };
    assert!(matches!(
        Reducer::new(deployment, checkpoint.clone()),
        Err(FatalReducerError::InvalidActivationCheckpoint)
    ));
    assert_eq!(
        CoreReplay::new(
            CoreReplayConfiguration::new(ACTIVATION_HEIGHT, retention).unwrap(),
            checkpoint,
        )
        .err(),
        Some(CoreReplayError::InvalidActivationCheckpoint)
    );
}

#[test]
fn hostile_inputs_candidate_validation_and_atomicity_are_differential() {
    let (mut legacy, mut core) = replay_pair();

    let mut block = empty_block(101, [10; 32], ACTIVATION_HASH);
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::NonSequentialHeight,
    );
    block.height = ACTIVATION_HEIGHT;
    block.prev_block_hash = [8; 32];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::PredecessorMismatch,
    );

    block.prev_block_hash = ACTIVATION_HASH;
    block.transactions = vec![empty_transaction(2), empty_transaction(2)];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::NonCanonicalTxOrder,
    );

    let mut candidate = empty_transaction(0);
    candidate.candidate_full_tx = Some(vec![]);
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::CandidateFlagMismatch,
    );

    let mut candidate = empty_transaction(0);
    candidate.full_tx_required = true;
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::RequiredFullTransactionMissing,
    );

    let mut candidate = empty_transaction(0);
    candidate.full_tx_required = true;
    candidate.candidate_full_tx = Some(vec![1, 2, 3]);
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::InvalidFullTransaction,
    );

    let mut candidate = empty_transaction(0);
    candidate.full_tx_required = true;
    candidate.candidate_full_tx = Some(vec![0; MAX_TRANSACTION_LEN + 1]);
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::OversizedTransaction,
    );

    let (valid_bytes, valid_txid) = empty_v6_transaction();
    let mut candidate = empty_transaction(0);
    candidate.full_tx_required = true;
    candidate.candidate_full_tx = Some(valid_bytes.clone());
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::TxidMismatch,
    );

    let mut candidate = empty_transaction(0);
    candidate.txid = valid_txid;
    candidate.full_tx_required = true;
    candidate.candidate_full_tx = Some(valid_bytes.clone());
    candidate.ironwood_commitments = vec![valid_commitment(0x44)];
    block.transactions = vec![candidate];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::IronwoodEffectsMismatch,
    );

    let mut invalid_nullifier = empty_transaction(0);
    invalid_nullifier.ironwood_nullifiers = vec![[0xff; 32]];
    block.transactions = vec![invalid_nullifier];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::NonCanonicalNullifier,
    );

    let mut prior_valid = empty_transaction(0);
    prior_valid.ironwood_nullifiers = vec![valid_nullifier(0x31)];
    prior_valid.ironwood_commitments = vec![valid_commitment(0x32)];
    let mut later_invalid = empty_transaction(4);
    later_invalid.ironwood_commitments = vec![[0xff; 32]];
    block.transactions = vec![prior_valid, later_invalid];
    apply_error(
        &mut legacy,
        &mut core,
        &block,
        FatalReducerError::InvalidIronwoodCommitment,
    );

    let mut effects = empty_transaction(2);
    effects.ironwood_nullifiers = vec![valid_nullifier(0x51)];
    effects.ironwood_commitments = vec![valid_commitment(0x52)];
    let mut candidate = empty_transaction(8);
    candidate.txid = valid_txid;
    candidate.full_tx_required = true;
    candidate.candidate_full_tx = Some(valid_bytes);
    block.transactions = vec![effects, candidate];
    let context = apply_success(&mut legacy, &mut core, &block);
    assert!(matches!(
        context.transactions()[0].candidate_status(),
        CandidateTransactionStatus::NotCandidate
    ));
    assert!(
        context.transactions()[1]
            .candidate_status()
            .validated_full_transaction()
            .is_some()
    );
}

#[test]
fn maximum_height_is_fatal_and_atomic_with_legacy_diagnostic_difference() {
    let mut deployment = deployment();
    deployment.activation_height = u32::MAX;
    let retention = required_reorg_retention_blocks(&deployment).unwrap();
    let checkpoint = ActivationCheckpoint {
        height: u32::MAX - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    };
    let mut legacy = Reducer::new(deployment, checkpoint.clone()).unwrap();
    let mut core = CoreReplay::new(
        CoreReplayConfiguration::new(u32::MAX, retention).unwrap(),
        checkpoint,
    )
    .unwrap();
    let block = empty_block(u32::MAX, [0xfe; 32], ACTIVATION_HASH);
    let legacy_before = legacy_full_observation(&legacy);
    let core_before = core_observation(&core);
    assert_eq!(
        legacy.apply_block(&block),
        Err(FatalReducerError::StateInvariantFailure)
    );
    assert_eq!(
        core.apply_block(&block),
        Err(CoreReplayError::ArithmeticOverflow)
    );
    assert_eq!(legacy_full_observation(&legacy), legacy_before);
    assert_eq!(core_observation(&core), core_before);
    assert_replay_equivalent(&legacy, &core);
}

#[test]
fn retained_rewind_replay_and_fresh_replay_are_differential() {
    let (mut legacy, mut core) = replay_pair();
    let mut prefix = Vec::new();
    let mut prev_hash = ACTIVATION_HASH;
    for height in ACTIVATION_HEIGHT..=230 {
        let block = generated_block(height, prev_hash, 0x10);
        prev_hash = block.block_hash;
        apply_success(&mut legacy, &mut core, &block);
        prefix.push(block);
    }
    assert_eq!(legacy.oldest_rewind_height(), 109);
    assert_eq!(core.oldest_rewind_height(), 109);

    let legacy_before = legacy_full_observation(&legacy);
    let core_before = core_observation(&core);
    assert_eq!(legacy.rewind_to(98), Err(RewindError::BeforeActivation));
    assert_eq!(core.rewind_to(98), Err(CoreRewindError::BeforeActivation));
    assert_eq!(legacy.rewind_to(231), Err(RewindError::BeyondTip));
    assert_eq!(core.rewind_to(231), Err(CoreRewindError::BeyondTip));
    assert_eq!(legacy.rewind_to(108), Err(RewindError::SnapshotMissing));
    assert_eq!(core.rewind_to(108), Err(CoreRewindError::SnapshotMissing));
    assert_eq!(legacy_full_observation(&legacy), legacy_before);
    assert_eq!(core_observation(&core), core_before);

    let common_height = 115;
    legacy.rewind_to(common_height).unwrap();
    core.rewind_to(common_height).unwrap();
    assert_replay_equivalent(&legacy, &core);

    let (mut fresh_legacy, mut fresh_core) = replay_pair();
    for block in prefix
        .iter()
        .take((common_height - ACTIVATION_HEIGHT + 1) as usize)
    {
        apply_success(&mut fresh_legacy, &mut fresh_core, block);
    }
    assert_replay_equivalent(&fresh_legacy, &fresh_core);
    assert_eq!(legacy.tip, fresh_legacy.tip);
    assert_eq!(legacy.state, fresh_legacy.state);
    assert_eq!(legacy.state_root, fresh_legacy.state_root);
    assert_eq!(legacy.ironwood_tree, fresh_legacy.ironwood_tree);
    assert_eq!(
        legacy.ironwood_checkpoints,
        fresh_legacy.ironwood_checkpoints
    );
    assert_eq!(core.tip(), fresh_core.tip());
    assert_eq!(core.ironwood_frontier(), fresh_core.ironwood_frontier());
    assert_eq!(
        core.ironwood_checkpoints(),
        fresh_core.ironwood_checkpoints()
    );
    // Rewind cannot recreate undo records that the long-lived replay already
    // pruned; the fresh short replay still has those older records. Both the
    // legacy and Core paths preserve that same bounded-journal distinction.
    assert_eq!(legacy.oldest_rewind_height(), 109);
    assert_eq!(core.oldest_rewind_height(), 109);
    assert_eq!(fresh_legacy.oldest_rewind_height(), 99);
    assert_eq!(fresh_core.oldest_rewind_height(), 99);

    let mut prev_hash = legacy.tip.block_hash;
    let mut replacement_contexts = Vec::new();
    let mut fresh_contexts = Vec::new();
    for height in (common_height + 1)..=238 {
        let block = generated_block(height, prev_hash, 0x80);
        prev_hash = block.block_hash;
        replacement_contexts.push(apply_success(&mut legacy, &mut core, &block));
        fresh_contexts.push(apply_success(&mut fresh_legacy, &mut fresh_core, &block));
    }
    assert_eq!(replacement_contexts, fresh_contexts);
    assert_eq!(
        legacy_core_observation(&legacy),
        legacy_core_observation(&fresh_legacy)
    );
    assert_eq!(core_observation(&core), core_observation(&fresh_core));
    assert_eq!(legacy.state, fresh_legacy.state);
    assert_eq!(legacy.state_root, fresh_legacy.state_root);
}

#[test]
fn normalized_checkpoint_types_cover_every_retained_entry() {
    let (mut legacy, mut core) = replay_pair();
    let block = generated_block(ACTIVATION_HEIGHT, ACTIVATION_HASH, 0x40);
    let context = apply_success(&mut legacy, &mut core, &block);
    let checkpoint: CoreIronwoodCheckpoint = context.ironwood_checkpoint();
    let tip: CoreReplayTip = core.tip();
    assert_eq!(checkpoint.height, tip.height);
    assert_eq!(checkpoint.root, core.ironwood_frontier().root().to_bytes());
    assert_eq!(
        checkpoint.tree_size as usize,
        core.ironwood_frontier().size()
    );
}
