use super::*;
use crate::{
    authorization,
    bond::{V1BondProver, V1BondWitness},
    bond_tag, carrier_v1,
    config::Rendezvous,
    names_runtime::{
        NamesProtocolRejection, NamesRuntime, NamesRuntimeAppliedBlock, NamesRuntimeError,
        NamesTransactionOutcome,
    },
};
use coppice_core::{
    application::CoppiceApplication,
    replay::{CoreReplay, CoreReplayConfiguration},
};
use incrementalmerkletree::Retention;
use orchard::{
    Note, Proof,
    builder::{Builder, BundleType},
    bundle::{Authorized as OrchardAuthorized, BundleVersion},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    primitives::redpallas::{Binding, SigningKey, SpendAuth},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_address::unified::{self, Encoding};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType},
    value::ZatBalance,
};

const ACTIVATION_HEIGHT: u32 = 100;
const ACTIVATION_HASH: [u8; 32] = [9; 32];

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

fn replay_pair() -> (Reducer, NamesRuntime) {
    let deployment = deployment();
    let checkpoint = ActivationCheckpoint {
        height: ACTIVATION_HEIGHT - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    };
    let legacy = Reducer::new(deployment.clone(), checkpoint.clone()).unwrap();
    let runtime = NamesRuntime::from_names_deployment(deployment, checkpoint).unwrap();
    assert_eq!(legacy.state(), runtime.names().state());
    assert_eq!(legacy.state_root, runtime.names().state_root());
    assert_eq!(legacy.tip.height, runtime.names().tip().height);
    assert_eq!(legacy.tip.block_hash, runtime.names().tip().block_hash);
    (legacy, runtime)
}

fn candidate_transaction(
    deployment: &DeploymentParameters,
    operation: &Operation,
    seed: u8,
) -> CanonicalTxInput {
    let payload = crate::envelope::encode_operation(operation).unwrap();
    let frames =
        carrier_v1::encode_frames_v1(deployment.deployment_id().unwrap(), &payload).unwrap();
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    let receiver = crate::carrier::bulletin_address(deployment.rendezvous).unwrap();
    for frame in frames {
        builder
            .add_output(None, receiver, NoteValue::ZERO, frame)
            .unwrap();
    }
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let action_count = unauthorized.actions().len();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(action_count)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceTestSpendAuth"),
        |rng, _| {
            OrchardAuthorized::from_parts(proof, binding_key.sign(&mut *rng, b"CoppiceTestBinding"))
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(ACTIVATION_HEIGHT),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let txid = transaction.txid().into();
    let effects = crate::ironwood::extract_ironwood_effects(&transaction);
    let mut bytes = Vec::new();
    transaction.write(&mut bytes).unwrap();
    CanonicalTxInput {
        tx_index: u32::from(seed),
        txid,
        ironwood_nullifiers: effects.nullifiers,
        ironwood_commitments: effects.commitments,
        full_tx_required: true,
        candidate_full_tx: Some(bytes),
    }
}

struct BondMaterial {
    input: CanonicalTxInput,
    note: Note,
    full_viewing_key: FullViewingKey,
    spend_authorizing_key: SpendAuthorizingKey,
}

fn bond_transaction(deployment: &DeploymentParameters, seed: u8) -> BondMaterial {
    let spending_key = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
    let spend_authorizing_key = SpendAuthorizingKey::from(&spending_key);
    let full_viewing_key = FullViewingKey::from(&spending_key);
    let incoming_viewing_key = full_viewing_key.to_ivk(Scope::External);
    let recipient = full_viewing_key.address_at(0u32, Scope::External);
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(deployment.minimum_bond_value),
            [0; 512],
        )
        .unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let action = &unauthorized.actions()[0];
    let (note, _, _) = try_note_decryption(
        &IronwoodDomain::for_action(action),
        &incoming_viewing_key.prepare(),
        action,
    )
    .unwrap();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(1)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceTestSpendAuth"),
        |rng, _| {
            OrchardAuthorized::from_parts(proof, binding_key.sign(&mut *rng, b"CoppiceTestBinding"))
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(ACTIVATION_HEIGHT),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let effects = crate::ironwood::extract_ironwood_effects(&transaction);
    BondMaterial {
        input: CanonicalTxInput {
            tx_index: u32::from(seed),
            txid: transaction.txid().into(),
            ironwood_nullifiers: effects.nullifiers,
            ironwood_commitments: effects.commitments,
            full_tx_required: false,
            candidate_full_tx: None,
        },
        note,
        full_viewing_key,
        spend_authorizing_key,
    }
}

fn witness_for_chain(
    bond: BondMaterial,
    prior_commitments: impl IntoIterator<Item = [u8; 32]>,
) -> V1BondWitness {
    let bond_commitment = ExtractedNoteCommitment::from(bond.note.commitment());
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    let mut position = 0u32;
    for commitment in prior_commitments {
        let node =
            Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&commitment)).unwrap();
        tree.append(node, Retention::Ephemeral).unwrap();
        position += 1;
    }
    assert_eq!(
        bond.input.ironwood_commitments,
        vec![bond_commitment.to_bytes()]
    );
    tree.append(
        MerkleHashOrchard::from_cmx(&bond_commitment),
        Retention::Marked,
    )
    .unwrap();
    tree.checkpoint(1).unwrap();
    let merkle_path: MerklePath = tree
        .witness_at_checkpoint_depth(u64::from(position).into(), 0)
        .unwrap()
        .unwrap()
        .into();
    V1BondWitness {
        note: bond.note,
        full_viewing_key: bond.full_viewing_key,
        spend_authorizing_key: bond.spend_authorizing_key,
        merkle_path,
    }
}

fn canonical_address(deployment: &DeploymentParameters, key_byte: u8) -> Vec<u8> {
    let key = Option::<SpendingKey>::from(SpendingKey::from_bytes([key_byte; 32])).unwrap();
    let receiver = FullViewingKey::from(&key)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    unified::Address::try_from_items(vec![unified::Receiver::Orchard(receiver)])
        .unwrap()
        .encode(&deployment.address_network)
        .into_bytes()
}

fn block(
    legacy: &Reducer,
    height: u32,
    transactions: Vec<CanonicalTxInput>,
) -> CanonicalBlockInput {
    CanonicalBlockInput {
        height,
        block_hash: [height as u8; 32],
        prev_block_hash: legacy.tip.block_hash,
        branch_id: BranchId::Nu6_3,
        transactions,
    }
}

fn map_rejection(rejection: NamesProtocolRejection) -> ProtocolRejection {
    match rejection {
        NamesProtocolRejection::InvalidName => ProtocolRejection::InvalidName,
        NamesProtocolRejection::InvalidAddress => ProtocolRejection::InvalidAddress,
        NamesProtocolRejection::InvalidOwnerKey => ProtocolRejection::InvalidOwnerKey,
        NamesProtocolRejection::DuplicateCommitment => ProtocolRejection::DuplicateCommitment,
        NamesProtocolRejection::UnknownCommitment => ProtocolRejection::UnknownCommitment,
        NamesProtocolRejection::CommitmentNotMature => ProtocolRejection::CommitmentNotMature,
        NamesProtocolRejection::CommitmentExpired => ProtocolRejection::CommitmentExpired,
        NamesProtocolRejection::NameUnavailable => ProtocolRejection::NameUnavailable,
        NamesProtocolRejection::CommitPredatesClaimEpoch => {
            ProtocolRejection::CommitPredatesClaimEpoch
        }
        NamesProtocolRejection::InvalidSequence => ProtocolRejection::InvalidSequence,
        NamesProtocolRejection::InvalidSignature => ProtocolRejection::InvalidSignature,
        NamesProtocolRejection::BondAlreadyInUse => ProtocolRejection::BondAlreadyInUse,
        NamesProtocolRejection::BondRecentlySpent => ProtocolRejection::BondRecentlySpent,
        NamesProtocolRejection::InvalidBondAnchorHeight => {
            ProtocolRejection::InvalidBondAnchorHeight
        }
        NamesProtocolRejection::UnknownBondAnchor => ProtocolRejection::UnknownBondAnchor,
        NamesProtocolRejection::InvalidBondProof => ProtocolRejection::InvalidBondProof,
        NamesProtocolRejection::OversizedProof => ProtocolRejection::OversizedProof,
        NamesProtocolRejection::MalformedCarrier => ProtocolRejection::MalformedCarrier,
        NamesProtocolRejection::MalformedOperation => ProtocolRejection::MalformedOperation,
    }
}

fn map_outcome(outcome: NamesTransactionOutcome) -> TransactionOutcome {
    match outcome {
        NamesTransactionOutcome::NoOperation => TransactionOutcome::NoOperation,
        NamesTransactionOutcome::Applied => TransactionOutcome::Applied,
        NamesTransactionOutcome::Rejected(rejection) => {
            TransactionOutcome::Rejected(map_rejection(rejection))
        }
    }
}

fn assert_equivalent(
    legacy: &Reducer,
    runtime: &NamesRuntime,
    legacy_applied: &AppliedBlock,
    runtime_applied: &NamesRuntimeAppliedBlock,
) {
    let names = runtime.names();
    assert_eq!(legacy.state(), names.state());
    assert_eq!(legacy.tip.height, names.tip().height);
    assert_eq!(legacy.tip.block_hash, names.tip().block_hash);
    assert_eq!(legacy.state_root, names.state_root());
    assert_eq!(
        legacy_applied.name_tree_root,
        runtime_applied.names.name_tree_root
    );
    assert_eq!(
        legacy_applied.pending_root,
        runtime_applied.names.pending_root
    );
    assert_eq!(
        legacy_applied.recent_spent_root,
        runtime_applied.names.recent_spent_root
    );
    assert_eq!(legacy_applied.state_root, runtime_applied.names.state_root);
    assert_eq!(
        legacy_applied.transaction_outcomes,
        runtime_applied
            .names
            .transaction_outcomes
            .iter()
            .copied()
            .map(map_outcome)
            .collect::<Vec<_>>()
    );
    assert_eq!(legacy.tip.height, runtime.core().tip().height);
    assert_eq!(legacy.tip.block_hash, runtime.core().tip().block_hash);
    assert_eq!(
        legacy.ironwood_frontier(),
        runtime.core().ironwood_frontier()
    );
    assert_eq!(legacy.oldest_rewind_height(), names.oldest_rewind_height());
    assert_eq!(
        legacy.oldest_rewind_height(),
        runtime.core().oldest_rewind_height()
    );
    assert_eq!(
        (
            legacy_applied.ironwood_checkpoint.height,
            legacy_applied.ironwood_checkpoint.root,
            legacy_applied.ironwood_checkpoint.tree_size,
        ),
        (
            runtime_applied.core.ironwood_checkpoint().height,
            runtime_applied.core.ironwood_checkpoint().root,
            runtime_applied.core.ironwood_checkpoint().tree_size,
        )
    );
    assert_eq!(
        legacy
            .ironwood_checkpoints()
            .values()
            .map(|checkpoint| (checkpoint.height, checkpoint.root, checkpoint.tree_size))
            .collect::<Vec<_>>(),
        runtime
            .core()
            .ironwood_checkpoints()
            .values()
            .map(|checkpoint| (checkpoint.height, checkpoint.root, checkpoint.tree_size))
            .collect::<Vec<_>>()
    );
    for height in legacy.oldest_rewind_height()..=legacy.tip.height {
        assert_eq!(
            legacy
                .retained_tip_at(height)
                .map(|tip| (tip.height, tip.block_hash)),
            names
                .retained_tip_at(height)
                .map(|tip| (tip.height, tip.block_hash))
        );
        assert_eq!(
            legacy
                .retained_tip_at(height)
                .map(|tip| (tip.height, tip.block_hash)),
            runtime
                .core()
                .retained_tip_at(height)
                .map(|tip| (tip.height, tip.block_hash))
        );
    }
}

fn apply_success(
    legacy: &mut Reducer,
    runtime: &mut NamesRuntime,
    input: &CanonicalBlockInput,
) -> (AppliedBlock, NamesRuntimeAppliedBlock) {
    let legacy_applied = legacy.apply_block(input).unwrap();
    let runtime_applied = runtime.apply_block(input).unwrap();
    assert_equivalent(legacy, runtime, &legacy_applied, &runtime_applied);
    (legacy_applied, runtime_applied)
}

#[test]
fn commit_and_duplicate_commit_are_differential_through_real_carriers() {
    let (mut legacy, mut runtime) = replay_pair();
    let operation = Operation::Commit {
        commitment: [0x44; 32],
    };
    let first = candidate_transaction(legacy.deployment(), &operation, 1);
    let input = block(&legacy, 100, vec![first]);
    apply_success(&mut legacy, &mut runtime, &input);

    let duplicate = candidate_transaction(legacy.deployment(), &operation, 2);
    let input = block(&legacy, 101, vec![duplicate]);
    let (legacy_applied, _) = apply_success(&mut legacy, &mut runtime, &input);
    assert_eq!(
        legacy_applied.transaction_outcomes,
        vec![TransactionOutcome::Rejected(
            ProtocolRejection::DuplicateCommitment
        )]
    );
}

#[test]
fn full_names_lifecycle_reorg_pruning_and_fresh_replay_are_differential() {
    let (mut legacy, mut runtime) = replay_pair();
    let owner_key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
    let owner_pk = crate::owner::owner_key_bytes(&(&owner_key).into());
    let address = canonical_address(legacy.deployment(), 8);
    let updated_address = canonical_address(legacy.deployment(), 9);
    let name = "alice";
    let secret = [0x55; 32];
    let bond = bond_transaction(legacy.deployment(), 21);
    let bond_nullifier = bond.note.nullifier(&bond.full_viewing_key).to_bytes();
    let bond_tag = bond_tag::derive_v1_bond_tag(&bond_nullifier).unwrap();
    let commitment = crate::registration::registration_commitment(
        legacy.deployment(),
        name,
        owner_pk,
        bond_tag,
        &address,
        secret,
    )
    .unwrap();
    let commit = Operation::Commit { commitment };
    let commit_input = candidate_transaction(legacy.deployment(), &commit, 1);
    let block_100 = block(&legacy, 100, vec![commit_input.clone()]);
    apply_success(&mut legacy, &mut runtime, &block_100);

    let bond_input = bond.input.clone();
    let witness = witness_for_chain(bond, commit_input.ironwood_commitments.clone());
    let block_101 = block(&legacy, 101, vec![bond_input.clone()]);
    let (_, applied_101) = apply_success(&mut legacy, &mut runtime, &block_101);
    let anchor = applied_101.core.ironwood_checkpoint().root;
    let proof = V1BondProver::new()
        .unwrap()
        .prove_v1_bond(
            witness,
            legacy.deployment(),
            name,
            &address,
            owner_pk,
            bond_tag,
            anchor,
            0,
            ChaCha20Rng::from_seed([42; 32]),
        )
        .unwrap();
    let reveal = Operation::Reveal {
        name: name.to_owned(),
        owner_pk,
        bond_tag,
        bond_anchor_height: 101,
        bond_anchor: anchor,
        bond_proof: proof.proof,
        address: address.clone(),
        secret,
    };
    let reveal_input = candidate_transaction(legacy.deployment(), &reveal, 2);
    let block_102 = block(&legacy, 102, vec![reveal_input]);
    let (applied_102, _) = apply_success(&mut legacy, &mut runtime, &block_102);
    assert_eq!(
        applied_102.transaction_outcomes,
        vec![TransactionOutcome::Applied]
    );
    assert_eq!(legacy.state().names[name].status, NameStatus::Active);

    let mut unknown_reveal = reveal.clone();
    let Operation::Reveal { secret, .. } = &mut unknown_reveal else {
        unreachable!()
    };
    *secret = [0x99; 32];
    let unknown_input = candidate_transaction(legacy.deployment(), &unknown_reveal, 3);
    let block_103 = block(&legacy, 103, vec![unknown_input]);
    let (applied_103, _) = apply_success(&mut legacy, &mut runtime, &block_103);
    assert_eq!(
        applied_103.transaction_outcomes,
        vec![TransactionOutcome::Rejected(
            ProtocolRejection::UnknownCommitment
        )]
    );

    let previous = legacy.state().names[name].clone();
    let mut update = Operation::Update {
        name: name.to_owned(),
        sequence: 1,
        address: updated_address,
        signature: vec![0; 64],
    };
    let signature =
        authorization::sign_v1(legacy.deployment_id(), &owner_key, &update, &previous).unwrap();
    let Operation::Update {
        signature: slot, ..
    } = &mut update
    else {
        unreachable!()
    };
    *slot = signature.to_vec();
    let update_input = candidate_transaction(legacy.deployment(), &update, 4);
    let block_104 = block(&legacy, 104, vec![update_input]);
    apply_success(&mut legacy, &mut runtime, &block_104);
    assert_eq!(legacy.state().names[name].sequence, 1);

    let invalid_sequence = Operation::Update {
        name: name.to_owned(),
        sequence: 3,
        address: address.clone(),
        signature: vec![0; 64],
    };
    let invalid_sequence_input = candidate_transaction(legacy.deployment(), &invalid_sequence, 5);
    let invalid_update = Operation::Update {
        name: name.to_owned(),
        sequence: 2,
        address: address.clone(),
        signature: vec![0; 64],
    };
    let invalid_input = candidate_transaction(legacy.deployment(), &invalid_update, 8);
    let block_105 = block(&legacy, 105, vec![invalid_sequence_input, invalid_input]);
    let (applied_105, _) = apply_success(&mut legacy, &mut runtime, &block_105);
    assert_eq!(
        applied_105.transaction_outcomes,
        vec![
            TransactionOutcome::Rejected(ProtocolRejection::InvalidSequence),
            TransactionOutcome::Rejected(ProtocolRejection::InvalidSignature),
        ]
    );

    let previous = legacy.state().names[name].clone();
    let mut release = Operation::Release {
        name: name.to_owned(),
        sequence: 2,
        signature: vec![0; 64],
    };
    let signature =
        authorization::sign_v1(legacy.deployment_id(), &owner_key, &release, &previous).unwrap();
    let Operation::Release {
        signature: slot, ..
    } = &mut release
    else {
        unreachable!()
    };
    *slot = signature.to_vec();
    let release_input = candidate_transaction(legacy.deployment(), &release, 9);
    let block_106_release = block(&legacy, 106, vec![release_input]);
    apply_success(&mut legacy, &mut runtime, &block_106_release);
    assert_eq!(
        legacy.state().names[name].status,
        NameStatus::Released {
            terminal_height: 106
        }
    );

    legacy.rewind_to(105).unwrap();
    runtime.rewind_to(105).unwrap();
    assert_eq!(legacy.state(), runtime.names().state());
    assert_eq!(legacy.state_root, runtime.names().state_root());
    let bond_spend = CanonicalTxInput {
        tx_index: 0,
        txid: [0x77; 32],
        ironwood_nullifiers: vec![bond_nullifier],
        ironwood_commitments: vec![],
        full_tx_required: false,
        candidate_full_tx: None,
    };
    let block_106_spend = block(&legacy, 106, vec![bond_spend]);
    apply_success(&mut legacy, &mut runtime, &block_106_spend);
    assert_eq!(
        legacy.state().names[name].status,
        NameStatus::BondSpent {
            terminal_height: 106
        }
    );

    let expiring_commitment = [0xaa; 32];
    let expiring_operation = Operation::Commit {
        commitment: expiring_commitment,
    };
    let expiring_input = candidate_transaction(legacy.deployment(), &expiring_operation, 7);
    let block_107 = block(&legacy, 107, vec![expiring_input]);
    apply_success(&mut legacy, &mut runtime, &block_107);
    assert!(legacy.state().pending.contains_key(&expiring_commitment));

    let mut canonical_suffix = vec![block_106_spend.clone(), block_107.clone()];
    for height in 108..=226 {
        let input = block(&legacy, height, vec![]);
        apply_success(&mut legacy, &mut runtime, &input);
        canonical_suffix.push(input);
    }
    assert!(!legacy.state().pending.contains_key(&expiring_commitment));
    assert!(!legacy.state().recent_spent.contains_key(&bond_tag));

    let (mut fresh_legacy, mut fresh_runtime) = replay_pair();
    for input in [
        &block_100, &block_101, &block_102, &block_103, &block_104, &block_105,
    ] {
        apply_success(&mut fresh_legacy, &mut fresh_runtime, input);
    }
    for input in &canonical_suffix {
        apply_success(&mut fresh_legacy, &mut fresh_runtime, input);
    }
    assert_eq!(legacy.state(), fresh_legacy.state());
    assert_eq!(legacy.state_root, fresh_legacy.state_root);
    assert_eq!(runtime.names().state(), fresh_runtime.names().state());
    assert_eq!(
        runtime.names().state_root(),
        fresh_runtime.names().state_root()
    );
    assert_eq!(runtime.core().tip(), fresh_runtime.core().tip());
}

#[test]
fn fatal_block_failure_is_atomic_across_core_and_names() {
    let (mut legacy, mut runtime) = replay_pair();
    let operation = Operation::Commit {
        commitment: [0xbb; 32],
    };
    let valid = candidate_transaction(legacy.deployment(), &operation, 1);
    let missing = CanonicalTxInput {
        tx_index: 2,
        txid: [0; 32],
        ironwood_nullifiers: vec![],
        ironwood_commitments: vec![],
        full_tx_required: true,
        candidate_full_tx: None,
    };
    let input = block(&legacy, 100, vec![valid, missing.clone()]);
    let legacy_before = legacy_full_observation_for_names(&legacy);
    let runtime_tip_before = runtime.core().tip();
    let runtime_state_before = runtime.names().state().clone();
    let runtime_root_before = runtime.names().state_root();
    assert_eq!(
        legacy.apply_block(&input),
        Err(FatalReducerError::RequiredFullTransactionMissing)
    );
    assert_eq!(
        runtime.apply_block(&input),
        Err(NamesRuntimeError::Core(
            coppice_core::replay::CoreReplayError::RequiredFullTransactionMissing
        ))
    );
    assert_eq!(legacy_full_observation_for_names(&legacy), legacy_before);
    assert_eq!(runtime.core().tip(), runtime_tip_before);
    assert_eq!(runtime.names().state(), &runtime_state_before);
    assert_eq!(runtime.names().state_root(), runtime_root_before);

    let noncanonical = block(
        &legacy,
        100,
        vec![
            missing,
            candidate_transaction(legacy.deployment(), &operation, 1),
        ],
    );
    assert_eq!(
        runtime.apply_block(&noncanonical),
        Err(NamesRuntimeError::Core(
            coppice_core::replay::CoreReplayError::NonCanonicalTxOrder
        ))
    );
}

fn legacy_full_observation_for_names(
    reducer: &Reducer,
) -> (CoppiceState, ReplayTip, [u8; 32], IronwoodFrontier, usize) {
    (
        reducer.state.clone(),
        reducer.tip,
        reducer.state_root,
        reducer.ironwood_tree.clone(),
        reducer.history.len(),
    )
}

#[test]
fn names_application_identity_and_retention_are_explicit_runtime_requirements() {
    let deployment = deployment();
    let checkpoint = ActivationCheckpoint {
        height: ACTIVATION_HEIGHT - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    };
    let core = CoreReplay::new(
        CoreReplayConfiguration::new(
            ACTIVATION_HEIGHT,
            required_reorg_retention_blocks(&deployment).unwrap() + 1,
        )
        .unwrap(),
        checkpoint,
    )
    .unwrap();
    let core = coppice_core::runtime::CoreRuntime::new(
        crate::names_application::names_v1_core_runtime_parameters(&deployment).unwrap(),
        core,
    )
    .unwrap();
    assert!(matches!(
        NamesRuntime::new(core, deployment),
        Err(crate::names_runtime::NamesRuntimeInitializationError::CoreRetentionMismatch)
    ));

    let (_, runtime) = replay_pair();
    assert_eq!(
        runtime.names().descriptor(),
        crate::names_application::names_v1_application_descriptor(ACTIVATION_HEIGHT)
    );
}
