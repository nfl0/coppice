use coppice::{
    carrier_v1::reconstruct_frames_v1,
    config::{DeploymentParameters, REGTEST_V0},
    envelope::decode_operation,
    reducer::{
        ActivationCheckpoint, CanonicalBlockInput, CanonicalTxInput, IronwoodFrontier, V1Reducer,
    },
};
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

/// Deterministic fuzz regression for the two hostile byte-oriented protocol
/// boundaries. Any generated input may be rejected, but parsing must remain
/// total and panic-free.
#[test]
fn arbitrary_operation_and_indexed_frame_bytes_are_panic_free() {
    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    for iteration in 0..10_000usize {
        let mut operation = vec![0; iteration % 9_000];
        rng.fill_bytes(&mut operation);
        let _ = decode_operation(&operation);

        let frame_count = iteration % 34;
        let mut frames = vec![[0u8; 512]; frame_count];
        for frame in &mut frames {
            rng.fill_bytes(frame);
        }
        let _ = reconstruct_frames_v1(&frames, [0x42; 32]);
    }
}

fn reducer() -> V1Reducer {
    let deployment = DeploymentParameters {
        network_id: REGTEST_V0.network_id.to_vec(),
        address_network: zcash_protocol::consensus::NetworkType::Regtest,
        activation_height: REGTEST_V0.activation_height,
        minimum_bond_value: REGTEST_V0.minimum_bond_value,
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: REGTEST_V0.rendezvous,
    };
    V1Reducer::new(
        deployment,
        ActivationCheckpoint {
            height: REGTEST_V0.activation_height - 1,
            block_hash: [0x99; 32],
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .unwrap()
}

fn apply_generated(reducer: &mut V1Reducer, hash: [u8; 32], append: bool) {
    let height = reducer.tip().height + 1;
    reducer
        .apply_block(&CanonicalBlockInput {
            height,
            block_hash: hash,
            prev_block_hash: reducer.tip().block_hash,
            branch_id: zcash_protocol::consensus::BranchId::Nu6_3,
            transactions: append
                .then(|| CanonicalTxInput {
                    tx_index: 0,
                    txid: [0; 32],
                    ironwood_nullifiers: vec![],
                    ironwood_commitments: vec![MerkleHashOrchard::empty_leaf().to_bytes()],
                    full_tx_required: false,
                    candidate_full_tx: None,
                })
                .into_iter()
                .collect(),
        })
        .unwrap();
}

/// Deterministic replay property over the persisted delta undo journal: a
/// retained rewind followed by replacement replay converges to a fresh direct
/// replay of the same canonical branch, including tree and checkpoints.
#[test]
fn persisted_delta_reorgs_equal_fresh_replay() {
    for seed in 0u8..8 {
        let mut local = reducer();
        let mut prefix = vec![];
        for index in 0u8..80 {
            let hash = [seed.wrapping_mul(17).wrapping_add(index); 32];
            let append = index % 5 == 0;
            apply_generated(&mut local, hash, append);
            prefix.push((hash, append));
        }
        local =
            V1Reducer::load_snapshot(local.deployment().clone(), &local.save_snapshot().unwrap())
                .unwrap();

        let rewind_count = 1 + usize::from(seed % 31);
        let common_len = prefix.len() - rewind_count;
        let common_height = (REGTEST_V0.activation_height - 1) + common_len as u32;
        local.rewind_to(common_height).unwrap();

        let mut fresh = reducer();
        for (hash, append) in &prefix[..common_len] {
            apply_generated(&mut fresh, *hash, *append);
        }
        for index in 0..(rewind_count + 7) {
            let hash = [0x80u8.wrapping_add(seed).wrapping_add(index as u8); 32];
            let append = index % 3 == 0;
            apply_generated(&mut local, hash, append);
            apply_generated(&mut fresh, hash, append);
        }

        let restored =
            V1Reducer::load_snapshot(local.deployment().clone(), &local.save_snapshot().unwrap())
                .unwrap();
        assert_eq!(restored.tip(), fresh.tip());
        assert_eq!(restored.state(), fresh.state());
        assert_eq!(restored.ironwood_frontier(), fresh.ironwood_frontier());
        assert_eq!(
            restored.ironwood_checkpoints(),
            fresh.ironwood_checkpoints()
        );
    }
}
