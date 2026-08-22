use crate::{
    constants,
    envelope::{self, Operation},
    name_tree, owner,
    replay::{ChainContext, ReplayState},
    spent::{SpentTagTree, bond_tag_domain_field, domain_field, native_hash, spent_tag},
    state::{NameRecord, Status},
};
use orchard::primitives::redpallas::SigningKey;
use pasta_curves::group::ff::PrimeField;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Vectors {
    canonical_name: String,
    name_id: String,
    owner_verification_key: String,
    name_record: String,
    name_record_hash: String,
    registration_commitment: String,
    commit: String,
    reveal: String,
    update: String,
    release: String,
    update_signing_preimage: String,
    update_signing_hash: String,
    release_signing_preimage: String,
    release_signing_hash: String,
    transfer_with_new_bond: String,
    transfer_signing_preimage: String,
    transfer_signing_hash: String,
    single_frame: String,
    multi_frames: Vec<String>,
    ironwood_nullifier: String,
    spent_tag: String,
    bond_tag_domain_field: String,
    bond_protocol_binding: String,
    bond_registration_context: String,
    name_membership_proof: String,
    name_nonmembership_proof: String,
    name_tree_root: String,
    spent_membership_proof: String,
    spent_nonmembership_proof: String,
    spent_tree_root: String,
    coppice_state_root: String,
}
fn proof_hex(v: &[[u8; 32]]) -> String {
    hex::encode(v.concat())
}
pub fn generate(real_nf: [u8; 32]) -> String {
    let key = SigningKey::try_from([1; 32]).expect("fixed valid key");
    let owner_pk = owner::owner_key_bytes(&(&key).into());
    let tag = spent_tag(&real_nf).expect("canonical real nullifier");
    let bob_tag = spent_tag(&[9; 32]).expect("canonical fixture nullifier");
    let old = NameRecord {
        owner_pk,
        bond_tag: tag,
        sequence: 0,
        address: b"UA_A".to_vec(),
        status: Status::Active,
    };
    let secret = [7; 32];
    let commitment =
        crate::state::registration_commitment("alice", owner_pk, tag, [0; 32], b"UA_A", secret);
    let commit = Operation::Commit { commitment };
    let reveal = Operation::Reveal {
        name: "alice".into(),
        owner_pk,
        bond_tag: tag,
        bond_anchor: [0; 32],
        bond_proof: Vec::new(),
        address: b"UA_A".to_vec(),
        secret,
    };
    let mut update = Operation::Update {
        name: "alice".into(),
        sequence: 1,
        address: b"UA_B".to_vec(),
        signature: vec![],
    };
    let up = owner::authorization_message(&update, &old).expect("update message");
    let usig = key.sign(ChaCha20Rng::from_seed([11; 32]), &up);
    if let Operation::Update { signature, .. } = &mut update {
        *signature = <[u8; 64]>::from(&usig).to_vec();
    }
    let updated = NameRecord {
        owner_pk,
        bond_tag: tag,
        sequence: 1,
        address: b"UA_B".to_vec(),
        status: Status::Active,
    };
    let mut release = Operation::Release {
        name: "alice".into(),
        sequence: 2,
        signature: vec![],
    };
    let rp = owner::authorization_message(&release, &updated).expect("release message");
    let rsig = key.sign(ChaCha20Rng::from_seed([12; 32]), &rp);
    if let Operation::Release { signature, .. } = &mut release {
        *signature = <[u8; 64]>::from(&rsig).to_vec();
    }
    let new_key = SigningKey::try_from([2; 32]).expect("fixed valid key");
    let mut transfer = Operation::TransferWithNewBond {
        name: "alice".into(),
        sequence: 1,
        new_owner_pk: owner::owner_key_bytes(&(&new_key).into()),
        new_bond_tag: bob_tag,
        new_bond_anchor: [3; 32],
        new_bond_proof: Vec::new(),
        address: b"UA_T".to_vec(),
        signature: Vec::new(),
    };
    let tp = owner::authorization_message(&transfer, &old).expect("transfer message");
    let tsig = key.sign(ChaCha20Rng::from_seed([13; 32]), &tp);
    if let Operation::TransferWithNewBond { signature, .. } = &mut transfer {
        *signature = <[u8; 64]>::from(&tsig).to_vec();
    }
    let released = NameRecord {
        owner_pk,
        bond_tag: tag,
        sequence: 2,
        address: b"UA_B".to_vec(),
        status: Status::Released,
    };
    let bob = NameRecord {
        owner_pk,
        bond_tag: bob_tag,
        sequence: 0,
        address: b"UA_C".to_vec(),
        status: Status::Active,
    };
    let mut names = BTreeMap::new();
    names.insert("alice".into(), released);
    names.insert("bob".into(), bob);
    let name_root = name_tree::root(&names);
    let mp = name_tree::prove(&names, "bob");
    let np = name_tree::prove(&names, "charlie");
    let mut spent = SpentTagTree::default();
    let absent = spent.prove_unspent(tag);
    spent.insert_spent_tag(tag);
    let present = spent.prove_spent(tag);
    let mut replay = ReplayState::new();
    replay.names.names = names.clone();
    replay.spent = spent.clone();
    let context = ChainContext {
        height: 105,
        fixture_block_id: Sha256::digest(b"CoppiceFixtureChainV0").into(),
    };
    let com = envelope::encode_operation(&commit).expect("commit");
    let rev = envelope::encode_operation(&reveal).expect("reveal");
    let upd = envelope::encode_operation(&update).expect("update");
    let rel = envelope::encode_operation(&release).expect("release");
    let trn = envelope::encode_operation(&transfer).expect("transfer");
    let sf = envelope::frames(&rev, 7, 400).expect("single");
    let mf = envelope::frames(&vec![0x55; 900], 9, 400).expect("multi");
    let v = Vectors {
        canonical_name: hex::encode("alice"),
        name_id: hex::encode(owner::name_id("alice")),
        owner_verification_key: hex::encode(owner_pk),
        name_record: hex::encode(owner::canonical_record_bytes(&old)),
        name_record_hash: hex::encode(owner::record_hash(&old)),
        registration_commitment: hex::encode(commitment),
        commit: hex::encode(com),
        reveal: hex::encode(rev),
        update: hex::encode(upd),
        release: hex::encode(rel),
        update_signing_preimage: hex::encode(&up),
        update_signing_hash: hex::encode(Sha256::digest(&up)),
        release_signing_preimage: hex::encode(&rp),
        release_signing_hash: hex::encode(Sha256::digest(&rp)),
        transfer_with_new_bond: hex::encode(trn),
        transfer_signing_preimage: hex::encode(&tp),
        transfer_signing_hash: hex::encode(Sha256::digest(&tp)),
        single_frame: hex::encode(&sf[0]),
        multi_frames: mf.iter().map(hex::encode).collect(),
        ironwood_nullifier: hex::encode(real_nf),
        spent_tag: hex::encode(tag),
        bond_tag_domain_field: hex::encode(bond_tag_domain_field().to_repr()),
        bond_protocol_binding: hex::encode(
            native_hash(
                constants::BOND_PROTOCOL_DOMAIN,
                domain_field(constants::NETWORK_ID).expect("network field"),
            )
            .expect("protocol hash")
            .to_repr(),
        ),
        bond_registration_context: hex::encode(
            crate::bond::context_binding("alice", b"UA_A").to_repr(),
        ),
        name_membership_proof: proof_hex(&mp.siblings),
        name_nonmembership_proof: proof_hex(&np.siblings),
        name_tree_root: hex::encode(name_root),
        spent_membership_proof: proof_hex(&present.siblings),
        spent_nonmembership_proof: proof_hex(&absent.siblings),
        spent_tree_root: hex::encode(spent.root()),
        coppice_state_root: hex::encode(replay.state_commitment(&context)),
    };
    serde_json::to_string_pretty(&v).expect("vector serialization") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vectors_regenerate_byte_for_byte() {
        let expected = include_str!("../../../test-vectors/reference-v0.json");
        let value: serde_json::Value = serde_json::from_str(expected).unwrap();
        let nf = hex::decode(value["ironwood_nullifier"].as_str().unwrap()).unwrap();
        let nf: [u8; 32] = nf.try_into().unwrap();
        assert_eq!(generate(nf), expected);
    }
}
