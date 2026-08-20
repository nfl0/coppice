use crate::{
    DEFAULT_TAG_BITS,
    envelope::Operation,
    ironwood::{self, IronwoodEffects},
    spent::SpentTagTree,
    state::{ChainPosition, CoppiceState, Transition, TransitionRejectReason, apply_operation},
};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOutcome {
    NotCandidate,
    CandidateNoOperation,
    Applied(Operation),
    Rejected(ReplayRejectReason),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayRejectReason {
    InvalidOperation(TransitionRejectReason),
    MalformedNullifier,
}
#[derive(Clone, Debug)]
pub struct ReplayResult {
    pub effects: IronwoodEffects,
    /// Root after Ironwood effects and before any Coppice transition in this transaction.
    pub spent_root_before_operation: [u8; 32],
    pub operation: Option<Operation>,
    pub transition: Option<Transition>,
    pub outcome: ReplayOutcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializedReplayError {
    InvalidTransaction,
}
#[derive(Default)]
pub struct ReplayState {
    pub names: CoppiceState,
    pub spent: SpentTagTree,
    pub tag_bits: u8,
}
#[derive(Clone, Debug)]
pub struct ChainContext {
    pub height: u32,
    pub fixture_block_id: [u8; 32],
}
impl ReplayState {
    pub fn new(tag_bits: u8) -> Self {
        Self {
            names: CoppiceState::default(),
            spent: SpentTagTree::default(),
            tag_bits,
        }
    }
    pub fn state_commitment(&self, c: &ChainContext) -> [u8; 32] {
        let mut b = crate::constants::STATE_ROOT_DOMAIN.to_vec();
        b.extend_from_slice(crate::constants::POC_NETWORK_ID);
        b.extend_from_slice(&c.height.to_be_bytes());
        b.extend_from_slice(&c.fixture_block_id);
        b.extend_from_slice(&self.names.state_root());
        b.extend_from_slice(&self.spent.root());
        Sha256::digest(b).into()
    }
}
/// Effects are inserted before the same transaction's Coppice operation is interpreted.
pub fn process_transaction(
    s: &mut ReplayState,
    height: u32,
    tx_index: u32,
    tx: &Transaction,
) -> ReplayResult {
    let effects = ironwood::extract_ironwood_effects(tx);
    for nf in &effects.nullifiers {
        if s.spent.insert_nullifier(*nf).is_err() {
            return ReplayResult {
                effects,
                spent_root_before_operation: s.spent.root(),
                operation: None,
                transition: None,
                outcome: ReplayOutcome::Rejected(ReplayRejectReason::MalformedNullifier),
            };
        }
    }
    let spent_root_before_operation = s.spent.root();
    let bits = if s.tag_bits == 0 {
        DEFAULT_TAG_BITS as u8
    } else {
        s.tag_bits
    };
    if !crate::is_coppice_candidate(&tx.txid(), bits) {
        return ReplayResult {
            effects,
            spent_root_before_operation,
            operation: None,
            transition: None,
            outcome: ReplayOutcome::NotCandidate,
        };
    }
    match crate::carrier::decode_bulletin(tx) {
        Ok(op) => {
            let t = apply_operation(
                &mut s.names,
                op.clone(),
                ChainPosition {
                    block_height: height,
                    tx_index,
                },
            );
            let outcome = match &t {
                Transition::Applied => ReplayOutcome::Applied(op.clone()),
                Transition::Rejected(r) => {
                    ReplayOutcome::Rejected(ReplayRejectReason::InvalidOperation(*r))
                }
            };
            ReplayResult {
                effects,
                spent_root_before_operation,
                operation: Some(op),
                transition: Some(t),
                outcome,
            }
        }
        Err(_) => ReplayResult {
            effects,
            spent_root_before_operation,
            operation: None,
            transition: None,
            outcome: ReplayOutcome::CandidateNoOperation,
        },
    }
}

pub fn process_serialized_transaction(
    s: &mut ReplayState,
    height: u32,
    tx_index: u32,
    bytes: &[u8],
) -> Result<ReplayResult, SerializedReplayError> {
    let tx = Transaction::read(bytes, BranchId::Nu6_3)
        .map_err(|_| SerializedReplayError::InvalidTransaction)?;
    Ok(process_transaction(s, height, tx_index, &tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        carrier,
        envelope::Operation,
        spent::{SpentTagTree, spent_tag},
    };
    #[test]
    fn real_note_spend_updates_spent_tag_tree() {
        let op = Operation::Register {
            name: "bond-note".into(),
            owner_pk: [3; 32],
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA_BOND".to_vec(),
        };
        let built = carrier::build_coppice_transaction(&op, 8).unwrap();
        let tag = spent_tag(&built.input_nullifier).unwrap();
        let mut state = ReplayState::new(8);
        let before = state.spent.prove_unspent(tag);
        assert!(SpentTagTree::verify_unspent(
            state.spent.root(),
            tag,
            &before
        ));
        let result = process_transaction(&mut state, 100, 0, &built.tx);
        assert_eq!(result.spent_root_before_operation, state.spent.root());
        assert!(result.effects.nullifiers.contains(&built.input_nullifier));
        let after = state.spent.prove_spent(tag);
        assert!(SpentTagTree::verify_spent(state.spent.root(), tag, &after));
    }

    fn serialized(tx: &Transaction) -> Vec<u8> {
        let mut b = Vec::new();
        tx.write(&mut b).unwrap();
        b
    }

    #[test]
    fn canonical_serialized_fixture_is_deterministic() {
        use crate::{
            owner::{OwnerSigningKey, owner_key_bytes, sign_operation},
            state::{NameRecord, Status},
        };
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner = owner_key_bytes(&(&key).into());
        let alice_bond = crate::bond::test_registration_bond("alice");
        let bob_bond = crate::bond::test_registration_bond("bob");
        let register = Operation::Register {
            name: "alice".into(),
            owner_pk: owner,
            bond_tag: alice_bond.bond_tag,
            bond_anchor: alice_bond.anchor,
            bond_proof: alice_bond.proof.clone(),
            address: b"UA_A".to_vec(),
        };
        let mut invalid_proof = register.clone();
        if let Operation::Register { bond_proof, .. } = &mut invalid_proof {
            bond_proof[0] ^= 1;
        }
        let mut mismatched_tag = register.clone();
        if let Operation::Register { bond_tag, .. } = &mut mismatched_tag {
            use pasta_curves::{group::ff::PrimeField, pallas};
            let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(*bond_tag)).unwrap();
            *bond_tag = (tag + pallas::Base::one()).to_repr();
        }
        let old = NameRecord {
            owner_pk: owner,
            bond_tag: alice_bond.bond_tag,
            sequence: 0,
            address: b"UA_A".to_vec(),
            status: Status::Active,
        };
        let mut update = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA_B".to_vec(),
            signature: vec![],
        };
        let update_sig = sign_operation(&key, &update, &old).unwrap();
        if let Operation::Update { signature, .. } = &mut update {
            *signature = update_sig;
        }
        let updated = NameRecord {
            owner_pk: owner,
            bond_tag: alice_bond.bond_tag,
            sequence: 1,
            address: b"UA_B".to_vec(),
            status: Status::Active,
        };
        let mut release = Operation::Release {
            name: "alice".into(),
            sequence: 2,
            signature: vec![],
        };
        let release_sig = sign_operation(&key, &release, &updated).unwrap();
        if let Operation::Release { signature, .. } = &mut release {
            *signature = release_sig;
        }
        let bob = Operation::Register {
            name: "bob".into(),
            owner_pk: owner,
            bond_tag: bob_bond.bond_tag,
            bond_anchor: bob_bond.anchor,
            bond_proof: bob_bond.proof.clone(),
            address: b"UA_C".to_vec(),
        };
        let txs = [
            carrier::build_coppice_transaction(&invalid_proof, 6).unwrap(),
            carrier::build_coppice_transaction(&mismatched_tag, 6).unwrap(),
            carrier::build_coppice_transaction(&register, 6).unwrap(),
            carrier::build_coppice_transaction(&update, 6).unwrap(),
            carrier::build_coppice_payload(&[0xff], 6).unwrap(),
            carrier::build_coppice_transaction(&bob, 6).unwrap(),
            carrier::build_coppice_transaction(&release, 6).unwrap(),
        ];
        let bytes = txs.iter().map(|x| serialized(&x.tx)).collect::<Vec<_>>();
        let run = || {
            let mut s = ReplayState::new(6);
            let outcomes = bytes
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    process_serialized_transaction(&mut s, 100 + i as u32, 0, b)
                        .unwrap()
                        .outcome
                })
                .collect::<Vec<_>>();
            (s, outcomes)
        };
        let (a, oa) = run();
        let (b, ob) = run();
        let (c, oc) = run();
        assert_eq!(oa, ob);
        assert_eq!(ob, oc);
        assert_eq!(
            oa[0],
            ReplayOutcome::Rejected(ReplayRejectReason::InvalidOperation(
                TransitionRejectReason::InvalidBondProof
            ))
        );
        assert_eq!(
            oa[1],
            ReplayOutcome::Rejected(ReplayRejectReason::InvalidOperation(
                TransitionRejectReason::InvalidBondProof
            ))
        );
        assert!(matches!(oa[2], ReplayOutcome::Applied(_)));
        assert!(matches!(oa[4], ReplayOutcome::CandidateNoOperation));
        assert_eq!(a.names.state_root(), b.names.state_root());
        assert_eq!(b.names.state_root(), c.names.state_root());
        assert_eq!(a.spent.root(), b.spent.root());
        assert_eq!(b.spent.root(), c.spent.root());
        let ctx = ChainContext {
            height: 105,
            fixture_block_id: Sha256::digest(b"CoppiceFixtureChainV0").into(),
        };
        assert_eq!(a.state_commitment(&ctx), b.state_commitment(&ctx));
        assert_eq!(b.state_commitment(&ctx), c.state_commitment(&ctx));
        assert_eq!(a.names.names["alice"].status, Status::Released);
        assert_eq!(a.names.names["bob"].address, b"UA_C");
        assert!(!a.names.names.contains_key("charlie"));
    }
}
