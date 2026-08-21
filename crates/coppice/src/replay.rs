use crate::{
    DEFAULT_TAG_BITS,
    envelope::Operation,
    ironwood::{self, IronwoodEffects},
    spent::SpentTagTree,
    state::{
        ChainPosition, CoppiceState, Transition, TransitionRejectReason, apply_operation_with_spent,
    },
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    MalformedCarrier,
    MalformedNullifier,
    UnknownBondAnchor,
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
#[derive(Clone, Default)]
pub struct ReplayState {
    pub names: CoppiceState,
    pub spent: SpentTagTree,
    pub tag_bits: u8,
    accepted_bond_anchors: BTreeSet<[u8; 32]>,
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
            accepted_bond_anchors: BTreeSet::new(),
        }
    }
    /// Records an Ironwood root independently derived from authenticated chain
    /// history. REGISTER proofs are accepted only against roots in this set.
    pub fn accept_bond_anchor(&mut self, anchor: [u8; 32]) {
        self.accepted_bond_anchors.insert(anchor);
    }
    pub fn accepted_bond_anchors(&self) -> &BTreeSet<[u8; 32]> {
        &self.accepted_bond_anchors
    }
    pub fn state_commitment(&self, c: &ChainContext) -> [u8; 32] {
        let mut b = crate::constants::STATE_ROOT_DOMAIN.to_vec();
        b.extend_from_slice(crate::constants::NETWORK_ID);
        b.extend_from_slice(&c.height.to_be_bytes());
        b.extend_from_slice(&c.fixture_block_id);
        b.extend_from_slice(&self.names.state_root());
        b.extend_from_slice(&self.names.commitment_root());
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
    let mut next_spent = s.spent.clone();
    for nf in &effects.nullifiers {
        if next_spent.insert_nullifier(*nf).is_err() {
            return ReplayResult {
                effects,
                spent_root_before_operation: s.spent.root(),
                operation: None,
                transition: None,
                outcome: ReplayOutcome::Rejected(ReplayRejectReason::MalformedNullifier),
            };
        }
    }
    s.spent = next_spent;
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
            let bond_anchor = match &op {
                Operation::Reveal { bond_anchor, .. } => Some(bond_anchor),
                Operation::TransferWithNewBond {
                    new_bond_anchor, ..
                } => Some(new_bond_anchor),
                _ => None,
            };
            if bond_anchor.is_some_and(|anchor| !s.accepted_bond_anchors.contains(anchor)) {
                return ReplayResult {
                    effects,
                    spent_root_before_operation,
                    operation: Some(op),
                    transition: None,
                    outcome: ReplayOutcome::Rejected(ReplayRejectReason::UnknownBondAnchor),
                };
            }
            let t = apply_operation_with_spent(
                &mut s.names,
                Some(&s.spent),
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
        Err(crate::carrier::Error::NotFound) => ReplayResult {
            effects,
            spent_root_before_operation,
            operation: None,
            transition: None,
            outcome: ReplayOutcome::CandidateNoOperation,
        },
        Err(_) => ReplayResult {
            effects,
            spent_root_before_operation,
            operation: None,
            transition: None,
            outcome: ReplayOutcome::Rejected(ReplayRejectReason::MalformedCarrier),
        },
    }
}

pub fn process_serialized_transaction(
    s: &mut ReplayState,
    height: u32,
    tx_index: u32,
    bytes: &[u8],
) -> Result<ReplayResult, SerializedReplayError> {
    if bytes.len() > crate::constants::MAX_TRANSACTION_BYTES {
        return Err(SerializedReplayError::InvalidTransaction);
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let tx = Transaction::read(&mut cursor, BranchId::Nu6_3)
        .map_err(|_| SerializedReplayError::InvalidTransaction)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(SerializedReplayError::InvalidTransaction);
    }
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
        let op = Operation::Commit {
            commitment: [3; 32],
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
        let alice_bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let bob_bond = crate::bond::test_registration_bond("bob", b"UA_C");
        let secret = [7; 32];
        let commitment = crate::state::registration_commitment(
            "alice",
            owner,
            alice_bond.bond_tag,
            alice_bond.anchor,
            b"UA_A",
            secret,
        );
        let reveal = Operation::Reveal {
            name: "alice".into(),
            owner_pk: owner,
            bond_tag: alice_bond.bond_tag,
            bond_anchor: alice_bond.anchor,
            bond_proof: alice_bond.proof.clone(),
            address: b"UA_A".to_vec(),
            secret,
        };
        let mut invalid_proof = reveal.clone();
        if let Operation::Reveal { bond_proof, .. } = &mut invalid_proof {
            bond_proof[0] ^= 1;
        }
        let mut mismatched_tag = reveal.clone();
        if let Operation::Reveal { bond_tag, .. } = &mut mismatched_tag {
            use pasta_curves::{group::ff::PrimeField, pallas};
            let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(*bond_tag)).unwrap();
            *bond_tag = (tag + pallas::Base::one()).to_repr();
        }
        let mismatched_commitment = if let Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            bond_anchor,
            address,
            secret,
            ..
        } = &mismatched_tag
        {
            crate::state::registration_commitment(
                name,
                *owner_pk,
                *bond_tag,
                *bond_anchor,
                address,
                *secret,
            )
        } else {
            unreachable!()
        };
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
        let bob_secret = [8; 32];
        let bob_commitment = crate::state::registration_commitment(
            "bob",
            owner,
            bob_bond.bond_tag,
            bob_bond.anchor,
            b"UA_C",
            bob_secret,
        );
        let bob = Operation::Reveal {
            name: "bob".into(),
            owner_pk: owner,
            bond_tag: bob_bond.bond_tag,
            bond_anchor: bob_bond.anchor,
            bond_proof: bob_bond.proof.clone(),
            address: b"UA_C".to_vec(),
            secret: bob_secret,
        };
        let txs = [
            carrier::build_coppice_transaction(&Operation::Commit { commitment }, 6).unwrap(),
            carrier::build_coppice_transaction(&invalid_proof, 6).unwrap(),
            carrier::build_coppice_transaction(
                &Operation::Commit {
                    commitment: mismatched_commitment,
                },
                6,
            )
            .unwrap(),
            carrier::build_coppice_transaction(&mismatched_tag, 6).unwrap(),
            carrier::build_coppice_transaction(&reveal, 6).unwrap(),
            carrier::build_coppice_transaction(&update, 6).unwrap(),
            carrier::build_coppice_payload(&[0xff], 6).unwrap(),
            carrier::build_coppice_transaction(
                &Operation::Commit {
                    commitment: bob_commitment,
                },
                6,
            )
            .unwrap(),
            carrier::build_coppice_transaction(&bob, 6).unwrap(),
            carrier::build_coppice_transaction(&release, 6).unwrap(),
        ];
        let bytes = txs.iter().map(|x| serialized(&x.tx)).collect::<Vec<_>>();
        let mut strict = ReplayState::new(6);
        let empty_root = strict.names.state_root();
        assert_eq!(
            process_serialized_transaction(&mut strict, 99, 0, &bytes[4])
                .unwrap()
                .outcome,
            ReplayOutcome::Rejected(ReplayRejectReason::UnknownBondAnchor)
        );
        assert_eq!(strict.names.state_root(), empty_root);
        let mut trailing = bytes[1].clone();
        trailing.push(0);
        assert!(matches!(
            process_serialized_transaction(&mut ReplayState::new(6), 99, 0, &trailing),
            Err(SerializedReplayError::InvalidTransaction)
        ));
        let run = || {
            let mut s = ReplayState::new(6);
            s.accept_bond_anchor(alice_bond.anchor);
            s.accept_bond_anchor(bob_bond.anchor);
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
            oa[1],
            ReplayOutcome::Rejected(ReplayRejectReason::InvalidOperation(
                TransitionRejectReason::InvalidBondProof
            ))
        );
        assert_eq!(
            oa[3],
            ReplayOutcome::Rejected(ReplayRejectReason::InvalidOperation(
                TransitionRejectReason::InvalidBondProof
            ))
        );
        assert!(matches!(oa[4], ReplayOutcome::Applied(_)));
        assert!(matches!(
            oa[6],
            ReplayOutcome::Rejected(ReplayRejectReason::MalformedCarrier)
        ));
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
