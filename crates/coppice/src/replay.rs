use crate::{
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
    pub rendezvous: crate::config::Rendezvous,
    accepted_bond_anchors: BTreeSet<[u8; 32]>,
}
#[derive(Clone, Debug)]
pub struct ChainContext {
    pub height: u32,
    pub fixture_block_id: [u8; 32],
}
impl ReplayState {
    pub fn new() -> Self {
        Self {
            names: CoppiceState::default(),
            spent: SpentTagTree::default(),
            rendezvous: crate::config::TESTNET_V0.rendezvous,
            accepted_bond_anchors: BTreeSet::new(),
        }
    }
    pub fn set_rendezvous(&mut self, rendezvous: crate::config::Rendezvous) {
        self.rendezvous = rendezvous;
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
    match crate::carrier::decode_bulletin_for(tx, s.rendezvous) {
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
