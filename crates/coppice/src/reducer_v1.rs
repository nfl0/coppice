//! Forward-only canonical Coppice v1 block reduction.
//!
//! The host performs compact Ironwood trial decryption with
//! [`crate::carrier::compact_action_is_bulletin`] and sets `full_tx_required`.
//! This reducer never performs wallet discovery and never treats an unavailable
//! required full transaction as an empty candidate.

use crate::{
    authorization,
    bond::V1BondVerifier,
    bond_tag, carrier,
    config::{DeploymentParameters, DeploymentValidationError},
    constants::MAX_TRANSACTION_LEN,
    envelope::Operation,
    ironwood, pending,
    record::NameStatus,
    reveal::{self, AuthenticatedIronwoodCheckpoint, RevealValidationError},
    state::{CoppiceState, StateMutationError},
    state_root::{self, StateRootInput},
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use std::{collections::BTreeMap, io::Cursor};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

pub type IronwoodFrontier = CommitmentTree<MerkleHashOrchard, 32>;

#[derive(Clone, Debug)]
pub struct CanonicalBlockInput {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub branch_id: BranchId,
    pub transactions: Vec<CanonicalTxInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTxInput {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub ironwood_nullifiers: Vec<[u8; 32]>,
    pub ironwood_commitments: Vec<[u8; 32]>,
    pub full_tx_required: bool,
    pub candidate_full_tx: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationCheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub ironwood_frontier: IronwoodFrontier,
    pub ironwood_tree_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolRejection {
    InvalidName,
    InvalidAddress,
    InvalidOwnerKey,
    DuplicateCommitment,
    UnknownCommitment,
    CommitmentNotMature,
    CommitmentExpired,
    NameUnavailable,
    CommitPredatesClaimEpoch,
    InvalidSequence,
    InvalidSignature,
    BondAlreadyInUse,
    BondRecentlySpent,
    InvalidBondAnchorHeight,
    UnknownBondAnchor,
    InvalidBondProof,
    OversizedProof,
    MalformedCarrier,
    MalformedOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionOutcome {
    NoOperation,
    Applied,
    Rejected(ProtocolRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FatalReducerError {
    InvalidDeployment(DeploymentValidationError),
    InvalidActivationCheckpoint,
    NonSequentialHeight,
    PredecessorMismatch,
    NonCanonicalTxOrder,
    CandidateFlagMismatch,
    RequiredFullTransactionMissing,
    OversizedTransaction,
    InvalidFullTransaction,
    TxidMismatch,
    IronwoodEffectsMismatch,
    NonCanonicalNullifier,
    InvalidIronwoodCommitment,
    IronwoodAppendFailure,
    MissingRequiredCheckpoint,
    StateInvariantFailure,
    ArithmeticOverflow,
    VerifierInitializationFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedBlock {
    pub tip: ReplayTip,
    pub ironwood_checkpoint: AuthenticatedIronwoodCheckpoint,
    pub name_tree_root: [u8; 32],
    pub pending_root: [u8; 32],
    pub recent_spent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub transaction_outcomes: Vec<TransactionOutcome>,
}

pub struct V1Reducer {
    deployment: DeploymentParameters,
    deployment_id: [u8; 32],
    state: CoppiceState,
    ironwood_tree: IronwoodFrontier,
    ironwood_checkpoints: BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
    tip: ReplayTip,
    verifier: V1BondVerifier,
}

enum CarrierSemantic {
    NoOperation,
    Rejected(ProtocolRejection),
    Operation(Operation),
}

impl V1Reducer {
    pub fn new(
        deployment: DeploymentParameters,
        checkpoint: ActivationCheckpoint,
    ) -> Result<Self, FatalReducerError> {
        let deployment_id = deployment
            .validate()
            .map_err(FatalReducerError::InvalidDeployment)?;
        let expected_height = deployment
            .activation_height
            .checked_sub(1)
            .ok_or(FatalReducerError::ArithmeticOverflow)?;
        let actual_size = u32::try_from(checkpoint.ironwood_frontier.size())
            .map_err(|_| FatalReducerError::InvalidActivationCheckpoint)?;
        if checkpoint.height != expected_height || actual_size != checkpoint.ironwood_tree_size {
            return Err(FatalReducerError::InvalidActivationCheckpoint);
        }
        let root = checkpoint.ironwood_frontier.root().to_bytes();
        let authenticated = AuthenticatedIronwoodCheckpoint {
            height: checkpoint.height,
            root,
            tree_size: actual_size,
        };
        let mut ironwood_checkpoints = BTreeMap::new();
        ironwood_checkpoints.insert(checkpoint.height, authenticated);
        let verifier =
            V1BondVerifier::new().map_err(|_| FatalReducerError::VerifierInitializationFailure)?;
        Ok(Self {
            deployment,
            deployment_id,
            state: CoppiceState::default(),
            ironwood_tree: checkpoint.ironwood_frontier,
            ironwood_checkpoints,
            tip: ReplayTip {
                height: checkpoint.height,
                block_hash: checkpoint.block_hash,
            },
            verifier,
        })
    }

    pub fn deployment(&self) -> &DeploymentParameters {
        &self.deployment
    }

    pub fn deployment_id(&self) -> [u8; 32] {
        self.deployment_id
    }

    pub fn state(&self) -> &CoppiceState {
        &self.state
    }

    pub fn ironwood_frontier(&self) -> &IronwoodFrontier {
        &self.ironwood_tree
    }

    pub fn ironwood_checkpoints(&self) -> &BTreeMap<u32, AuthenticatedIronwoodCheckpoint> {
        &self.ironwood_checkpoints
    }

    pub fn tip(&self) -> ReplayTip {
        self.tip
    }

    pub fn apply_block(
        &mut self,
        block: &CanonicalBlockInput,
    ) -> Result<AppliedBlock, FatalReducerError> {
        let expected_height = self
            .tip
            .height
            .checked_add(1)
            .ok_or(FatalReducerError::ArithmeticOverflow)?;
        if block.height != expected_height {
            return Err(FatalReducerError::NonSequentialHeight);
        }
        if block.prev_block_hash != self.tip.block_hash {
            return Err(FatalReducerError::PredecessorMismatch);
        }
        if block
            .transactions
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        {
            return Err(FatalReducerError::NonCanonicalTxOrder);
        }

        let mut state = self.state.clone();
        let mut tree = self.ironwood_tree.clone();
        let mut checkpoints = self.ironwood_checkpoints.clone();
        let mut outcomes = Vec::with_capacity(block.transactions.len());

        for tx_input in &block.transactions {
            let parsed = Self::validate_candidate(block.branch_id, tx_input)?;
            for nullifier in &tx_input.ironwood_nullifiers {
                let tag = bond_tag::derive_v1_bond_tag(nullifier)
                    .map_err(|_| FatalReducerError::NonCanonicalNullifier)?;
                state
                    .process_prevalidated_bond_tag(tag, block.height)
                    .map_err(map_state_fatal)?;
            }
            for commitment in &tx_input.ironwood_commitments {
                let node =
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(commitment))
                        .ok_or(FatalReducerError::InvalidIronwoodCommitment)?;
                tree.append(node)
                    .map_err(|_| FatalReducerError::IronwoodAppendFailure)?;
            }
            let outcome = match parsed {
                None => TransactionOutcome::NoOperation,
                Some(tx) => match carrier_semantic(carrier::decode_v1_bulletin_for(
                    &tx,
                    self.deployment.rendezvous,
                    self.deployment_id,
                ))? {
                    CarrierSemantic::Operation(operation) => self.apply_operation(
                        &mut state,
                        &checkpoints,
                        block.height,
                        tx_input.tx_index,
                        &operation,
                    )?,
                    CarrierSemantic::NoOperation => TransactionOutcome::NoOperation,
                    CarrierSemantic::Rejected(rejection) => TransactionOutcome::Rejected(rejection),
                },
            };
            outcomes.push(outcome);
        }

        let tree_size =
            u32::try_from(tree.size()).map_err(|_| FatalReducerError::ArithmeticOverflow)?;
        let ironwood_checkpoint = AuthenticatedIronwoodCheckpoint {
            height: block.height,
            root: tree.root().to_bytes(),
            tree_size,
        };
        checkpoints.insert(block.height, ironwood_checkpoint);
        state
            .expire_pending_at_end_of_block(block.height, self.deployment.commit_ttl_blocks)
            .map_err(map_state_fatal)?;
        let (oldest_retained_height, _) = state
            .prune_recent_spent_at_end_of_block(
                self.deployment.activation_height,
                block.height,
                self.deployment.bond_note_max_age_blocks,
                self.deployment.commit_ttl_blocks,
            )
            .map_err(map_state_fatal)?;
        self.prune_checkpoints(block.height, &mut checkpoints)?;
        let name_tree_root = state
            .name_tree_root()
            .map_err(|_| FatalReducerError::StateInvariantFailure)?;
        let pending_root = state
            .pending_root()
            .map_err(|_| FatalReducerError::StateInvariantFailure)?;
        let recent_spent_root = state
            .recent_spent_root(oldest_retained_height)
            .map_err(|_| FatalReducerError::StateInvariantFailure)?;
        let final_root = state_root::state_root(&StateRootInput {
            deployment_id: self.deployment_id,
            height: block.height,
            block_hash: block.block_hash,
            ironwood_tree_size: tree_size,
            ironwood_root: ironwood_checkpoint.root,
            name_tree_root,
            pending_root,
            recent_spent_root,
        })
        .map_err(|_| FatalReducerError::StateInvariantFailure)?;
        let tip = ReplayTip {
            height: block.height,
            block_hash: block.block_hash,
        };

        self.state = state;
        self.ironwood_tree = tree;
        self.ironwood_checkpoints = checkpoints;
        self.tip = tip;
        Ok(AppliedBlock {
            tip,
            ironwood_checkpoint,
            name_tree_root,
            pending_root,
            recent_spent_root,
            state_root: final_root,
            transaction_outcomes: outcomes,
        })
    }

    fn validate_candidate(
        branch_id: BranchId,
        input: &CanonicalTxInput,
    ) -> Result<Option<Transaction>, FatalReducerError> {
        match (input.full_tx_required, input.candidate_full_tx.as_deref()) {
            (false, None) => Ok(None),
            (false, Some(_)) => Err(FatalReducerError::CandidateFlagMismatch),
            (true, None) => Err(FatalReducerError::RequiredFullTransactionMissing),
            (true, Some(bytes)) => {
                if bytes.len() > MAX_TRANSACTION_LEN {
                    return Err(FatalReducerError::OversizedTransaction);
                }
                let mut cursor = Cursor::new(bytes);
                let tx = Transaction::read(&mut cursor, branch_id)
                    .map_err(|_| FatalReducerError::InvalidFullTransaction)?;
                if cursor.position() != bytes.len() as u64 {
                    return Err(FatalReducerError::InvalidFullTransaction);
                }
                let txid: [u8; 32] = tx.txid().into();
                if txid != input.txid {
                    return Err(FatalReducerError::TxidMismatch);
                }
                let effects = ironwood::extract_ironwood_effects(&tx);
                if effects.nullifiers != input.ironwood_nullifiers
                    || effects.commitments != input.ironwood_commitments
                {
                    return Err(FatalReducerError::IronwoodEffectsMismatch);
                }
                Ok(Some(tx))
            }
        }
    }

    fn apply_operation(
        &self,
        state: &mut CoppiceState,
        checkpoints: &BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
        height: u32,
        tx_index: u32,
        operation: &Operation,
    ) -> Result<TransactionOutcome, FatalReducerError> {
        let rejection = match operation {
            Operation::Commit { commitment } => match state.apply_prevalidated_commit(
                *commitment,
                pending::ChainPosition {
                    block_height: height,
                    tx_index,
                },
            ) {
                Ok(()) => return Ok(TransactionOutcome::Applied),
                Err(StateMutationError::DuplicateCommitment) => {
                    ProtocolRejection::DuplicateCommitment
                }
                Err(error) => return Err(map_state_fatal(error)),
            },
            Operation::Reveal {
                name,
                owner_pk,
                bond_anchor_height,
                bond_proof,
                address,
                ..
            } => {
                if !crate::envelope::valid_name(name) {
                    return Ok(TransactionOutcome::Rejected(ProtocolRejection::InvalidName));
                }
                if crate::owner::parse_owner_key(*owner_pk).is_err() {
                    return Ok(TransactionOutcome::Rejected(
                        ProtocolRejection::InvalidOwnerKey,
                    ));
                }
                if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                    return Ok(TransactionOutcome::Rejected(
                        ProtocolRejection::InvalidAddress,
                    ));
                }
                if bond_proof.len() > reveal::MAX_BOND_PROOF_LEN {
                    return Ok(TransactionOutcome::Rejected(
                        ProtocolRejection::OversizedProof,
                    ));
                }
                let commitment = reveal_commitment(state, &self.deployment, operation)
                    .ok_or(FatalReducerError::StateInvariantFailure)?;
                let Some(committed_at) = state.pending.get(&commitment).copied() else {
                    return Ok(TransactionOutcome::Rejected(
                        ProtocolRejection::UnknownCommitment,
                    ));
                };
                if *bond_anchor_height < committed_at.block_height || *bond_anchor_height >= height
                {
                    return Ok(TransactionOutcome::Rejected(
                        ProtocolRejection::InvalidBondAnchorHeight,
                    ));
                }
                let anchor = checkpoints
                    .get(bond_anchor_height)
                    .copied()
                    .ok_or(FatalReducerError::MissingRequiredCheckpoint)?;
                let floor_height = (self.deployment.activation_height - 1).max(
                    committed_at
                        .block_height
                        .saturating_sub(self.deployment.bond_note_max_age_blocks),
                );
                let floor = checkpoints
                    .get(&floor_height)
                    .copied()
                    .ok_or(FatalReducerError::MissingRequiredCheckpoint)?;
                match reveal::validate_v1_reveal(
                    state,
                    &self.deployment,
                    height,
                    anchor,
                    floor,
                    &self.verifier,
                    operation,
                ) {
                    Ok(validated) => {
                        state
                            .apply_prevalidated_reveal(validated)
                            .map_err(map_state_fatal)?;
                        return Ok(TransactionOutcome::Applied);
                    }
                    Err(error) => map_reveal_rejection(error)?,
                }
            }
            Operation::Update {
                name,
                sequence,
                address,
                ..
            } => {
                if !crate::envelope::valid_name(name) {
                    ProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(TransactionOutcome::Rejected(
                            ProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        ProtocolRejection::NameUnavailable
                    } else if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                        ProtocolRejection::InvalidAddress
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        ProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(self.deployment_id, operation, current) {
                        ProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_update(name, *sequence, address.clone())
                            .map_err(map_state_fatal)?;
                        return Ok(TransactionOutcome::Applied);
                    }
                }
            }
            Operation::Release { name, sequence, .. } => {
                if !crate::envelope::valid_name(name) {
                    ProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(TransactionOutcome::Rejected(
                            ProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        ProtocolRejection::NameUnavailable
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        ProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(self.deployment_id, operation, current) {
                        ProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_release(name, *sequence, height)
                            .map_err(map_state_fatal)?;
                        return Ok(TransactionOutcome::Applied);
                    }
                }
            }
        };
        Ok(TransactionOutcome::Rejected(rejection))
    }

    fn prune_checkpoints(
        &self,
        height: u32,
        checkpoints: &mut BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
    ) -> Result<(), FatalReducerError> {
        let retention = self
            .deployment
            .bond_note_max_age_blocks
            .checked_add(self.deployment.commit_ttl_blocks)
            .and_then(|value| value.checked_add(1))
            .ok_or(FatalReducerError::ArithmeticOverflow)?;
        let next_height = height
            .checked_add(1)
            .ok_or(FatalReducerError::ArithmeticOverflow)?;
        let activation_checkpoint = self
            .deployment
            .activation_height
            .checked_sub(1)
            .ok_or(FatalReducerError::ArithmeticOverflow)?;
        let oldest = activation_checkpoint.max(next_height.saturating_sub(retention));
        checkpoints.retain(|checkpoint_height, _| *checkpoint_height >= oldest);
        Ok(())
    }
}

fn carrier_semantic(
    result: Result<Operation, carrier::V1CarrierError>,
) -> Result<CarrierSemantic, FatalReducerError> {
    match result {
        Ok(operation) => Ok(CarrierSemantic::Operation(operation)),
        Err(carrier::V1CarrierError::NotFound) => Ok(CarrierSemantic::NoOperation),
        Err(carrier::V1CarrierError::Malformed) => Ok(CarrierSemantic::Rejected(
            ProtocolRejection::MalformedCarrier,
        )),
        Err(carrier::V1CarrierError::Build) => Err(FatalReducerError::StateInvariantFailure),
    }
}

fn reveal_commitment(
    _state: &CoppiceState,
    deployment: &DeploymentParameters,
    operation: &Operation,
) -> Option<[u8; 32]> {
    let Operation::Reveal {
        name,
        owner_pk,
        bond_tag,
        address,
        secret,
        ..
    } = operation
    else {
        return None;
    };
    crate::registration::registration_commitment(
        deployment, name, *owner_pk, *bond_tag, address, *secret,
    )
    .ok()
}

fn map_state_fatal(_error: StateMutationError) -> FatalReducerError {
    FatalReducerError::StateInvariantFailure
}

fn map_reveal_rejection(
    error: RevealValidationError,
) -> Result<ProtocolRejection, FatalReducerError> {
    Ok(match error {
        RevealValidationError::InvalidName => ProtocolRejection::InvalidName,
        RevealValidationError::InvalidOwnerKey => ProtocolRejection::InvalidOwnerKey,
        RevealValidationError::InvalidAddress
        | RevealValidationError::WrongAddressNetwork
        | RevealValidationError::NonCanonicalAddress
        | RevealValidationError::AddressTooLong => ProtocolRejection::InvalidAddress,
        RevealValidationError::CommitmentNotPending => ProtocolRejection::UnknownCommitment,
        RevealValidationError::CommitmentNotMature => ProtocolRejection::CommitmentNotMature,
        RevealValidationError::CommitmentExpired => ProtocolRejection::CommitmentExpired,
        RevealValidationError::NameNotClaimable => ProtocolRejection::NameUnavailable,
        RevealValidationError::CommitPredatesClaimability => {
            ProtocolRejection::CommitPredatesClaimEpoch
        }
        RevealValidationError::BondAlreadySpent => ProtocolRejection::BondRecentlySpent,
        RevealValidationError::BondAlreadyInUse => ProtocolRejection::BondAlreadyInUse,
        RevealValidationError::InvalidAnchorHeight => ProtocolRejection::InvalidBondAnchorHeight,
        RevealValidationError::AnchorCheckpointMismatch
        | RevealValidationError::FreshnessCheckpointMismatch => {
            ProtocolRejection::UnknownBondAnchor
        }
        RevealValidationError::ProofTooLarge => ProtocolRejection::OversizedProof,
        RevealValidationError::InvalidPublicInput | RevealValidationError::InvalidProof => {
            ProtocolRejection::InvalidBondProof
        }
        RevealValidationError::UnsupportedOperation => ProtocolRejection::MalformedOperation,
        RevealValidationError::DeploymentEncoding(_)
        | RevealValidationError::VerifierIdentityMismatch => {
            return Err(FatalReducerError::StateInvariantFailure);
        }
        RevealValidationError::ArithmeticOverflow => {
            return Err(FatalReducerError::ArithmeticOverflow);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Rendezvous,
        owner::{OwnerSigningKey, owner_key_bytes},
        recent_spent,
        record::NameRecord,
    };
    use std::collections::BTreeMap;
    use zcash_address::unified::{self, Encoding};
    use zcash_protocol::consensus::NetworkType;

    fn deployment() -> DeploymentParameters {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &fixture["input"];
        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: NetworkType::Regtest,
            activation_height: 100,
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

    fn reducer() -> V1Reducer {
        V1Reducer::new(
            deployment(),
            ActivationCheckpoint {
                height: 99,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn block(transactions: Vec<CanonicalTxInput>) -> CanonicalBlockInput {
        CanonicalBlockInput {
            height: 100,
            block_hash: [10; 32],
            prev_block_hash: [9; 32],
            branch_id: BranchId::Nu6_3,
            transactions,
        }
    }

    fn tx(index: u32) -> CanonicalTxInput {
        CanonicalTxInput {
            tx_index: index,
            txid: [0; 32],
            ironwood_nullifiers: vec![],
            ironwood_commitments: vec![],
            full_tx_required: false,
            candidate_full_tx: None,
        }
    }

    fn snapshot(
        reducer: &V1Reducer,
    ) -> (
        CoppiceState,
        IronwoodFrontier,
        BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
        ReplayTip,
    ) {
        (
            reducer.state.clone(),
            reducer.ironwood_tree.clone(),
            reducer.ironwood_checkpoints.clone(),
            reducer.tip,
        )
    }

    fn assert_atomic(error: FatalReducerError, mutate: impl FnOnce(&mut CanonicalBlockInput)) {
        let mut reducer = reducer();
        let before = snapshot(&reducer);
        let mut input = block(vec![]);
        mutate(&mut input);
        assert_eq!(reducer.apply_block(&input), Err(error));
        assert_eq!(snapshot(&reducer), before);
    }

    fn canonical_nullifier() -> [u8; 32] {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/bond_tags.json")).unwrap();
        hex::decode(vector["canonical_nullifier"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn canonical_ua() -> Vec<u8> {
        unified::Address::try_from_items(vec![unified::Receiver::Orchard(
            deployment().rendezvous.orchard_receiver,
        )])
        .unwrap()
        .encode(&NetworkType::Regtest)
        .into_bytes()
    }

    #[test]
    fn fatal_inputs_are_atomic() {
        assert_atomic(FatalReducerError::NonSequentialHeight, |block| {
            block.height = 101
        });
        assert_atomic(FatalReducerError::PredecessorMismatch, |block| {
            block.prev_block_hash = [8; 32]
        });
        assert_atomic(FatalReducerError::NonCanonicalTxOrder, |block| {
            block.transactions = vec![tx(2), tx(2)]
        });
        assert_atomic(FatalReducerError::RequiredFullTransactionMissing, |block| {
            let mut candidate = tx(0);
            candidate.full_tx_required = true;
            block.transactions.push(candidate);
        });
        assert_atomic(FatalReducerError::CandidateFlagMismatch, |block| {
            let mut candidate = tx(0);
            candidate.candidate_full_tx = Some(vec![]);
            block.transactions.push(candidate);
        });
        assert_atomic(FatalReducerError::InvalidFullTransaction, |block| {
            let mut candidate = tx(0);
            candidate.full_tx_required = true;
            candidate.candidate_full_tx = Some(vec![1, 2, 3]);
            block.transactions.push(candidate);
        });
        assert_atomic(FatalReducerError::NonCanonicalNullifier, |block| {
            let mut candidate = tx(0);
            candidate.ironwood_nullifiers.push([0xff; 32]);
            block.transactions.push(candidate);
        });
        assert_atomic(FatalReducerError::InvalidIronwoodCommitment, |block| {
            let mut candidate = tx(0);
            candidate.ironwood_commitments.push([0xff; 32]);
            block.transactions.push(candidate);
        });
    }

    #[test]
    fn nullifiers_are_first_seen_and_terminate_active_bonds_before_operations() {
        let mut reducer = reducer();
        let nullifier = canonical_nullifier();
        let tag = bond_tag::derive_v1_bond_tag(&nullifier).unwrap();
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let record = NameRecord {
            owner_pk: owner_key_bytes(&(&key).into()),
            bond_tag: tag,
            sequence: 0,
            address: canonical_ua(),
            status: NameStatus::Active,
        };
        let mut names = BTreeMap::new();
        names.insert("alice".to_owned(), record.clone());
        reducer.state = CoppiceState::from_authoritative_parts(
            names,
            pending::PendingCommitments::new(),
            recent_spent::RecentSpent::new(),
        )
        .unwrap();

        reducer
            .state
            .process_prevalidated_bond_tag(tag, 100)
            .unwrap();
        let mut update = Operation::Update {
            name: "alice".to_owned(),
            sequence: 1,
            address: canonical_ua(),
            signature: vec![],
        };
        let signature =
            authorization::sign_v1(reducer.deployment_id, &key, &update, &record).unwrap();
        if let Operation::Update { signature: out, .. } = &mut update {
            *out = signature.to_vec();
        }
        assert_eq!(
            reducer
                .apply_operation(
                    &mut reducer.state.clone(),
                    &reducer.ironwood_checkpoints,
                    100,
                    0,
                    &update
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::NameUnavailable)
        );
        assert_eq!(
            reducer.state.names["alice"].status,
            NameStatus::BondSpent {
                terminal_height: 100
            }
        );
        assert!(!reducer.state.active_bond_index().contains_key(&tag));
        assert_eq!(reducer.state.recent_spent.get(&tag), Some(&100));
        reducer
            .state
            .process_prevalidated_bond_tag(tag, 101)
            .unwrap();
        assert_eq!(reducer.state.recent_spent.get(&tag), Some(&100));

        let release = Operation::Release {
            name: "alice".to_owned(),
            sequence: 1,
            signature: vec![0; 64],
        };
        let mut staged = reducer.state.clone();
        assert_eq!(
            reducer
                .apply_operation(&mut staged, &reducer.ironwood_checkpoints, 100, 1, &release)
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::NameUnavailable)
        );
        assert!(matches!(
            staged.names["alice"].status,
            NameStatus::BondSpent { .. }
        ));
    }

    #[test]
    fn protocol_rejections_are_noops_and_block_end_processing_still_commits() {
        let mut reducer = reducer();
        let commitment = [4; 32];
        reducer
            .state
            .apply_prevalidated_commit(
                commitment,
                pending::ChainPosition {
                    block_height: 80,
                    tx_index: 0,
                },
            )
            .unwrap();
        let mut staged = reducer.state.clone();
        assert_eq!(
            reducer
                .apply_operation(
                    &mut staged,
                    &reducer.ironwood_checkpoints,
                    100,
                    0,
                    &Operation::Commit { commitment },
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::DuplicateCommitment)
        );
        assert!(staged.pending.contains_key(&commitment));

        let applied = reducer.apply_block(&block(vec![])).unwrap();
        assert_eq!(applied.tip.height, 100);
        assert!(!reducer.state.pending.contains_key(&commitment));
    }

    #[test]
    fn final_reveal_block_observes_live_commit_before_expiry() {
        let reducer = reducer();
        let commitment = [5; 32];
        let mut staged = CoppiceState::default();
        staged
            .apply_prevalidated_commit(
                commitment,
                pending::ChainPosition {
                    block_height: 100,
                    tx_index: 0,
                },
            )
            .unwrap();
        assert_eq!(
            reducer
                .apply_operation(
                    &mut staged,
                    &reducer.ironwood_checkpoints,
                    120,
                    1,
                    &Operation::Commit { commitment },
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::DuplicateCommitment)
        );
        assert!(staged.pending.contains_key(&commitment));
        staged.expire_pending_at_end_of_block(120, 20).unwrap();
        assert!(!staged.pending.contains_key(&commitment));
    }

    #[test]
    fn invalid_update_signature_and_release_sequence_do_not_mutate() {
        let mut reducer = reducer();
        let key = OwnerSigningKey::try_from([2; 32]).unwrap();
        let record = NameRecord {
            owner_pk: owner_key_bytes(&(&key).into()),
            bond_tag: [3; 32],
            sequence: 7,
            address: canonical_ua(),
            status: NameStatus::Active,
        };
        let mut names = BTreeMap::new();
        names.insert("alice".to_owned(), record);
        reducer.state = CoppiceState::from_authoritative_parts(
            names,
            pending::PendingCommitments::new(),
            recent_spent::RecentSpent::new(),
        )
        .unwrap();
        let before = reducer.state.clone();
        let mut staged = before.clone();
        let invalid_update = Operation::Update {
            name: "alice".to_owned(),
            sequence: 8,
            address: canonical_ua(),
            signature: vec![0; 64],
        };
        assert_eq!(
            reducer
                .apply_operation(
                    &mut staged,
                    &reducer.ironwood_checkpoints,
                    100,
                    0,
                    &invalid_update
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::InvalidSignature)
        );
        let invalid_release = Operation::Release {
            name: "alice".to_owned(),
            sequence: 9,
            signature: vec![0; 64],
        };
        assert_eq!(
            reducer
                .apply_operation(
                    &mut staged,
                    &reducer.ironwood_checkpoints,
                    100,
                    1,
                    &invalid_release
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::InvalidSequence)
        );
        assert_eq!(staged, before);
    }

    #[test]
    fn checkpoint_retention_keeps_boundaries_and_prunes_when_safe() {
        let mut reducer = reducer();
        for height in 100..=219 {
            let previous = reducer.tip.block_hash;
            reducer
                .apply_block(&CanonicalBlockInput {
                    height,
                    block_hash: [height as u8; 32],
                    prev_block_hash: previous,
                    branch_id: BranchId::Nu6_3,
                    transactions: vec![],
                })
                .unwrap();
        }
        assert!(reducer.ironwood_checkpoints.contains_key(&99));
        let previous = reducer.tip.block_hash;
        reducer
            .apply_block(&CanonicalBlockInput {
                height: 220,
                block_hash: [220; 32],
                prev_block_hash: previous,
                branch_id: BranchId::Nu6_3,
                transactions: vec![],
            })
            .unwrap();
        assert!(!reducer.ironwood_checkpoints.contains_key(&99));
        assert!(reducer.ironwood_checkpoints.contains_key(&100));
        let previous = reducer.tip.block_hash;
        reducer
            .apply_block(&CanonicalBlockInput {
                height: 221,
                block_hash: [221; 32],
                prev_block_hash: previous,
                branch_id: BranchId::Nu6_3,
                transactions: vec![],
            })
            .unwrap();
        assert!(!reducer.ironwood_checkpoints.contains_key(&100));
        assert!(reducer.ironwood_checkpoints.contains_key(&101));
    }

    #[test]
    fn malformed_carrier_keeps_preceding_canonical_effects() {
        let mut state = CoppiceState::default();
        let tag = bond_tag::derive_v1_bond_tag(&canonical_nullifier()).unwrap();
        state.process_prevalidated_bond_tag(tag, 100).unwrap();
        let outcome = carrier_semantic(Err(carrier::V1CarrierError::Malformed)).unwrap();
        assert!(matches!(
            outcome,
            CarrierSemantic::Rejected(ProtocolRejection::MalformedCarrier)
        ));
        assert_eq!(state.recent_spent.get(&tag), Some(&100));
    }

    #[test]
    fn final_root_uses_real_block_hash_and_recent_spent_boundary_survives() {
        let mut reducer = reducer();
        let nullifier = canonical_nullifier();
        let tag = bond_tag::derive_v1_bond_tag(&nullifier).unwrap();
        reducer.state.recent_spent.insert(tag, 100);
        let applied = reducer.apply_block(&block(vec![])).unwrap();
        assert_eq!(applied.tip.block_hash, [10; 32]);
        assert_eq!(reducer.state.recent_spent.get(&tag), Some(&100));
        assert_eq!(
            applied.state_root,
            state_root::state_root(&StateRootInput {
                deployment_id: reducer.deployment_id,
                height: 100,
                block_hash: [10; 32],
                ironwood_tree_size: applied.ironwood_checkpoint.tree_size,
                ironwood_root: applied.ironwood_checkpoint.root,
                name_tree_root: applied.name_tree_root,
                pending_root: applied.pending_root,
                recent_spent_root: applied.recent_spent_root,
            })
            .unwrap()
        );
    }
}
