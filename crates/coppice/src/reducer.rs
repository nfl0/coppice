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
    ironwood, pending, recent_spent,
    record::NameStatus,
    reveal::{self, AuthenticatedIronwoodCheckpoint, RevealValidationError},
    state::{CoppiceState, StateMutationError},
    state_root::{self, StateRootInput},
};
use orchard::tree::MerkleHashOrchard;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Cursor};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

pub use coppice_core::replay::{
    CoreCanonicalBlockInput as CanonicalBlockInput,
    CoreCanonicalTransactionInput as CanonicalTxInput,
    CoreReplayActivationCheckpoint as ActivationCheckpoint, IronwoodFrontier,
};

pub const COPPICE_SNAPSHOT_FORMAT_VERSION: u32 = 1;

fn required_reorg_retention_blocks(
    deployment: &DeploymentParameters,
) -> Result<u32, SnapshotError> {
    deployment
        .bond_note_max_age_blocks
        .checked_add(deployment.commit_ttl_blocks)
        .and_then(|value| value.checked_add(1))
        .ok_or(SnapshotError::HistoryTooLarge)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewindError {
    BeforeActivation,
    BeyondTip,
    SnapshotMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    Encoding,
    UnsupportedFormat,
    DeploymentMismatch,
    EmptyHistory,
    HistoryTooLarge,
    NonCanonicalHistory,
    InvalidState,
    InvalidIronwoodTree,
    InvalidCheckpoint,
    StateRootMismatch,
    VerifierInitializationFailure,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredState {
    names: Vec<(String, crate::record::NameRecord)>,
    pending: Vec<([u8; 32], pending::ChainPosition)>,
    recent_spent: Vec<([u8; 32], u32)>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredCheckpoint {
    height: u32,
    root: [u8; 32],
    tree_size: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredReducerSnapshot {
    height: u32,
    block_hash: [u8; 32],
    state: StoredState,
    ironwood_tree: Vec<u8>,
    ironwood_checkpoints: Vec<StoredCheckpoint>,
    state_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredStateUndo {
    names: Vec<(String, Option<crate::record::NameRecord>)>,
    pending: Vec<([u8; 32], Option<pending::ChainPosition>)>,
    recent_spent: Vec<([u8; 32], Option<u32>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredReducerUndo {
    applied_height: u32,
    applied_block_hash: [u8; 32],
    prior_height: u32,
    prior_block_hash: [u8; 32],
    state: StoredStateUndo,
    prior_ironwood_tree: Vec<u8>,
    checkpoint_undo: Vec<(u32, Option<StoredCheckpoint>)>,
    prior_state_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredReducer {
    format_version: u32,
    deployment_id: [u8; 32],
    current: StoredReducerSnapshot,
    undo: Vec<StoredReducerUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReducerSnapshot {
    state: CoppiceState,
    ironwood_tree: IronwoodFrontier,
    ironwood_checkpoints: BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
    tip: ReplayTip,
    state_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StateUndo {
    names: Vec<(String, Option<crate::record::NameRecord>)>,
    pending: Vec<([u8; 32], Option<pending::ChainPosition>)>,
    recent_spent: Vec<([u8; 32], Option<u32>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReducerUndo {
    applied_tip: ReplayTip,
    prior_tip: ReplayTip,
    state: StateUndo,
    prior_ironwood_tree: IronwoodFrontier,
    checkpoint_undo: Vec<(u32, Option<AuthenticatedIronwoodCheckpoint>)>,
    prior_state_root: [u8; 32],
}

impl StateUndo {
    fn between(before: &CoppiceState, after: &CoppiceState) -> Self {
        Self {
            names: map_undo(&before.names, &after.names),
            pending: map_undo(&before.pending, &after.pending),
            recent_spent: map_undo(&before.recent_spent, &after.recent_spent),
        }
    }
}

fn map_undo<K: Ord + Clone, V: Clone + PartialEq>(
    before: &BTreeMap<K, V>,
    after: &BTreeMap<K, V>,
) -> Vec<(K, Option<V>)> {
    let keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|key| {
            (before.get(&key) != after.get(&key)).then(|| (key.clone(), before.get(&key).cloned()))
        })
        .collect()
}

fn apply_map_undo<K: Ord + Clone, V: Clone>(target: &mut BTreeMap<K, V>, undo: &[(K, Option<V>)]) {
    for (key, value) in undo {
        match value {
            Some(value) => {
                target.insert(key.clone(), value.clone());
            }
            None => {
                target.remove(key);
            }
        }
    }
}

fn has_duplicate_keys<K: Ord, V>(values: &[(K, V)]) -> bool {
    values.windows(2).any(|pair| pair[0].0 >= pair[1].0)
}

pub struct Reducer {
    deployment: DeploymentParameters,
    deployment_id: [u8; 32],
    state: CoppiceState,
    ironwood_tree: IronwoodFrontier,
    ironwood_checkpoints: BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
    tip: ReplayTip,
    state_root: [u8; 32],
    verifier: V1BondVerifier,
    /// Bounded per-block undo journal. Registry maps retain only keys changed
    /// by each block; the current full state is stored exactly once.
    history: BTreeMap<u32, ReducerUndo>,
}

#[allow(clippy::large_enum_variant)]
enum CarrierSemantic {
    NoOperation,
    Rejected(ProtocolRejection),
    Operation(Operation),
}

impl Reducer {
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
        let state = CoppiceState::default();
        let ironwood_tree = checkpoint.ironwood_frontier;
        let tip = ReplayTip {
            height: checkpoint.height,
            block_hash: checkpoint.block_hash,
        };
        let state_root = Self::snapshot_state_root(
            &deployment,
            deployment_id,
            &state,
            &ironwood_tree,
            &ironwood_checkpoints,
            tip,
        )
        .map_err(|_| FatalReducerError::StateInvariantFailure)?;
        Ok(Self {
            deployment,
            deployment_id,
            state,
            ironwood_tree,
            ironwood_checkpoints,
            tip,
            state_root,
            verifier,
            history: BTreeMap::new(),
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

    pub fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first_key_value()
            .map_or(self.tip.height, |(_, undo)| undo.prior_tip.height)
    }

    /// Wallet-local rewind depth aligned with the authenticated checkpoint
    /// horizon required by freshness and REVEAL preparation.
    pub fn reorg_retention_blocks(&self) -> u32 {
        required_reorg_retention_blocks(&self.deployment)
            .expect("validated deployment has a bounded checkpoint horizon")
    }

    pub fn has_rewind_snapshot(&self, height: u32) -> bool {
        height == self.tip.height
            || (height >= self.oldest_rewind_height() && height < self.tip.height)
    }

    /// Returns the canonical identity stored in a retained rewind snapshot.
    /// This is read-only and does not extend or otherwise alter retention.
    pub fn retained_tip_at(&self, height: u32) -> Option<ReplayTip> {
        if height == self.tip.height {
            Some(self.tip)
        } else {
            height
                .checked_add(1)
                .and_then(|next| self.history.get(&next))
                .map(|undo| undo.prior_tip)
        }
    }

    /// Serializes the validated reducer state and bounded rewind journal.
    ///
    /// The returned bytes are local wallet material, not protocol wire data.
    pub fn save_snapshot(&self) -> Result<Vec<u8>, SnapshotError> {
        let current = self.store_current_snapshot()?;
        let undo = self
            .history
            .values()
            .map(Self::store_undo)
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_vec(&StoredReducer {
            format_version: COPPICE_SNAPSHOT_FORMAT_VERSION,
            deployment_id: self.deployment_id,
            current,
            undo,
        })
        .map_err(|_| SnapshotError::Encoding)
    }

    /// Loads and fully validates a local reducer snapshot.
    ///
    /// Derived indexes are rebuilt from authoritative records. The caller must
    /// still compare the returned tip with its host-selected canonical block
    /// identity before using the reducer for protected wallet operations.
    pub fn load_snapshot(
        deployment: DeploymentParameters,
        bytes: &[u8],
    ) -> Result<Self, SnapshotError> {
        let deployment_id = deployment
            .validate()
            .map_err(|_| SnapshotError::DeploymentMismatch)?;
        let stored: StoredReducer =
            serde_json::from_slice(bytes).map_err(|_| SnapshotError::Encoding)?;
        if stored.format_version != COPPICE_SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotError::UnsupportedFormat);
        }
        if stored.deployment_id != deployment_id {
            return Err(SnapshotError::DeploymentMismatch);
        }
        if stored.undo.len() > required_reorg_retention_blocks(&deployment)? as usize {
            return Err(SnapshotError::HistoryTooLarge);
        }

        let activation_base = deployment
            .activation_height
            .checked_sub(1)
            .ok_or(SnapshotError::InvalidState)?;
        let current = Self::restore_snapshot(&deployment, deployment_id, stored.current)?;
        if current.tip.height < activation_base {
            return Err(SnapshotError::NonCanonicalHistory);
        }
        let mut history = BTreeMap::new();
        for stored_undo in stored.undo {
            let undo = Self::restore_undo(stored_undo)?;
            if undo.prior_tip.height < activation_base
                || undo.prior_tip.height.checked_add(1) != Some(undo.applied_tip.height)
                || history.insert(undo.applied_tip.height, undo).is_some()
            {
                return Err(SnapshotError::NonCanonicalHistory);
            }
        }
        let expected_oldest = current.tip.height.saturating_sub(history.len() as u32);
        if history
            .keys()
            .copied()
            .ne(expected_oldest.saturating_add(1)..=current.tip.height)
        {
            return Err(SnapshotError::NonCanonicalHistory);
        }

        // Validate the complete journal by replaying every undo on temporary
        // state. This authenticates historical checkpoints and roots without
        // retaining complete historical registry snapshots.
        let mut validation_state = current.state.clone();
        let mut validation_tree = current.ironwood_tree.clone();
        let mut validation_checkpoints = current.ironwood_checkpoints.clone();
        let mut validation_tip = current.tip;
        let mut validation_root = current.state_root;
        for undo in history.values().rev() {
            if undo.applied_tip != validation_tip {
                return Err(SnapshotError::NonCanonicalHistory);
            }
            Self::apply_undo_to(
                undo,
                &mut validation_state,
                &mut validation_tree,
                &mut validation_checkpoints,
                &mut validation_tip,
                &mut validation_root,
            )?;
            Self::validate_state_shape(&deployment, &validation_state, validation_tip.height)?;
            let root = Self::snapshot_state_root(
                &deployment,
                deployment_id,
                &validation_state,
                &validation_tree,
                &validation_checkpoints,
                validation_tip,
            )?;
            if root != undo.prior_state_root {
                return Err(SnapshotError::StateRootMismatch);
            }
            if validation_root != root {
                return Err(SnapshotError::StateRootMismatch);
            }
        }
        let verifier =
            V1BondVerifier::new().map_err(|_| SnapshotError::VerifierInitializationFailure)?;
        Ok(Self {
            deployment,
            deployment_id,
            state: current.state,
            ironwood_tree: current.ironwood_tree,
            ironwood_checkpoints: current.ironwood_checkpoints,
            tip: current.tip,
            state_root: current.state_root,
            verifier,
            history,
        })
    }

    /// Restores the exact in-memory reducer snapshot at the host-selected
    /// common ancestor and discards the abandoned canonical suffix.
    pub fn rewind_to(&mut self, height: u32) -> Result<(), RewindError> {
        let activation_checkpoint_height = self
            .deployment
            .activation_height
            .checked_sub(1)
            .expect("validated deployment has nonzero activation height");
        if height < activation_checkpoint_height {
            return Err(RewindError::BeforeActivation);
        }
        if height > self.tip.height {
            return Err(RewindError::BeyondTip);
        }
        if height < self.oldest_rewind_height() {
            return Err(RewindError::SnapshotMissing);
        }
        while self.tip.height > height {
            let undo = self
                .history
                .remove(&self.tip.height)
                .ok_or(RewindError::SnapshotMissing)?;
            Self::apply_undo_to(
                &undo,
                &mut self.state,
                &mut self.ironwood_tree,
                &mut self.ironwood_checkpoints,
                &mut self.tip,
                &mut self.state_root,
            )
            .map_err(|_| RewindError::SnapshotMissing)?;
        }
        Ok(())
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
        // Keep the production oracle aligned with Core's generic preflight:
        // application processing cannot shadow terminal-height overflow.
        block
            .height
            .checked_add(1)
            .ok_or(FatalReducerError::ArithmeticOverflow)?;

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

        let undo = ReducerUndo {
            applied_tip: tip,
            prior_tip: self.tip,
            state: StateUndo::between(&self.state, &state),
            prior_ironwood_tree: self.ironwood_tree.clone(),
            checkpoint_undo: map_undo(&self.ironwood_checkpoints, &checkpoints),
            prior_state_root: self.state_root,
        };

        self.state = state;
        self.ironwood_tree = tree;
        self.ironwood_checkpoints = checkpoints;
        self.tip = tip;
        self.state_root = final_root;
        self.history.insert(block.height, undo);
        let oldest_undo = block
            .height
            .saturating_sub(self.reorg_retention_blocks())
            .saturating_add(1);
        self.history.retain(|height, _| *height >= oldest_undo);
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

    fn store_current_snapshot(&self) -> Result<StoredReducerSnapshot, SnapshotError> {
        let mut ironwood_tree = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(
            &self.ironwood_tree,
            &mut ironwood_tree,
        )
        .map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        let state_root = Self::snapshot_state_root(
            &self.deployment,
            self.deployment_id,
            &self.state,
            &self.ironwood_tree,
            &self.ironwood_checkpoints,
            self.tip,
        )?;
        if state_root != self.state_root {
            return Err(SnapshotError::StateRootMismatch);
        }
        Ok(StoredReducerSnapshot {
            height: self.tip.height,
            block_hash: self.tip.block_hash,
            state: StoredState {
                names: self
                    .state
                    .names
                    .iter()
                    .map(|(name, record)| (name.clone(), record.clone()))
                    .collect(),
                pending: self
                    .state
                    .pending
                    .iter()
                    .map(|(commitment, position)| (*commitment, *position))
                    .collect(),
                recent_spent: self
                    .state
                    .recent_spent
                    .iter()
                    .map(|(tag, height)| (*tag, *height))
                    .collect(),
            },
            ironwood_tree,
            ironwood_checkpoints: self
                .ironwood_checkpoints
                .values()
                .map(|checkpoint| StoredCheckpoint {
                    height: checkpoint.height,
                    root: checkpoint.root,
                    tree_size: checkpoint.tree_size,
                })
                .collect(),
            state_root: self.state_root,
        })
    }

    fn store_undo(undo: &ReducerUndo) -> Result<StoredReducerUndo, SnapshotError> {
        let mut prior_ironwood_tree = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(
            &undo.prior_ironwood_tree,
            &mut prior_ironwood_tree,
        )
        .map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        Ok(StoredReducerUndo {
            applied_height: undo.applied_tip.height,
            applied_block_hash: undo.applied_tip.block_hash,
            prior_height: undo.prior_tip.height,
            prior_block_hash: undo.prior_tip.block_hash,
            state: StoredStateUndo {
                names: undo.state.names.clone(),
                pending: undo.state.pending.clone(),
                recent_spent: undo.state.recent_spent.clone(),
            },
            prior_ironwood_tree,
            checkpoint_undo: undo
                .checkpoint_undo
                .iter()
                .map(|(height, checkpoint)| {
                    (
                        *height,
                        checkpoint.map(|checkpoint| StoredCheckpoint {
                            height: checkpoint.height,
                            root: checkpoint.root,
                            tree_size: checkpoint.tree_size,
                        }),
                    )
                })
                .collect(),
            prior_state_root: undo.prior_state_root,
        })
    }

    fn restore_snapshot(
        deployment: &DeploymentParameters,
        deployment_id: [u8; 32],
        stored: StoredReducerSnapshot,
    ) -> Result<ReducerSnapshot, SnapshotError> {
        let stored_name_count = stored.state.names.len();
        let names = stored.state.names.into_iter().collect::<BTreeMap<_, _>>();
        if names.len() != stored_name_count
            || names.iter().any(|(name, record)| {
                !crate::envelope::valid_name(name)
                    || crate::owner::parse_v1_owner_key(record.owner_pk).is_err()
                    || reveal::canonical_v1_address(&record.address, deployment).is_err()
                    || matches!(
                        record.status,
                        NameStatus::Released { terminal_height: 0 }
                            | NameStatus::BondSpent { terminal_height: 0 }
                    )
            })
        {
            return Err(SnapshotError::InvalidState);
        }
        let pending = stored
            .state
            .pending
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        let recent_spent = stored
            .state
            .recent_spent
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        if pending.len() != stored.state.pending.len()
            || recent_spent.len() != stored.state.recent_spent.len()
            || pending
                .values()
                .any(|position| position.block_height > stored.height)
            || recent_spent.values().any(|height| *height > stored.height)
        {
            return Err(SnapshotError::InvalidState);
        }
        let state = CoppiceState::from_authoritative_parts(names, pending, recent_spent)
            .map_err(|_| SnapshotError::InvalidState)?;

        let mut tree_cursor = Cursor::new(&stored.ironwood_tree);
        let ironwood_tree: IronwoodFrontier =
            zcash_primitives::merkle_tree::read_commitment_tree(&mut tree_cursor)
                .map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        if tree_cursor.position() != stored.ironwood_tree.len() as u64 {
            return Err(SnapshotError::InvalidIronwoodTree);
        }

        let checkpoints = stored
            .ironwood_checkpoints
            .iter()
            .map(|checkpoint| {
                (
                    checkpoint.height,
                    AuthenticatedIronwoodCheckpoint {
                        height: checkpoint.height,
                        root: checkpoint.root,
                        tree_size: checkpoint.tree_size,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if checkpoints.len() != stored.ironwood_checkpoints.len()
            || checkpoints.keys().any(|height| *height > stored.height)
        {
            return Err(SnapshotError::InvalidCheckpoint);
        }
        let tree_size =
            u32::try_from(ironwood_tree.size()).map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        let tip_checkpoint = checkpoints
            .get(&stored.height)
            .ok_or(SnapshotError::InvalidCheckpoint)?;
        if tip_checkpoint.root != ironwood_tree.root().to_bytes()
            || tip_checkpoint.tree_size != tree_size
        {
            return Err(SnapshotError::InvalidCheckpoint);
        }
        let tip = ReplayTip {
            height: stored.height,
            block_hash: stored.block_hash,
        };
        let computed_root = Self::snapshot_state_root(
            deployment,
            deployment_id,
            &state,
            &ironwood_tree,
            &checkpoints,
            tip,
        )?;
        if computed_root != stored.state_root {
            return Err(SnapshotError::StateRootMismatch);
        }
        Ok(ReducerSnapshot {
            state,
            ironwood_tree,
            ironwood_checkpoints: checkpoints,
            tip,
            state_root: stored.state_root,
        })
    }

    fn validate_state_shape(
        deployment: &DeploymentParameters,
        state: &CoppiceState,
        height: u32,
    ) -> Result<(), SnapshotError> {
        if state.names.iter().any(|(name, record)| {
            !crate::envelope::valid_name(name)
                || crate::owner::parse_v1_owner_key(record.owner_pk).is_err()
                || reveal::canonical_v1_address(&record.address, deployment).is_err()
                || matches!(
                    record.status,
                    NameStatus::Released { terminal_height: 0 }
                        | NameStatus::BondSpent { terminal_height: 0 }
                )
        }) || state
            .pending
            .values()
            .any(|position| position.block_height > height)
            || state.recent_spent.values().any(|spent| *spent > height)
        {
            return Err(SnapshotError::InvalidState);
        }
        Ok(())
    }

    fn restore_undo(stored: StoredReducerUndo) -> Result<ReducerUndo, SnapshotError> {
        let mut tree_cursor = Cursor::new(&stored.prior_ironwood_tree);
        let prior_ironwood_tree: IronwoodFrontier =
            zcash_primitives::merkle_tree::read_commitment_tree(&mut tree_cursor)
                .map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        if tree_cursor.position() != stored.prior_ironwood_tree.len() as u64 {
            return Err(SnapshotError::InvalidIronwoodTree);
        }
        let checkpoint_undo = stored
            .checkpoint_undo
            .into_iter()
            .map(|(height, checkpoint)| {
                let checkpoint = checkpoint.map(|checkpoint| {
                    if checkpoint.height != height {
                        return Err(SnapshotError::InvalidCheckpoint);
                    }
                    Ok(AuthenticatedIronwoodCheckpoint {
                        height,
                        root: checkpoint.root,
                        tree_size: checkpoint.tree_size,
                    })
                });
                match checkpoint.transpose() {
                    Ok(checkpoint) => Ok((height, checkpoint)),
                    Err(error) => Err(error),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if has_duplicate_keys(&stored.state.names)
            || has_duplicate_keys(&stored.state.pending)
            || has_duplicate_keys(&stored.state.recent_spent)
            || has_duplicate_keys(&checkpoint_undo)
        {
            return Err(SnapshotError::NonCanonicalHistory);
        }
        Ok(ReducerUndo {
            applied_tip: ReplayTip {
                height: stored.applied_height,
                block_hash: stored.applied_block_hash,
            },
            prior_tip: ReplayTip {
                height: stored.prior_height,
                block_hash: stored.prior_block_hash,
            },
            state: StateUndo {
                names: stored.state.names,
                pending: stored.state.pending,
                recent_spent: stored.state.recent_spent,
            },
            prior_ironwood_tree,
            checkpoint_undo,
            prior_state_root: stored.prior_state_root,
        })
    }

    fn apply_undo_to(
        undo: &ReducerUndo,
        state: &mut CoppiceState,
        tree: &mut IronwoodFrontier,
        checkpoints: &mut BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
        tip: &mut ReplayTip,
        state_root: &mut [u8; 32],
    ) -> Result<(), SnapshotError> {
        if *tip != undo.applied_tip {
            return Err(SnapshotError::NonCanonicalHistory);
        }
        let mut names = state.names.clone();
        let mut pending = state.pending.clone();
        let mut recent_spent = state.recent_spent.clone();
        apply_map_undo(&mut names, &undo.state.names);
        apply_map_undo(&mut pending, &undo.state.pending);
        apply_map_undo(&mut recent_spent, &undo.state.recent_spent);
        *state = CoppiceState::from_authoritative_parts(names, pending, recent_spent)
            .map_err(|_| SnapshotError::InvalidState)?;
        *tree = undo.prior_ironwood_tree.clone();
        apply_map_undo(checkpoints, &undo.checkpoint_undo);
        *tip = undo.prior_tip;
        *state_root = undo.prior_state_root;
        Ok(())
    }

    fn snapshot_state_root(
        deployment: &DeploymentParameters,
        deployment_id: [u8; 32],
        state: &CoppiceState,
        tree: &IronwoodFrontier,
        checkpoints: &BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
        tip: ReplayTip,
    ) -> Result<[u8; 32], SnapshotError> {
        let checkpoint = checkpoints
            .get(&tip.height)
            .ok_or(SnapshotError::InvalidCheckpoint)?;
        let tree_size =
            u32::try_from(tree.size()).map_err(|_| SnapshotError::InvalidIronwoodTree)?;
        if checkpoint.tree_size != tree_size || checkpoint.root != tree.root().to_bytes() {
            return Err(SnapshotError::InvalidCheckpoint);
        }
        let oldest_retained_height = recent_spent::oldest_retained_height(
            deployment.activation_height,
            tip.height,
            deployment.bond_note_max_age_blocks,
            deployment.commit_ttl_blocks,
        )
        .map_err(|_| SnapshotError::InvalidState)?;
        if state
            .recent_spent
            .values()
            .any(|height| *height < oldest_retained_height || *height > tip.height)
        {
            return Err(SnapshotError::InvalidState);
        }
        let name_tree_root = state
            .name_tree_root()
            .map_err(|_| SnapshotError::InvalidState)?;
        let pending_root = state
            .pending_root()
            .map_err(|_| SnapshotError::InvalidState)?;
        let recent_spent_root = state
            .recent_spent_root(oldest_retained_height)
            .map_err(|_| SnapshotError::InvalidState)?;
        state_root::state_root(&StateRootInput {
            deployment_id,
            height: tip.height,
            block_hash: tip.block_hash,
            ironwood_tree_size: tree_size,
            ironwood_root: checkpoint.root,
            name_tree_root,
            pending_root,
            recent_spent_root,
        })
        .map_err(|_| SnapshotError::InvalidState)
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
                if crate::owner::parse_v1_owner_key(*owner_pk).is_err() {
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
mod core_replay_differential;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Rendezvous,
        owner::{OwnerSigningKey, owner_key_bytes},
        recent_spent,
        record::NameRecord,
    };
    use orchard::note::Nullifier;
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

    fn reducer() -> Reducer {
        Reducer::new(
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

    type TestReducerSnapshot = (
        CoppiceState,
        IronwoodFrontier,
        BTreeMap<u32, AuthenticatedIronwoodCheckpoint>,
        ReplayTip,
        [u8; 32],
        BTreeMap<u32, ReducerUndo>,
    );

    fn snapshot(reducer: &Reducer) -> TestReducerSnapshot {
        (
            reducer.state.clone(),
            reducer.ironwood_tree.clone(),
            reducer.ironwood_checkpoints.clone(),
            reducer.tip,
            reducer.state_root,
            reducer.history.clone(),
        )
    }

    fn empty_block_at(reducer: &Reducer, height: u32, block_hash: [u8; 32]) -> CanonicalBlockInput {
        CanonicalBlockInput {
            height,
            block_hash,
            prev_block_hash: reducer.tip.block_hash,
            branch_id: BranchId::Nu6_3,
            transactions: vec![],
        }
    }

    fn semantic_block(
        reducer: &mut Reducer,
        height: u32,
        block_hash: [u8; 32],
        mutate: impl FnOnce(&Reducer, &mut CoppiceState),
    ) -> AppliedBlock {
        let prior_state = reducer.state.clone();
        let mut staged = reducer.state.clone();
        mutate(reducer, &mut staged);
        reducer.state = staged;
        let applied = reducer
            .apply_block(&empty_block_at(reducer, height, block_hash))
            .unwrap();
        reducer.history.get_mut(&height).unwrap().state =
            StateUndo::between(&prior_state, &reducer.state);
        applied
    }

    fn block_with_effects(
        reducer: &Reducer,
        height: u32,
        block_hash: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
    ) -> CanonicalBlockInput {
        let mut input = empty_block_at(reducer, height, block_hash);
        input.transactions.push(CanonicalTxInput {
            tx_index: 0,
            txid: [height as u8; 32],
            ironwood_nullifiers: nullifiers,
            ironwood_commitments: commitments,
            full_tx_required: false,
            candidate_full_tx: None,
        });
        input
    }

    fn semantic_block_with_effects(
        reducer: &mut Reducer,
        height: u32,
        block_hash: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        mutate: impl FnOnce(&Reducer, &mut CoppiceState),
    ) -> AppliedBlock {
        let prior_state = reducer.state.clone();
        let mut staged = reducer.state.clone();
        mutate(reducer, &mut staged);
        reducer.state = staged;
        let input = block_with_effects(reducer, height, block_hash, nullifiers, commitments);
        let applied = reducer.apply_block(&input).unwrap();
        reducer.history.get_mut(&height).unwrap().state =
            StateUndo::between(&prior_state, &reducer.state);
        applied
    }

    fn valid_commitment(byte: u8) -> [u8; 32] {
        for suffix in 0..=u8::MAX {
            let mut candidate = [byte; 32];
            candidate[31] = suffix;
            if Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&candidate))
                .is_some()
            {
                return candidate;
            }
        }
        panic!("test must find a canonical field encoding")
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

    fn phase6_nullifier(marker: u8) -> [u8; 32] {
        for suffix in 0..=u8::MAX {
            let mut candidate = [marker; 32];
            candidate[31] = suffix;
            if Option::<Nullifier>::from(Nullifier::from_bytes(&candidate)).is_some() {
                return candidate;
            }
        }
        panic!("test marker must yield a canonical nullifier")
    }

    fn phase6_tag(marker: u8) -> [u8; 32] {
        bond_tag::derive_v1_bond_tag(&phase6_nullifier(marker)).unwrap()
    }

    fn phase6_owner(marker: u8) -> [u8; 32] {
        let key = OwnerSigningKey::try_from([marker; 32]).unwrap();
        owner_key_bytes(&(&key).into())
    }

    fn phase6_block_hash(branch: u8, height: u32) -> [u8; 32] {
        let mut hash = [branch; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        hash[4] = branch ^ 0x5a;
        hash
    }

    fn phase6_pending(branch: u8) -> [u8; 32] {
        let mut commitment = [0; 32];
        commitment[0] = 0xd0 ^ branch;
        commitment[1] = 0x06;
        commitment
    }

    fn phase6_common_prefix(reducer: &mut Reducer) {
        let active_commitment = [0xa1; 32];
        let released_commitment = [0xa2; 32];
        let spent_commitment = [0xa3; 32];
        let active_tag = phase6_tag(0x11);
        let released_tag = phase6_tag(0x12);
        let spent_tag = phase6_tag(0x13);

        semantic_block_with_effects(
            reducer,
            100,
            phase6_block_hash(0, 100),
            vec![],
            vec![valid_commitment(0x01), valid_commitment(0x02)],
            |_, state| {
                for commitment in [active_commitment, released_commitment, spent_commitment] {
                    state
                        .apply_prevalidated_commit(
                            commitment,
                            pending::ChainPosition {
                                block_height: 100,
                                tx_index: 0,
                            },
                        )
                        .unwrap();
                }
            },
        );

        semantic_block_with_effects(
            reducer,
            101,
            phase6_block_hash(0, 101),
            vec![],
            vec![valid_commitment(0x03)],
            |_, state| {
                for (name, owner_pk, bond_tag, commitment) in [
                    (
                        "phase6-active",
                        phase6_owner(0x21),
                        active_tag,
                        active_commitment,
                    ),
                    (
                        "phase6-released",
                        phase6_owner(0x22),
                        released_tag,
                        released_commitment,
                    ),
                    (
                        "phase6-spent",
                        phase6_owner(0x23),
                        spent_tag,
                        spent_commitment,
                    ),
                ] {
                    state
                        .apply_prevalidated_reveal(crate::state::PrevalidatedReveal {
                            name: name.to_owned(),
                            owner_pk,
                            bond_tag,
                            address: canonical_ua(),
                            commitment,
                            path: crate::state::PrevalidatedRevealPath::NewName,
                        })
                        .unwrap();
                }
            },
        );

        reducer
            .apply_block(&block_with_effects(
                reducer,
                102,
                phase6_block_hash(0, 102),
                vec![],
                vec![valid_commitment(0x04)],
            ))
            .unwrap();

        semantic_block_with_effects(
            reducer,
            103,
            phase6_block_hash(0, 103),
            vec![],
            vec![valid_commitment(0x05)],
            |_, state| {
                state
                    .apply_prevalidated_release("phase6-released", 1, 103)
                    .unwrap();
            },
        );

        semantic_block_with_effects(
            reducer,
            104,
            phase6_block_hash(0, 104),
            vec![],
            vec![valid_commitment(0x06)],
            |_, state| {
                state
                    .apply_prevalidated_update("phase6-active", 1, canonical_ua())
                    .unwrap();
            },
        );

        reducer
            .apply_block(&block_with_effects(
                reducer,
                105,
                phase6_block_hash(0, 105),
                vec![],
                vec![valid_commitment(0x07)],
            ))
            .unwrap();
    }

    fn phase6_apply_shared_suffix(reducer: &mut Reducer) {
        for height in 106..=225 {
            let commitments = vec![valid_commitment((height as u8).wrapping_add(0x20))];
            if height == 120 {
                semantic_block_with_effects(
                    reducer,
                    height,
                    phase6_block_hash(0, height),
                    vec![],
                    commitments,
                    |_, state| {
                        state
                            .apply_prevalidated_update("phase6-active", 2, canonical_ua())
                            .unwrap();
                    },
                );
            } else if height == 150 {
                reducer
                    .apply_block(&block_with_effects(
                        reducer,
                        height,
                        phase6_block_hash(0, height),
                        vec![phase6_nullifier(0x13)],
                        commitments,
                    ))
                    .unwrap();
            } else {
                reducer
                    .apply_block(&block_with_effects(
                        reducer,
                        height,
                        phase6_block_hash(0, height),
                        vec![],
                        commitments,
                    ))
                    .unwrap();
            }
        }
    }

    fn phase6_apply_divergent_suffix(reducer: &mut Reducer, branch: u8) {
        for height in 226..=240 {
            let commitments = vec![valid_commitment((height as u8).wrapping_add(branch))];
            if height == 230 {
                let commitment = phase6_pending(branch);
                semantic_block_with_effects(
                    reducer,
                    height,
                    phase6_block_hash(branch, height),
                    vec![],
                    commitments,
                    |_, state| {
                        state
                            .apply_prevalidated_commit(
                                commitment,
                                pending::ChainPosition {
                                    block_height: height,
                                    tx_index: 0,
                                },
                            )
                            .unwrap();
                    },
                );
            } else {
                reducer
                    .apply_block(&block_with_effects(
                        reducer,
                        height,
                        phase6_block_hash(branch, height),
                        vec![],
                        commitments,
                    ))
                    .unwrap();
            }
        }
    }

    fn phase6_apply_long_suffix(reducer: &mut Reducer, branch: u8) {
        for height in 106..=240 {
            let commitments = vec![valid_commitment((height as u8).wrapping_add(branch))];
            if height == 120 && branch == 1 {
                semantic_block_with_effects(
                    reducer,
                    height,
                    phase6_block_hash(branch, height),
                    vec![],
                    commitments,
                    |_, state| {
                        state
                            .apply_prevalidated_update("phase6-active", 2, canonical_ua())
                            .unwrap();
                    },
                );
            } else if height == 150 {
                reducer
                    .apply_block(&block_with_effects(
                        reducer,
                        height,
                        phase6_block_hash(branch, height),
                        vec![phase6_nullifier(0x13)],
                        commitments,
                    ))
                    .unwrap();
            } else if height == 230 {
                let commitment = phase6_pending(branch);
                semantic_block_with_effects(
                    reducer,
                    height,
                    phase6_block_hash(branch, height),
                    vec![],
                    commitments,
                    |_, state| {
                        state
                            .apply_prevalidated_commit(
                                commitment,
                                pending::ChainPosition {
                                    block_height: height,
                                    tx_index: 0,
                                },
                            )
                            .unwrap();
                    },
                );
            } else {
                reducer
                    .apply_block(&block_with_effects(
                        reducer,
                        height,
                        phase6_block_hash(branch, height),
                        vec![],
                        commitments,
                    ))
                    .unwrap();
            }
        }
    }

    fn assert_phase6_replacement_state(reducer: &Reducer, branch: u8) {
        assert_eq!(reducer.tip().height, 240);
        assert_eq!(reducer.state.names["phase6-active"].sequence, 1);
        assert_eq!(
            reducer.state.names["phase6-active"].status,
            NameStatus::Active
        );
        assert_eq!(
            reducer.state.names["phase6-released"].status,
            NameStatus::Released {
                terminal_height: 103
            }
        );
        assert_eq!(
            reducer.state.names["phase6-spent"].status,
            NameStatus::BondSpent {
                terminal_height: 150
            }
        );
        assert_eq!(
            reducer.state.pending.get(&phase6_pending(branch)),
            Some(&pending::ChainPosition {
                block_height: 230,
                tx_index: 0,
            })
        );
        assert_eq!(
            reducer.state.recent_spent.get(&phase6_tag(0x13)),
            Some(&150)
        );
        assert!(
            reducer
                .state
                .active_bond_index()
                .contains_key(&phase6_tag(0x11))
        );
        assert!(
            !reducer
                .state
                .active_bond_index()
                .contains_key(&phase6_tag(0x12))
        );
        assert!(
            !reducer
                .state
                .active_bond_index()
                .contains_key(&phase6_tag(0x13))
        );
        assert_eq!(
            reducer.ironwood_checkpoints().first_key_value().unwrap().0,
            &120
        );
        assert!(reducer.ironwood_checkpoints().contains_key(&240));
        assert!(reducer.ironwood_frontier().size() > 120);
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

    fn install_reorg_common_history(reducer: &mut Reducer, commitment: [u8; 32]) {
        reducer
            .apply_block(&empty_block_at(reducer, 100, [0x10; 32]))
            .unwrap();
        semantic_block(reducer, 101, [0x11; 32], |_, state| {
            state
                .apply_prevalidated_commit(
                    commitment,
                    pending::ChainPosition {
                        block_height: 101,
                        tx_index: 0,
                    },
                )
                .unwrap();
        });
    }

    fn install_reorg_reveal(
        reducer: &mut Reducer,
        commitment: [u8; 32],
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        block_hash: [u8; 32],
    ) -> AppliedBlock {
        semantic_block(reducer, 102, block_hash, |_, state| {
            state
                .apply_prevalidated_reveal(crate::state::PrevalidatedReveal {
                    name: "alice".to_owned(),
                    owner_pk,
                    bond_tag,
                    address: canonical_ua(),
                    commitment,
                    path: crate::state::PrevalidatedRevealPath::NewName,
                })
                .unwrap();
        })
    }

    #[test]
    fn reorg_vector_rewind_and_replay_equals_fresh_replay() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/reorg.json")).unwrap();
        assert_eq!(vector["vector"]["common_ancestor_height"], 101);

        let key = OwnerSigningKey::try_from([7; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let nullifier = canonical_nullifier();
        let bond_tag = bond_tag::derive_v1_bond_tag(&nullifier).unwrap();
        let commitment = [0x51; 32];
        let abandoned_pending = [0x61; 32];
        let abandoned_nullifier = [1; 32];
        let abandoned_tag = bond_tag::derive_v1_bond_tag(&abandoned_nullifier).unwrap();
        let abandoned_commitment = valid_commitment(3);

        let mut rewound = reducer();
        install_reorg_common_history(&mut rewound, commitment);
        let ancestor = snapshot(&rewound);
        install_reorg_reveal(&mut rewound, commitment, owner_pk, bond_tag, [0xa2; 32]);

        let previous = rewound.state.names["alice"].clone();
        let mut update = Operation::Update {
            name: "alice".to_owned(),
            sequence: 1,
            address: canonical_ua(),
            signature: vec![],
        };
        let signature =
            authorization::sign_v1(rewound.deployment_id, &key, &update, &previous).unwrap();
        if let Operation::Update { signature: out, .. } = &mut update {
            *out = signature.to_vec();
        }
        let prior_state = rewound.state.clone();
        let mut staged = prior_state.clone();
        assert_eq!(
            rewound
                .apply_operation(&mut staged, &rewound.ironwood_checkpoints, 103, 0, &update)
                .unwrap(),
            TransactionOutcome::Applied
        );
        staged
            .apply_prevalidated_commit(
                abandoned_pending,
                pending::ChainPosition {
                    block_height: 103,
                    tx_index: 1,
                },
            )
            .unwrap();
        rewound.state = staged;
        let old_tip = rewound
            .apply_block(&block_with_effects(
                &rewound,
                103,
                [0xa3; 32],
                vec![abandoned_nullifier],
                vec![abandoned_commitment],
            ))
            .unwrap();
        rewound.history.get_mut(&103).unwrap().state =
            StateUndo::between(&prior_state, &rewound.state);
        assert_eq!(rewound.state.names["alice"].sequence, 1);
        assert_eq!(rewound.state.names["alice"].status, NameStatus::Active);
        assert!(rewound.state.pending.contains_key(&abandoned_pending));
        assert_eq!(old_tip.tip.block_hash, [0xa3; 32]);
        let abandoned_root = old_tip.ironwood_checkpoint.root;

        rewound.rewind_to(101).unwrap();
        assert_eq!(snapshot(&rewound).0, ancestor.0);
        assert_eq!(snapshot(&rewound).1, ancestor.1);
        assert_eq!(snapshot(&rewound).2, ancestor.2);
        assert_eq!(snapshot(&rewound).3, ancestor.3);
        assert!(!rewound.has_rewind_snapshot(102));
        assert!(!rewound.has_rewind_snapshot(103));
        assert!(!rewound.state.pending.contains_key(&abandoned_pending));
        assert!(rewound.state.recent_spent.is_empty());

        install_reorg_reveal(&mut rewound, commitment, owner_pk, bond_tag, [0xb2; 32]);
        let replacement = rewound
            .apply_block(&block_with_effects(
                &rewound,
                103,
                [0xb3; 32],
                vec![nullifier],
                vec![],
            ))
            .unwrap();

        let mut fresh = reducer();
        install_reorg_common_history(&mut fresh, commitment);
        install_reorg_reveal(&mut fresh, commitment, owner_pk, bond_tag, [0xb2; 32]);
        let fresh_replacement = fresh
            .apply_block(&block_with_effects(
                &fresh,
                103,
                [0xb3; 32],
                vec![nullifier],
                vec![],
            ))
            .unwrap();

        assert_eq!(rewound.state, fresh.state);
        assert_eq!(rewound.ironwood_tree, fresh.ironwood_tree);
        assert_eq!(rewound.ironwood_checkpoints, fresh.ironwood_checkpoints);
        assert_eq!(rewound.tip, fresh.tip);
        assert_eq!(replacement.name_tree_root, fresh_replacement.name_tree_root);
        assert_eq!(replacement.pending_root, fresh_replacement.pending_root);
        assert_eq!(
            replacement.recent_spent_root,
            fresh_replacement.recent_spent_root
        );
        assert_eq!(replacement.state_root, fresh_replacement.state_root);

        let expected = &vector["vector"]["expected_after_replay"];
        assert_eq!(expected["status"], "BondSpent");
        assert_eq!(expected["terminal_height"], 103);
        assert_eq!(expected["sequence"], 0);
        assert_eq!(rewound.state.names["alice"].sequence, 0);
        assert_eq!(
            rewound.state.names["alice"].status,
            NameStatus::BondSpent {
                terminal_height: 103
            }
        );
        assert!(!rewound.state.active_bond_index().contains_key(&bond_tag));
        assert_eq!(rewound.state.recent_spent.get(&bond_tag), Some(&103));
        assert!(!rewound.state.recent_spent.contains_key(&abandoned_tag));
        assert!(!rewound.state.pending.contains_key(&abandoned_pending));
        assert_ne!(replacement.ironwood_checkpoint.root, abandoned_root);
        assert_eq!(rewound.history[&103].applied_tip.block_hash, [0xb3; 32]);
        assert!(
            rewound
                .history
                .values()
                .all(|undo| undo.applied_tip.block_hash != [0xa3; 32])
        );
    }

    #[test]
    fn invalid_rewinds_and_fatal_replacement_are_atomic() {
        let mut reducer = reducer();
        let deployment_before = reducer.deployment.clone();
        let deployment_id_before = reducer.deployment_id;
        let verifier_id_before = reducer.verifier.verifier_id();
        assert_eq!(reducer.oldest_rewind_height(), 99);
        reducer
            .apply_block(&empty_block_at(&reducer, 100, [0x10; 32]))
            .unwrap();
        reducer
            .apply_block(&empty_block_at(&reducer, 101, [0x11; 32]))
            .unwrap();
        let before = snapshot(&reducer);
        assert_eq!(reducer.rewind_to(101), Ok(()));
        assert_eq!(snapshot(&reducer), before);
        assert_eq!(reducer.rewind_to(98), Err(RewindError::BeforeActivation));
        assert_eq!(snapshot(&reducer), before);
        assert_eq!(reducer.rewind_to(102), Err(RewindError::BeyondTip));
        assert_eq!(snapshot(&reducer), before);
        let removed = reducer.history.remove(&101).unwrap();
        let missing_before = snapshot(&reducer);
        assert_eq!(reducer.rewind_to(100), Err(RewindError::SnapshotMissing));
        assert_eq!(snapshot(&reducer), missing_before);
        reducer.history.insert(101, removed);

        reducer.rewind_to(99).unwrap();
        assert_eq!(reducer.deployment, deployment_before);
        assert_eq!(reducer.deployment_id, deployment_id_before);
        assert_eq!(reducer.verifier.verifier_id(), verifier_id_before);
        let ancestor = snapshot(&reducer);
        let mut invalid = empty_block_at(&reducer, 100, [0x20; 32]);
        invalid.prev_block_hash = [0xff; 32];
        assert_eq!(
            reducer.apply_block(&invalid),
            Err(FatalReducerError::PredecessorMismatch)
        );
        assert_eq!(snapshot(&reducer), ancestor);
    }

    #[test]
    fn rewind_restores_active_index_and_replacement_spend_removes_it() {
        let mut reducer = reducer();
        let nullifier = canonical_nullifier();
        let tag = bond_tag::derive_v1_bond_tag(&nullifier).unwrap();
        let key = OwnerSigningKey::try_from([8; 32]).unwrap();
        semantic_block(&mut reducer, 100, [0x10; 32], |_, state| {
            let mut names = BTreeMap::new();
            names.insert(
                "alice".to_owned(),
                NameRecord {
                    owner_pk: owner_key_bytes(&(&key).into()),
                    bond_tag: tag,
                    sequence: 0,
                    address: canonical_ua(),
                    status: NameStatus::Active,
                },
            );
            *state = CoppiceState::from_authoritative_parts(
                names,
                pending::PendingCommitments::new(),
                recent_spent::RecentSpent::new(),
            )
            .unwrap();
        });
        reducer
            .apply_block(&block_with_effects(
                &reducer,
                101,
                [0x11; 32],
                vec![nullifier],
                vec![],
            ))
            .unwrap();
        assert!(!reducer.state.active_bond_index().contains_key(&tag));
        reducer.rewind_to(100).unwrap();
        assert_eq!(reducer.state.names["alice"].status, NameStatus::Active);
        assert_eq!(
            reducer
                .state
                .active_bond_index()
                .get(&tag)
                .map(String::as_str),
            Some("alice")
        );
        reducer
            .apply_block(&block_with_effects(
                &reducer,
                101,
                [0x21; 32],
                vec![nullifier],
                vec![],
            ))
            .unwrap();
        assert!(!reducer.state.active_bond_index().contains_key(&tag));
    }

    #[test]
    fn repeated_rewinds_remove_each_abandoned_suffix() {
        let mut reducer = reducer();
        for (height, byte) in [(100, 0x10), (101, 0x11), (102, 0x12)] {
            reducer
                .apply_block(&empty_block_at(&reducer, height, [byte; 32]))
                .unwrap();
        }
        reducer.rewind_to(101).unwrap();
        reducer
            .apply_block(&empty_block_at(&reducer, 102, [0x22; 32]))
            .unwrap();
        assert_eq!(reducer.history[&102].applied_tip.block_hash, [0x22; 32]);
        reducer.rewind_to(100).unwrap();
        for (height, byte) in [(101, 0x31), (102, 0x32)] {
            reducer
                .apply_block(&empty_block_at(&reducer, height, [byte; 32]))
                .unwrap();
        }
        assert_eq!(reducer.history.len(), 3);
        assert_eq!(reducer.history[&101].applied_tip.block_hash, [0x31; 32]);
        assert_eq!(reducer.history[&102].applied_tip.block_hash, [0x32; 32]);
        assert!(reducer.history.values().all(|undo| {
            ![[0x11; 32], [0x12; 32], [0x22; 32]].contains(&undo.applied_tip.block_hash)
        }));
    }

    #[test]
    fn protocol_rejection_after_rewind_still_snapshots_committed_block() {
        let mut reducer = reducer();
        let commitment = [0x71; 32];
        semantic_block(&mut reducer, 100, [0x10; 32], |_, state| {
            state
                .apply_prevalidated_commit(
                    commitment,
                    pending::ChainPosition {
                        block_height: 100,
                        tx_index: 0,
                    },
                )
                .unwrap();
        });
        reducer
            .apply_block(&empty_block_at(&reducer, 101, [0x11; 32]))
            .unwrap();
        reducer.rewind_to(100).unwrap();
        let mut staged = reducer.state.clone();
        assert_eq!(
            reducer
                .apply_operation(
                    &mut staged,
                    &reducer.ironwood_checkpoints,
                    101,
                    0,
                    &Operation::Commit { commitment },
                )
                .unwrap(),
            TransactionOutcome::Rejected(ProtocolRejection::DuplicateCommitment)
        );
        reducer.state = staged;
        let replacement_commitment = valid_commitment(4);
        reducer
            .apply_block(&block_with_effects(
                &reducer,
                101,
                [0x21; 32],
                vec![],
                vec![replacement_commitment],
            ))
            .unwrap();
        assert_eq!(reducer.tip.height, 101);
        assert!(reducer.has_rewind_snapshot(101));
        assert!(reducer.state.pending.contains_key(&commitment));
        assert_eq!(reducer.ironwood_tree.size(), 1);
        assert_eq!(reducer.ironwood_checkpoints[&101].tree_size, 1);
    }

    #[test]
    fn bounded_history_and_validated_snapshot_round_trip() {
        let mut reducer = reducer();
        for height in 100u32..=229 {
            let mut block_hash = [0u8; 32];
            block_hash[..4].copy_from_slice(&height.to_be_bytes());
            reducer
                .apply_block(&empty_block_at(&reducer, height, block_hash))
                .unwrap();
        }

        assert_eq!(reducer.reorg_retention_blocks(), 121);
        assert_eq!(reducer.history.len(), 121);
        assert_eq!(reducer.oldest_rewind_height(), 108);
        assert!(!reducer.has_rewind_snapshot(107));
        assert_eq!(reducer.rewind_to(107), Err(RewindError::SnapshotMissing));

        let encoded = reducer.save_snapshot().unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(stored.get("snapshots").is_none());
        assert_eq!(stored["undo"].as_array().unwrap().len(), 121);
        assert!(stored["undo"].as_array().unwrap().iter().all(|undo| {
            undo["state"]["names"].as_array().unwrap().is_empty()
                && undo["state"]["pending"].as_array().unwrap().is_empty()
                && undo["state"]["recent_spent"].as_array().unwrap().is_empty()
        }));
        let restored = Reducer::load_snapshot(deployment(), &encoded).unwrap();
        assert_eq!(restored.tip(), reducer.tip());
        assert_eq!(restored.state(), reducer.state());
        assert_eq!(restored.ironwood_frontier(), reducer.ironwood_frontier());
        assert_eq!(
            restored.ironwood_checkpoints(),
            reducer.ironwood_checkpoints()
        );
        assert_eq!(restored.oldest_rewind_height(), 108);
        assert_eq!(restored.history.len(), 121);
    }

    #[test]
    fn phase6_retained_reorg_and_deep_rebuild_are_deterministic() {
        let retention = reducer().reorg_retention_blocks();
        assert_eq!(retention, 121);

        // The first branch exercises a shallow fork after a realistic state
        // prefix. Rewinding to height 225 is inside the configured horizon.
        let mut prefix = reducer();
        phase6_common_prefix(&mut prefix);
        let prefix_snapshot = prefix.save_snapshot().unwrap();

        let mut shared = Reducer::load_snapshot(deployment(), &prefix_snapshot).unwrap();
        phase6_apply_shared_suffix(&mut shared);
        let shared_snapshot = shared.save_snapshot().unwrap();

        let mut old_within = Reducer::load_snapshot(deployment(), &shared_snapshot).unwrap();
        phase6_apply_divergent_suffix(&mut old_within, 1);
        let old_within_tip = old_within.tip();

        let mut rewound = Reducer::load_snapshot(deployment(), &shared_snapshot).unwrap();
        phase6_apply_divergent_suffix(&mut rewound, 1);
        assert!(rewound.has_rewind_snapshot(225));
        rewound.rewind_to(225).unwrap();
        phase6_apply_divergent_suffix(&mut rewound, 2);

        let mut shallow_fresh = Reducer::load_snapshot(deployment(), &shared_snapshot).unwrap();
        phase6_apply_divergent_suffix(&mut shallow_fresh, 2);
        assert_eq!(
            rewound.save_snapshot().unwrap(),
            shallow_fresh.save_snapshot().unwrap()
        );
        assert_eq!(rewound.state_root, shallow_fresh.state_root);
        assert_eq!(rewound.ironwood_tree, shallow_fresh.ironwood_tree);
        assert_eq!(
            rewound.ironwood_checkpoints,
            shallow_fresh.ironwood_checkpoints
        );
        assert_eq!(rewound.tip, shallow_fresh.tip);
        assert_ne!(old_within_tip.block_hash, rewound.tip.block_hash);

        // Extend a different old branch beyond the retained undo horizon and
        // prove that the failed rewind is observationally atomic.
        let mut unrecoverable = Reducer::load_snapshot(deployment(), &prefix_snapshot).unwrap();
        phase6_apply_long_suffix(&mut unrecoverable, 1);
        assert_eq!(unrecoverable.tip().height - prefix.tip().height, 135);
        assert!(unrecoverable.tip().height - prefix.tip().height > retention);
        assert!(prefix.tip().height < unrecoverable.oldest_rewind_height());
        let before_failed_rewind = unrecoverable.save_snapshot().unwrap();
        assert_eq!(
            unrecoverable.rewind_to(prefix.tip().height),
            Err(RewindError::SnapshotMissing)
        );
        assert_eq!(unrecoverable.save_snapshot().unwrap(), before_failed_rewind);

        // The local state is now discarded. Both reducers below start from
        // the frozen activation checkpoint and independently replay the same
        // replacement chain; byte equality covers the retained journal as
        // well as current state, roots, checkpoints, frontier, and tip.
        drop(unrecoverable);
        let mut rebuilt = reducer();
        phase6_common_prefix(&mut rebuilt);
        phase6_apply_long_suffix(&mut rebuilt, 2);
        let mut clean = reducer();
        phase6_common_prefix(&mut clean);
        phase6_apply_long_suffix(&mut clean, 2);

        assert_phase6_replacement_state(&rebuilt, 2);
        assert_eq!(
            rebuilt.save_snapshot().unwrap(),
            clean.save_snapshot().unwrap()
        );
        assert_eq!(rebuilt.state_root, clean.state_root);
        assert_eq!(rebuilt.state, clean.state);
        assert_eq!(rebuilt.ironwood_tree, clean.ironwood_tree);
        assert_eq!(rebuilt.ironwood_checkpoints, clean.ironwood_checkpoints);
        assert_eq!(rebuilt.tip, clean.tip);
        assert_eq!(rebuilt.history, clean.history);
    }

    #[test]
    fn snapshot_rejects_wrong_deployment_and_tampered_state_root() {
        let mut reducer = reducer();
        reducer
            .apply_block(&empty_block_at(&reducer, 100, [0x10; 32]))
            .unwrap();
        let encoded = reducer.save_snapshot().unwrap();

        let mut old_format: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        old_format["format_version"] = serde_json::Value::from(2);
        assert!(matches!(
            Reducer::load_snapshot(deployment(), &serde_json::to_vec(&old_format).unwrap()),
            Err(SnapshotError::UnsupportedFormat)
        ));

        let mut wrong_deployment = deployment();
        wrong_deployment.network_id.push(0x42);
        assert!(matches!(
            Reducer::load_snapshot(wrong_deployment, &encoded),
            Err(SnapshotError::DeploymentMismatch)
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["current"]["state_root"] =
            serde_json::Value::Array(vec![serde_json::Value::from(0); 32]);
        assert!(matches!(
            Reducer::load_snapshot(deployment(), &serde_json::to_vec(&value).unwrap()),
            Err(SnapshotError::StateRootMismatch)
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["current"]["ironwood_checkpoints"][0]["root"][0] = serde_json::Value::from(1);
        assert!(matches!(
            Reducer::load_snapshot(deployment(), &serde_json::to_vec(&value).unwrap()),
            Err(SnapshotError::InvalidCheckpoint)
        ));
    }

    #[test]
    fn snapshot_authenticates_oldest_still_usable_checkpoint() {
        let mut reducer = reducer();
        for height in 100u32..=229 {
            let mut block_hash = [0u8; 32];
            block_hash[..4].copy_from_slice(&height.to_be_bytes());
            reducer
                .apply_block(&empty_block_at(&reducer, height, block_hash))
                .unwrap();
        }
        let oldest_checkpoint = *reducer.ironwood_checkpoints().first_key_value().unwrap().0;
        assert_eq!(oldest_checkpoint, 109);
        assert!(reducer.has_rewind_snapshot(oldest_checkpoint));

        let mut stored: serde_json::Value =
            serde_json::from_slice(&reducer.save_snapshot().unwrap()).unwrap();
        let checkpoints = stored["current"]["ironwood_checkpoints"]
            .as_array_mut()
            .unwrap();
        assert_eq!(
            checkpoints[0]["height"].as_u64(),
            Some(u64::from(oldest_checkpoint))
        );
        checkpoints[0]["root"][0] = serde_json::Value::from(1);
        assert!(matches!(
            Reducer::load_snapshot(deployment(), &serde_json::to_vec(&stored).unwrap()),
            Err(SnapshotError::StateRootMismatch | SnapshotError::InvalidCheckpoint)
        ));
    }
}
