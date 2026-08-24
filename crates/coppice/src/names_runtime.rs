//! Additive Coppice Names v1 application replay over generic Core context.
//!
//! This module is not production authority yet. It deliberately decodes the
//! existing naked Names CPV1 carrier so differential tests can establish exact
//! equivalence before application-envelope routing is enabled.

use crate::{
    authorization,
    bond::V1BondVerifier,
    bond_tag, carrier,
    config::{DeploymentParameters, DeploymentValidationError},
    envelope::Operation,
    names_application::{NamesDeploymentId, names_v1_application_descriptor},
    pending, recent_spent,
    record::NameStatus,
    reveal::{self, AuthenticatedIronwoodCheckpoint, RevealValidationError},
    state::{CoppiceState, StateMutationError},
    state_root::{self, StateRootInput},
};
use coppice_core::{
    application::{ApplicationDescriptor, ApplicationTip, CoppiceApplication},
    replay::{
        CandidateTransactionStatus, CoreBlockContext, CoreCanonicalBlockInput,
        CoreIronwoodCheckpoint, CoreReplay, CoreReplayError, CoreRewindError,
    },
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesProtocolRejection {
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
pub enum NamesTransactionOutcome {
    NoOperation,
    Applied,
    Rejected(NamesProtocolRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesAppliedBlock {
    pub tip: ApplicationTip,
    pub name_tree_root: [u8; 32],
    pub pending_root: [u8; 32],
    pub recent_spent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub transaction_outcomes: Vec<NamesTransactionOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesApplicationError {
    NonSequentialHeight,
    PredecessorMismatch,
    MissingRequiredCheckpoint,
    StateInvariantFailure,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesRewindError {
    BeforeActivation,
    BeyondTip,
    SnapshotMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesRuntimeInitializationError {
    InvalidDeployment(DeploymentValidationError),
    ActivationMismatch,
    InitialTipMismatch,
    InitialCheckpointMismatch,
    CoreRetentionMismatch,
    ArithmeticOverflow,
    StateInvariantFailure,
    VerifierInitializationFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesRuntimeError {
    Core(CoreReplayError),
    Names(NamesApplicationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesRuntimeRewindError {
    Core(CoreRewindError),
    Names(NamesRewindError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesRuntimeAppliedBlock {
    pub core: CoreBlockContext,
    pub names: NamesAppliedBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NamesStateUndo {
    names: Vec<(String, Option<crate::record::NameRecord>)>,
    pending: Vec<([u8; 32], Option<pending::ChainPosition>)>,
    recent_spent: Vec<([u8; 32], Option<u32>)>,
}

impl NamesStateUndo {
    fn between(before: &CoppiceState, after: &CoppiceState) -> Self {
        Self {
            names: map_undo(&before.names, &after.names),
            pending: map_undo(&before.pending, &after.pending),
            recent_spent: map_undo(&before.recent_spent, &after.recent_spent),
        }
    }

    fn apply_to(&self, state: &CoppiceState) -> Result<CoppiceState, NamesRewindError> {
        let mut names = state.names.clone();
        let mut pending = state.pending.clone();
        let mut recent_spent = state.recent_spent.clone();
        apply_map_undo(&mut names, &self.names);
        apply_map_undo(&mut pending, &self.pending);
        apply_map_undo(&mut recent_spent, &self.recent_spent);
        CoppiceState::from_authoritative_parts(names, pending, recent_spent)
            .map_err(|_| NamesRewindError::SnapshotMissing)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NamesUndo {
    applied_tip: ApplicationTip,
    prior_tip: ApplicationTip,
    state: NamesStateUndo,
    prior_state_root: [u8; 32],
}

/// Names-specific deterministic state machine. It consumes Core contexts but
/// neither owns canonical Zcash replay nor selects a fork.
pub struct NamesApplication {
    deployment: DeploymentParameters,
    deployment_id: NamesDeploymentId,
    descriptor: ApplicationDescriptor,
    state: CoppiceState,
    tip: ApplicationTip,
    state_root: [u8; 32],
    verifier: V1BondVerifier,
    retention_blocks: u32,
    history: BTreeMap<u32, NamesUndo>,
}

impl NamesApplication {
    fn new(
        deployment: DeploymentParameters,
        core: &CoreReplay,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        let deployment_id = NamesDeploymentId::from_bytes(
            deployment
                .validate()
                .map_err(NamesRuntimeInitializationError::InvalidDeployment)?,
        );
        if deployment.activation_height != core.configuration().activation_height() {
            return Err(NamesRuntimeInitializationError::ActivationMismatch);
        }
        let activation_checkpoint_height = deployment
            .activation_height
            .checked_sub(1)
            .ok_or(NamesRuntimeInitializationError::ArithmeticOverflow)?;
        let core_tip = core.tip();
        if core_tip.height != activation_checkpoint_height {
            return Err(NamesRuntimeInitializationError::InitialTipMismatch);
        }
        let checkpoint = core
            .ironwood_checkpoints()
            .get(&activation_checkpoint_height)
            .copied()
            .ok_or(NamesRuntimeInitializationError::InitialCheckpointMismatch)?;
        if checkpoint.tree_size as usize != core.ironwood_frontier().size()
            || checkpoint.root != core.ironwood_frontier().root().to_bytes()
        {
            return Err(NamesRuntimeInitializationError::InitialCheckpointMismatch);
        }
        let retention_blocks = names_v1_replay_retention_blocks(&deployment)?;
        if core.configuration().retention_blocks() != retention_blocks {
            return Err(NamesRuntimeInitializationError::CoreRetentionMismatch);
        }
        let tip = ApplicationTip {
            height: core_tip.height,
            block_hash: core_tip.block_hash,
        };
        let state = CoppiceState::default();
        let state_root = calculate_state_root(&deployment, deployment_id, &state, tip, checkpoint)?;
        let verifier = V1BondVerifier::new()
            .map_err(|_| NamesRuntimeInitializationError::VerifierInitializationFailure)?;
        Ok(Self {
            descriptor: names_v1_application_descriptor(deployment.activation_height),
            deployment,
            deployment_id,
            state,
            tip,
            state_root,
            verifier,
            retention_blocks,
            history: BTreeMap::new(),
        })
    }

    pub fn deployment(&self) -> &DeploymentParameters {
        &self.deployment
    }

    pub fn deployment_id(&self) -> NamesDeploymentId {
        self.deployment_id
    }

    pub fn state(&self) -> &CoppiceState {
        &self.state
    }

    pub fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first_key_value()
            .map_or(self.tip.height, |(_, undo)| undo.prior_tip.height)
    }

    pub fn has_rewind_snapshot(&self, height: u32) -> bool {
        height == self.tip.height
            || (height >= self.oldest_rewind_height() && height < self.tip.height)
    }

    pub fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        if height == self.tip.height {
            Some(self.tip)
        } else {
            height
                .checked_add(1)
                .and_then(|next| self.history.get(&next))
                .map(|undo| undo.prior_tip)
        }
    }

    fn apply_operation(
        &self,
        state: &mut CoppiceState,
        block: &CoreBlockContext,
        tx_index: u32,
        operation: &Operation,
    ) -> Result<NamesTransactionOutcome, NamesApplicationError> {
        let rejection = match operation {
            Operation::Commit { commitment } => match state.apply_prevalidated_commit(
                *commitment,
                pending::ChainPosition {
                    block_height: block.height(),
                    tx_index,
                },
            ) {
                Ok(()) => return Ok(NamesTransactionOutcome::Applied),
                Err(StateMutationError::DuplicateCommitment) => {
                    NamesProtocolRejection::DuplicateCommitment
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
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidName,
                    ));
                }
                if crate::owner::parse_v1_owner_key(*owner_pk).is_err() {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidOwnerKey,
                    ));
                }
                if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidAddress,
                    ));
                }
                if bond_proof.len() > reveal::MAX_BOND_PROOF_LEN {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::OversizedProof,
                    ));
                }
                let commitment = reveal_commitment(&self.deployment, operation)
                    .ok_or(NamesApplicationError::StateInvariantFailure)?;
                let Some(committed_at) = state.pending.get(&commitment).copied() else {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::UnknownCommitment,
                    ));
                };
                if *bond_anchor_height < committed_at.block_height
                    || *bond_anchor_height >= block.height()
                {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidBondAnchorHeight,
                    ));
                }
                let anchor = block
                    .prior_ironwood_checkpoint(*bond_anchor_height)
                    .map(authenticated_checkpoint)
                    .ok_or(NamesApplicationError::MissingRequiredCheckpoint)?;
                let floor_height = (self.deployment.activation_height - 1).max(
                    committed_at
                        .block_height
                        .saturating_sub(self.deployment.bond_note_max_age_blocks),
                );
                let floor = block
                    .prior_ironwood_checkpoint(floor_height)
                    .map(authenticated_checkpoint)
                    .ok_or(NamesApplicationError::MissingRequiredCheckpoint)?;
                match reveal::validate_v1_reveal(
                    state,
                    &self.deployment,
                    block.height(),
                    anchor,
                    floor,
                    &self.verifier,
                    operation,
                ) {
                    Ok(validated) => {
                        state
                            .apply_prevalidated_reveal(validated)
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
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
                    NamesProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(NamesTransactionOutcome::Rejected(
                            NamesProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        NamesProtocolRejection::NameUnavailable
                    } else if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                        NamesProtocolRejection::InvalidAddress
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        NamesProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(
                        self.deployment_id.to_bytes(),
                        operation,
                        current,
                    ) {
                        NamesProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_update(name, *sequence, address.clone())
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
                    }
                }
            }
            Operation::Release { name, sequence, .. } => {
                if !crate::envelope::valid_name(name) {
                    NamesProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(NamesTransactionOutcome::Rejected(
                            NamesProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        NamesProtocolRejection::NameUnavailable
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        NamesProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(
                        self.deployment_id.to_bytes(),
                        operation,
                        current,
                    ) {
                        NamesProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_release(name, *sequence, block.height())
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
                    }
                }
            }
        };
        Ok(NamesTransactionOutcome::Rejected(rejection))
    }
}

impl CoppiceApplication for NamesApplication {
    type BlockOutput = NamesAppliedBlock;
    type ApplyError = NamesApplicationError;
    type RewindError = NamesRewindError;

    fn descriptor(&self) -> ApplicationDescriptor {
        self.descriptor
    }

    fn tip(&self) -> ApplicationTip {
        self.tip
    }

    fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    fn apply_block(
        &mut self,
        block: &CoreBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        if self.tip.height.checked_add(1) != Some(block.height()) {
            return Err(NamesApplicationError::NonSequentialHeight);
        }
        if self.tip.block_hash != block.prev_block_hash() {
            return Err(NamesApplicationError::PredecessorMismatch);
        }

        let mut state = self.state.clone();
        let mut transaction_outcomes = Vec::with_capacity(block.transactions().len());
        for transaction in block.transactions() {
            for nullifier in transaction.ironwood_effects().nullifiers() {
                let bond_tag = bond_tag::derive_v1_bond_tag(nullifier)
                    .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
                state
                    .process_prevalidated_bond_tag(bond_tag, block.height())
                    .map_err(map_state_fatal)?;
            }
            let outcome = match transaction.candidate_status() {
                CandidateTransactionStatus::NotCandidate => NamesTransactionOutcome::NoOperation,
                CandidateTransactionStatus::ValidatedFullTransaction(validated) => {
                    match carrier_semantic(carrier::decode_v1_bulletin_for(
                        validated.transaction(),
                        self.deployment.rendezvous,
                        self.deployment_id.to_bytes(),
                    ))? {
                        NamesCarrierSemantic::Operation(operation) => self.apply_operation(
                            &mut state,
                            block,
                            transaction.tx_index(),
                            &operation,
                        )?,
                        NamesCarrierSemantic::NoOperation => NamesTransactionOutcome::NoOperation,
                        NamesCarrierSemantic::Rejected(rejection) => {
                            NamesTransactionOutcome::Rejected(rejection)
                        }
                    }
                }
            };
            transaction_outcomes.push(outcome);
        }

        state
            .expire_pending_at_end_of_block(block.height(), self.deployment.commit_ttl_blocks)
            .map_err(map_state_fatal)?;
        let (oldest_retained_height, _) = state
            .prune_recent_spent_at_end_of_block(
                self.deployment.activation_height,
                block.height(),
                self.deployment.bond_note_max_age_blocks,
                self.deployment.commit_ttl_blocks,
            )
            .map_err(map_state_fatal)?;
        let name_tree_root = state
            .name_tree_root()
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let pending_root = state
            .pending_root()
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let recent_spent_root = state
            .recent_spent_root(oldest_retained_height)
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let checkpoint = block.ironwood_checkpoint();
        let state_root = state_root::state_root(&StateRootInput {
            deployment_id: self.deployment_id.to_bytes(),
            height: block.height(),
            block_hash: block.block_hash(),
            ironwood_tree_size: checkpoint.tree_size,
            ironwood_root: checkpoint.root,
            name_tree_root,
            pending_root,
            recent_spent_root,
        })
        .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let tip = ApplicationTip {
            height: block.height(),
            block_hash: block.block_hash(),
        };
        let undo = NamesUndo {
            applied_tip: tip,
            prior_tip: self.tip,
            state: NamesStateUndo::between(&self.state, &state),
            prior_state_root: self.state_root,
        };

        self.state = state;
        self.tip = tip;
        self.state_root = state_root;
        self.history.insert(block.height(), undo);
        let oldest_undo = block
            .height()
            .saturating_sub(self.retention_blocks)
            .saturating_add(1);
        self.history.retain(|height, _| *height >= oldest_undo);

        Ok(NamesAppliedBlock {
            tip,
            name_tree_root,
            pending_root,
            recent_spent_root,
            state_root,
            transaction_outcomes,
        })
    }

    fn rewind_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        let activation_checkpoint_height = self.deployment.activation_height - 1;
        if height < activation_checkpoint_height {
            return Err(NamesRewindError::BeforeActivation);
        }
        if height > self.tip.height {
            return Err(NamesRewindError::BeyondTip);
        }
        if height < self.oldest_rewind_height() {
            return Err(NamesRewindError::SnapshotMissing);
        }

        let mut state = self.state.clone();
        let mut tip = self.tip;
        let mut state_root = self.state_root;
        let mut history = self.history.clone();
        while tip.height > height {
            let undo = history
                .remove(&tip.height)
                .ok_or(NamesRewindError::SnapshotMissing)?;
            if tip != undo.applied_tip {
                return Err(NamesRewindError::SnapshotMissing);
            }
            state = undo.state.apply_to(&state)?;
            tip = undo.prior_tip;
            state_root = undo.prior_state_root;
        }
        self.state = state;
        self.tip = tip;
        self.state_root = state_root;
        self.history = history;
        Ok(())
    }
}

/// Additive composite used only to prove that generic Core replay plus the
/// first application reproduces the monolithic reducer.
pub struct NamesRuntime {
    core: CoreReplay,
    names: NamesApplication,
}

impl NamesRuntime {
    pub fn new(
        core: CoreReplay,
        deployment: DeploymentParameters,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        let names = NamesApplication::new(deployment, &core)?;
        Ok(Self { core, names })
    }

    pub fn core(&self) -> &CoreReplay {
        &self.core
    }

    pub fn names(&self) -> &NamesApplication {
        &self.names
    }

    pub fn apply_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<NamesRuntimeAppliedBlock, NamesRuntimeError> {
        let mut staged_core = self.core.clone();
        let core = staged_core
            .apply_block(block)
            .map_err(NamesRuntimeError::Core)?;
        let names = self
            .names
            .apply_block(&core)
            .map_err(NamesRuntimeError::Names)?;
        self.core = staged_core;
        Ok(NamesRuntimeAppliedBlock { core, names })
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), NamesRuntimeRewindError> {
        let mut staged_core = self.core.clone();
        staged_core
            .rewind_to(height)
            .map_err(NamesRuntimeRewindError::Core)?;
        self.names
            .rewind_to(height)
            .map_err(NamesRuntimeRewindError::Names)?;
        self.core = staged_core;
        Ok(())
    }
}

pub fn names_v1_replay_retention_blocks(
    deployment: &DeploymentParameters,
) -> Result<u32, NamesRuntimeInitializationError> {
    deployment
        .bond_note_max_age_blocks
        .checked_add(deployment.commit_ttl_blocks)
        .and_then(|value| value.checked_add(1))
        .ok_or(NamesRuntimeInitializationError::ArithmeticOverflow)
}

#[allow(clippy::large_enum_variant)]
enum NamesCarrierSemantic {
    NoOperation,
    Rejected(NamesProtocolRejection),
    Operation(Operation),
}

fn carrier_semantic(
    result: Result<Operation, carrier::V1CarrierError>,
) -> Result<NamesCarrierSemantic, NamesApplicationError> {
    match result {
        Ok(operation) => Ok(NamesCarrierSemantic::Operation(operation)),
        Err(carrier::V1CarrierError::NotFound) => Ok(NamesCarrierSemantic::NoOperation),
        Err(carrier::V1CarrierError::Malformed) => Ok(NamesCarrierSemantic::Rejected(
            NamesProtocolRejection::MalformedCarrier,
        )),
        Err(carrier::V1CarrierError::Build) => Err(NamesApplicationError::StateInvariantFailure),
    }
}

fn reveal_commitment(deployment: &DeploymentParameters, operation: &Operation) -> Option<[u8; 32]> {
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

fn authenticated_checkpoint(checkpoint: CoreIronwoodCheckpoint) -> AuthenticatedIronwoodCheckpoint {
    AuthenticatedIronwoodCheckpoint {
        height: checkpoint.height,
        root: checkpoint.root,
        tree_size: checkpoint.tree_size,
    }
}

fn calculate_state_root(
    deployment: &DeploymentParameters,
    deployment_id: NamesDeploymentId,
    state: &CoppiceState,
    tip: ApplicationTip,
    checkpoint: CoreIronwoodCheckpoint,
) -> Result<[u8; 32], NamesRuntimeInitializationError> {
    let oldest_retained_height = recent_spent::oldest_retained_height(
        deployment.activation_height,
        tip.height,
        deployment.bond_note_max_age_blocks,
        deployment.commit_ttl_blocks,
    )
    .map_err(|_| NamesRuntimeInitializationError::ArithmeticOverflow)?;
    let name_tree_root = state
        .name_tree_root()
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    let pending_root = state
        .pending_root()
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    let recent_spent_root = state
        .recent_spent_root(oldest_retained_height)
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    state_root::state_root(&StateRootInput {
        deployment_id: deployment_id.to_bytes(),
        height: tip.height,
        block_hash: tip.block_hash,
        ironwood_tree_size: checkpoint.tree_size,
        ironwood_root: checkpoint.root,
        name_tree_root,
        pending_root,
        recent_spent_root,
    })
    .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)
}

fn map_state_fatal(_error: StateMutationError) -> NamesApplicationError {
    NamesApplicationError::StateInvariantFailure
}

fn map_reveal_rejection(
    error: RevealValidationError,
) -> Result<NamesProtocolRejection, NamesApplicationError> {
    Ok(match error {
        RevealValidationError::InvalidName => NamesProtocolRejection::InvalidName,
        RevealValidationError::InvalidOwnerKey => NamesProtocolRejection::InvalidOwnerKey,
        RevealValidationError::InvalidAddress
        | RevealValidationError::WrongAddressNetwork
        | RevealValidationError::NonCanonicalAddress
        | RevealValidationError::AddressTooLong => NamesProtocolRejection::InvalidAddress,
        RevealValidationError::CommitmentNotPending => NamesProtocolRejection::UnknownCommitment,
        RevealValidationError::CommitmentNotMature => NamesProtocolRejection::CommitmentNotMature,
        RevealValidationError::CommitmentExpired => NamesProtocolRejection::CommitmentExpired,
        RevealValidationError::NameNotClaimable => NamesProtocolRejection::NameUnavailable,
        RevealValidationError::CommitPredatesClaimability => {
            NamesProtocolRejection::CommitPredatesClaimEpoch
        }
        RevealValidationError::BondAlreadySpent => NamesProtocolRejection::BondRecentlySpent,
        RevealValidationError::BondAlreadyInUse => NamesProtocolRejection::BondAlreadyInUse,
        RevealValidationError::InvalidAnchorHeight => {
            NamesProtocolRejection::InvalidBondAnchorHeight
        }
        RevealValidationError::AnchorCheckpointMismatch
        | RevealValidationError::FreshnessCheckpointMismatch => {
            NamesProtocolRejection::UnknownBondAnchor
        }
        RevealValidationError::ProofTooLarge => NamesProtocolRejection::OversizedProof,
        RevealValidationError::InvalidPublicInput | RevealValidationError::InvalidProof => {
            NamesProtocolRejection::InvalidBondProof
        }
        RevealValidationError::UnsupportedOperation => NamesProtocolRejection::MalformedOperation,
        RevealValidationError::DeploymentEncoding(_)
        | RevealValidationError::VerifierIdentityMismatch => {
            return Err(NamesApplicationError::StateInvariantFailure);
        }
        RevealValidationError::ArithmeticOverflow => {
            return Err(NamesApplicationError::ArithmeticOverflow);
        }
    })
}

fn map_undo<K: Ord + Clone, V: Clone + PartialEq>(
    before: &BTreeMap<K, V>,
    after: &BTreeMap<K, V>,
) -> Vec<(K, Option<V>)> {
    before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
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
