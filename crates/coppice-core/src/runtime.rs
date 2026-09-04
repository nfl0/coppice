//! Generic application-envelope routing over canonical Core replay.

use crate::{
    application::{
        ApplicationActivationError, ApplicationBlockContext, ApplicationDescriptor,
        ApplicationEnvelope, ApplicationEnvelopeError, ApplicationTip,
        ApplicationTransactionContext, CanonicalCompactTransactionSummary,
    },
    carrier::CoreRendezvous,
    identity::{CoreRuntimeId, ValidatedCoreRuntimeParameters},
    replay::{
        CoreBlockContext, CoreCanonicalBlockInput, CoreIronwoodCheckpoint, CorePositionReplay,
        CorePositionedBlockContext, CoreReplay, CoreReplayConfiguration, CoreReplayError,
        CoreReplayPositionCheckpoint, CoreReplaySnapshotError, CoreReplayTip, CoreRewindError,
        FullTransactionAcquisition, FullTransactionStatus, IronwoodFrontier,
    },
    transport,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRuntimeConfigurationError {
    ActivationMismatch,
}

pub const CORE_RUNTIME_SNAPSHOT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRuntimeSnapshotError {
    Encoding,
    UnsupportedFormat,
    RuntimeMismatch,
    Replay(CoreReplaySnapshotError),
    Configuration(CoreRuntimeConfigurationError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredCoreRuntime {
    format_version: u32,
    runtime_id: [u8; 32],
    replay: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplicationMessageStatus {
    NotCandidate,
    NoMessage,
    MalformedTransport(transport::Error),
    MalformedEnvelope(ApplicationEnvelopeError),
    Message(ApplicationEnvelope),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTransactionContext {
    core_index: usize,
    message: ApplicationMessageStatus,
}

/// Read-only inspection of one transaction at the configured public
/// rendezvous. This is also used by transaction builders to prove that the
/// bytes they constructed are exactly the bytes Core will route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTransactionInspection {
    frames: Box<[[u8; 512]]>,
    routed_frames: Box<[RoutedFrame]>,
    message: ApplicationMessageStatus,
}

/// One carrier frame decrypted at an exact caller-supplied rendezvous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutedFrame {
    pub action_index: u32,
    pub value: u64,
    pub memo: [u8; 512],
}

impl RuntimeTransactionInspection {
    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }

    pub fn routed_frames(&self) -> &[RoutedFrame] {
        &self.routed_frames
    }

    pub fn message(&self) -> &ApplicationMessageStatus {
        &self.message
    }
}

impl RuntimeTransactionContext {
    pub fn core_index(&self) -> usize {
        self.core_index
    }

    pub fn message(&self) -> &ApplicationMessageStatus {
        &self.message
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlockContext {
    core: CoreBlockContext,
    transactions: Box<[RuntimeTransactionContext]>,
    runtime_activation_height: u32,
}

/// Routed block output for a host-owned commitment tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionedRuntimeBlockContext {
    core: CorePositionedBlockContext,
    transactions: Box<[RuntimeTransactionContext]>,
}

impl PositionedRuntimeBlockContext {
    pub fn core(&self) -> &CorePositionedBlockContext {
        &self.core
    }
    pub fn transactions(&self) -> &[RuntimeTransactionContext] {
        &self.transactions
    }
}

impl RuntimeBlockContext {
    pub fn core(&self) -> &CoreBlockContext {
        &self.core
    }

    pub fn transactions(&self) -> &[RuntimeTransactionContext] {
        &self.transactions
    }

    pub fn ironwood_checkpoint(&self) -> CoreIronwoodCheckpoint {
        self.core.ironwood_checkpoint()
    }

    /// Creates an application-scoped view of this block. The view is the only
    /// supported application lifecycle boundary: before the descriptor's
    /// activation height, Core metadata remains available only as a position
    /// while effects and routed messages are withheld.
    pub fn for_application(
        &self,
        descriptor: ApplicationDescriptor,
    ) -> Result<ApplicationBlockContext, ApplicationActivationError> {
        descriptor.validate_for_runtime(self.runtime_activation_height)?;
        let active = self.core.height() >= descriptor.activation_height;
        let transactions = if active {
            self.core
                .transactions()
                .iter()
                .zip(self.transactions.iter())
                .map(|(core, routed)| {
                    let payload = match routed.message() {
                        ApplicationMessageStatus::Message(message)
                            if message.key() == descriptor.key =>
                        {
                            Some(message.payload().to_vec().into_boxed_slice())
                        }
                        _ => None,
                    };
                    ApplicationTransactionContext::new(core.clone(), payload)
                })
                .collect::<Vec<_>>()
                .into_boxed_slice()
        } else {
            Box::new([])
        };
        Ok(ApplicationBlockContext {
            tip: ApplicationTip {
                height: self.core.height(),
                block_hash: self.core.block_hash(),
            },
            core: active.then(|| self.core.clone()),
            transactions,
            active,
        })
    }
}

/// Host-facing canonical runtime boundary used by generic CompactBlock
/// ingestion and reconciliation. Implementations may compose application
/// state above Core, but this trait exposes no application-specific concepts.
pub trait CanonicalRuntime {
    type BlockOutput;
    type ApplyError: Debug;
    type RewindError: Debug;

    fn core_parameters(&self) -> &ValidatedCoreRuntimeParameters;
    fn rendezvous(&self) -> &CoreRendezvous;
    fn tip(&self) -> CoreReplayTip;
    fn oldest_rewind_height(&self) -> u32;
    fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip>;

    /// Returns the complete deterministic acquisition requirement for one
    /// compact canonical transaction. Core carrier candidacy is always taken
    /// from the summary; composed runtimes additionally union active
    /// applications' read-only extended-effect requests.
    fn full_transaction_acquisition(
        &self,
        summary: &CanonicalCompactTransactionSummary<'_>,
    ) -> FullTransactionAcquisition {
        FullTransactionAcquisition::new(summary.rendezvous_candidate, false)
    }

    fn apply_canonical_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError>;
    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError>;
}

#[derive(Clone)]
pub struct CoreRuntime {
    parameters: ValidatedCoreRuntimeParameters,
    runtime_id: CoreRuntimeId,
    rendezvous: CoreRendezvous,
    replay: CoreReplay,
}

/// A Core change prepared against one exact base tip but not yet published.
///
/// Hosts persist [`Self::runtime`] inside their outer storage transaction. Once
/// that transaction commits, [`CoreRuntime::publish_staged`] performs the
/// infallible in-memory handoff under exclusive host ownership.
#[derive(Clone)]
pub struct StagedCoreChange<O> {
    base_tip: CoreReplayTip,
    runtime: CoreRuntime,
    output: O,
}

impl<O> StagedCoreChange<O> {
    pub fn base_tip(&self) -> CoreReplayTip {
        self.base_tip
    }

    pub fn runtime(&self) -> &CoreRuntime {
        &self.runtime
    }

    pub fn output(&self) -> &O {
        &self.output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedCorePublishError {
    BaseTipChanged,
}

impl CoreRuntime {
    pub fn new(
        parameters: ValidatedCoreRuntimeParameters,
        replay: CoreReplay,
    ) -> Result<Self, CoreRuntimeConfigurationError> {
        if parameters.parameters().runtime_activation_height
            != replay.configuration().activation_height()
        {
            return Err(CoreRuntimeConfigurationError::ActivationMismatch);
        }
        let runtime_id = parameters.core_runtime_id();
        let rendezvous = CoreRendezvous::from_validated(&parameters);
        Ok(Self {
            parameters,
            runtime_id,
            rendezvous,
            replay,
        })
    }

    pub fn parameters(&self) -> &ValidatedCoreRuntimeParameters {
        &self.parameters
    }

    pub fn runtime_id(&self) -> CoreRuntimeId {
        self.runtime_id
    }

    pub fn rendezvous(&self) -> &CoreRendezvous {
        &self.rendezvous
    }

    pub fn replay(&self) -> &CoreReplay {
        &self.replay
    }

    pub fn configuration(&self) -> CoreReplayConfiguration {
        self.replay.configuration()
    }

    pub fn ironwood_frontier(&self) -> &IronwoodFrontier {
        self.replay.ironwood_frontier()
    }

    pub fn ironwood_checkpoints(&self) -> &std::collections::BTreeMap<u32, CoreIronwoodCheckpoint> {
        self.replay.ironwood_checkpoints()
    }

    pub fn oldest_rewind_height(&self) -> u32 {
        self.replay.oldest_rewind_height()
    }

    pub fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        self.replay.retained_tip_at(height)
    }

    pub fn has_rewind_snapshot(&self, height: u32) -> bool {
        self.replay.has_rewind_snapshot(height)
    }

    pub fn tip(&self) -> CoreReplayTip {
        self.replay.tip()
    }

    pub fn apply_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<RuntimeBlockContext, CoreReplayError> {
        // CoreReplay::apply_block stages its frontier, checkpoints, and output
        // before committing any state. Application routing below is infallible,
        // so cloning the complete replay (including retained undo frontiers) here
        // adds no atomicity and makes light-wallet catch-up scale with retention.
        let core = self.replay.apply_block(block)?;
        let transactions = core
            .transactions()
            .iter()
            .enumerate()
            .map(|(core_index, transaction)| RuntimeTransactionContext {
                core_index,
                message: route_candidate(
                    transaction.full_transaction_status(),
                    transaction.is_carrier_candidate(),
                    &self.rendezvous,
                    self.runtime_id,
                ),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(RuntimeBlockContext {
            core,
            transactions,
            runtime_activation_height: self.parameters.parameters().runtime_activation_height,
        })
    }

    /// Prepares one canonical block without publishing it to this runtime.
    ///
    /// This clones only bounded Core replay state, not application state. A
    /// large-state host can apply all durable writes using the returned staged
    /// runtime, commit its outer transaction, then call [`Self::publish_staged`].
    pub fn stage_block(
        &self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<StagedCoreChange<RuntimeBlockContext>, CoreReplayError> {
        let base_tip = self.tip();
        let mut runtime = self.clone();
        let output = runtime.apply_block(block)?;
        Ok(StagedCoreChange {
            base_tip,
            runtime,
            output,
        })
    }

    /// Inspects application transport without advancing canonical replay.
    /// Canonical transaction/effect validation remains the responsibility of
    /// [`CoreReplay::apply_block`].
    pub fn inspect_transaction(
        &self,
        transaction: &zcash_primitives::transaction::Transaction,
    ) -> RuntimeTransactionInspection {
        inspect_transaction_for(transaction, &self.rendezvous, self.runtime_id)
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), CoreRewindError> {
        self.replay.rewind_to(height)
    }

    /// Prepares a rewind without publishing it to this runtime.
    pub fn stage_rewind(&self, height: u32) -> Result<StagedCoreChange<()>, CoreRewindError> {
        let base_tip = self.tip();
        let mut runtime = self.clone();
        runtime.rewind_to(height)?;
        Ok(StagedCoreChange {
            base_tip,
            runtime,
            output: (),
        })
    }

    /// Publishes a staged Core change after the host's durable transaction has
    /// committed. The base-tip check detects accidental concurrent mutation;
    /// well-formed hosts serialize access, making this handoff infallible.
    pub fn publish_staged<O>(
        &mut self,
        staged: StagedCoreChange<O>,
    ) -> Result<O, StagedCorePublishError> {
        if self.tip() != staged.base_tip {
            return Err(StagedCorePublishError::BaseTipChanged);
        }
        *self = staged.runtime;
        Ok(staged.output)
    }

    pub fn save_snapshot(&self) -> Result<Vec<u8>, CoreRuntimeSnapshotError> {
        let stored = StoredCoreRuntime {
            format_version: CORE_RUNTIME_SNAPSHOT_FORMAT_VERSION,
            runtime_id: self.runtime_id.to_bytes(),
            replay: self
                .replay
                .save_snapshot()
                .map_err(CoreRuntimeSnapshotError::Replay)?,
        };
        serde_json::to_vec(&stored).map_err(|_| CoreRuntimeSnapshotError::Encoding)
    }

    pub fn load_snapshot(
        parameters: ValidatedCoreRuntimeParameters,
        configuration: CoreReplayConfiguration,
        bytes: &[u8],
    ) -> Result<Self, CoreRuntimeSnapshotError> {
        let stored: StoredCoreRuntime =
            serde_json::from_slice(bytes).map_err(|_| CoreRuntimeSnapshotError::Encoding)?;
        if stored.format_version != CORE_RUNTIME_SNAPSHOT_FORMAT_VERSION {
            return Err(CoreRuntimeSnapshotError::UnsupportedFormat);
        }
        if stored.runtime_id != parameters.core_runtime_id().to_bytes() {
            return Err(CoreRuntimeSnapshotError::RuntimeMismatch);
        }
        let replay = CoreReplay::load_snapshot(configuration, &stored.replay)
            .map_err(CoreRuntimeSnapshotError::Replay)?;
        Self::new(parameters, replay).map_err(CoreRuntimeSnapshotError::Configuration)
    }
}

/// Core routing and canonical validation for a host that already owns the
/// authenticated Ironwood commitment tree.
///
/// This mode never hashes or stores a duplicate frontier. The host is
/// responsible for comparing the starting position with its tree and for
/// publishing the advanced runtime only after the same block range commits to
/// that tree.
#[derive(Clone)]
pub struct CorePositionRuntime {
    parameters: ValidatedCoreRuntimeParameters,
    runtime_id: CoreRuntimeId,
    rendezvous: CoreRendezvous,
    replay: CorePositionReplay,
}

impl CorePositionRuntime {
    pub fn new(
        parameters: ValidatedCoreRuntimeParameters,
        configuration: CoreReplayConfiguration,
        checkpoint: CoreReplayPositionCheckpoint,
    ) -> Result<Self, CoreRuntimeConfigurationError> {
        validate_runtime_configuration(&parameters, configuration)?;
        let runtime_id = parameters.core_runtime_id();
        let rendezvous = CoreRendezvous::from_validated(&parameters);
        let replay = CorePositionReplay::from_checkpoint(configuration, checkpoint)
            .map_err(|_| CoreRuntimeConfigurationError::ActivationMismatch)?;
        Ok(Self {
            parameters,
            runtime_id,
            rendezvous,
            replay,
        })
    }

    pub fn parameters(&self) -> &ValidatedCoreRuntimeParameters {
        &self.parameters
    }
    pub fn rendezvous(&self) -> &CoreRendezvous {
        &self.rendezvous
    }
    pub fn configuration(&self) -> CoreReplayConfiguration {
        self.replay.configuration()
    }
    pub fn tip(&self) -> CoreReplayTip {
        self.replay.tip()
    }
    pub fn ironwood_tree_size(&self) -> u32 {
        self.replay.ironwood_tree_size()
    }
    pub fn oldest_rewind_height(&self) -> u32 {
        self.replay.oldest_rewind_height()
    }
    pub fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        self.replay.retained_tip_at(height)
    }

    pub fn apply_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<PositionedRuntimeBlockContext, CoreReplayError> {
        let core = self.replay.apply_block(block)?;
        let transactions =
            route_transactions(core.transactions(), &self.rendezvous, self.runtime_id);
        Ok(PositionedRuntimeBlockContext { core, transactions })
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), CoreRewindError> {
        self.replay.rewind_to(height)
    }
}

impl CanonicalRuntime for CorePositionRuntime {
    type BlockOutput = PositionedRuntimeBlockContext;
    type ApplyError = CoreReplayError;
    type RewindError = CoreRewindError;

    fn core_parameters(&self) -> &ValidatedCoreRuntimeParameters {
        self.parameters()
    }
    fn rendezvous(&self) -> &CoreRendezvous {
        self.rendezvous()
    }
    fn tip(&self) -> CoreReplayTip {
        self.tip()
    }
    fn oldest_rewind_height(&self) -> u32 {
        self.oldest_rewind_height()
    }
    fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        self.retained_tip_at(height)
    }
    fn apply_canonical_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        self.apply_block(block)
    }
    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        self.rewind_to(height)
    }
}

fn validate_runtime_configuration(
    parameters: &ValidatedCoreRuntimeParameters,
    configuration: CoreReplayConfiguration,
) -> Result<(), CoreRuntimeConfigurationError> {
    if parameters.parameters().runtime_activation_height != configuration.activation_height() {
        return Err(CoreRuntimeConfigurationError::ActivationMismatch);
    }
    Ok(())
}

fn route_transactions(
    transactions: &[crate::replay::CoreTransactionContext],
    rendezvous: &CoreRendezvous,
    runtime_id: CoreRuntimeId,
) -> Box<[RuntimeTransactionContext]> {
    transactions
        .iter()
        .enumerate()
        .map(|(core_index, transaction)| RuntimeTransactionContext {
            core_index,
            message: route_candidate(
                transaction.full_transaction_status(),
                transaction.is_carrier_candidate(),
                rendezvous,
                runtime_id,
            ),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

impl CanonicalRuntime for CoreRuntime {
    type BlockOutput = RuntimeBlockContext;
    type ApplyError = CoreReplayError;
    type RewindError = CoreRewindError;

    fn core_parameters(&self) -> &ValidatedCoreRuntimeParameters {
        self.parameters()
    }

    fn rendezvous(&self) -> &CoreRendezvous {
        self.rendezvous()
    }

    fn tip(&self) -> CoreReplayTip {
        self.tip()
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.oldest_rewind_height()
    }

    fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        self.retained_tip_at(height)
    }

    fn apply_canonical_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        self.apply_block(block)
    }

    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        self.rewind_to(height)
    }
}

fn route_candidate(
    full_transaction: &FullTransactionStatus,
    carrier_candidate: bool,
    rendezvous: &CoreRendezvous,
    runtime_id: CoreRuntimeId,
) -> ApplicationMessageStatus {
    if !carrier_candidate {
        return ApplicationMessageStatus::NotCandidate;
    }
    let FullTransactionStatus::ValidatedFullTransaction(validated) = full_transaction else {
        return ApplicationMessageStatus::NotCandidate;
    };
    inspect_transaction_for(validated.transaction(), rendezvous, runtime_id).message
}

/// Routes one transaction at a validated runtime rendezvous without changing
/// replay state.
pub fn inspect_transaction(
    transaction: &zcash_primitives::transaction::Transaction,
    parameters: &ValidatedCoreRuntimeParameters,
) -> RuntimeTransactionInspection {
    let rendezvous = CoreRendezvous::from_validated(parameters);
    inspect_transaction_for(transaction, &rendezvous, parameters.core_runtime_id())
}

/// Inspects a transaction at an application-supplied public rendezvous.
///
/// Callers consuming chain data must first authenticate the full transaction
/// and its compact/full Ironwood equality through Core replay. This function
/// performs routing only and does not make transaction bytes authoritative.
pub fn inspect_transaction_at_rendezvous(
    transaction: &zcash_primitives::transaction::Transaction,
    rendezvous: &CoreRendezvous,
    runtime_id: CoreRuntimeId,
) -> RuntimeTransactionInspection {
    inspect_transaction_for(transaction, rendezvous, runtime_id)
}

fn inspect_transaction_for(
    transaction: &zcash_primitives::transaction::Transaction,
    rendezvous: &CoreRendezvous,
    runtime_id: CoreRuntimeId,
) -> RuntimeTransactionInspection {
    let Some(bundle) = transaction.ironwood_bundle() else {
        return RuntimeTransactionInspection {
            frames: Box::new([]),
            routed_frames: Box::new([]),
            message: ApplicationMessageStatus::NoMessage,
        };
    };
    let routed_frames = bundle
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(action_index, action)| {
            rendezvous.action_note(action).and_then(|note| {
                transport::is_frame(&note.memo).then_some(RoutedFrame {
                    action_index: u32::try_from(action_index).expect("action count fits u32"),
                    value: note.value,
                    memo: note.memo,
                })
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let frames = routed_frames
        .iter()
        .map(|frame| frame.memo)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let payload = match transport::reconstruct_frames(&frames, runtime_id.to_bytes()) {
        Ok(payload) => payload,
        Err(transport::Error::NoFrames | transport::Error::WrongRuntime) => {
            return RuntimeTransactionInspection {
                frames,
                routed_frames,
                message: ApplicationMessageStatus::NoMessage,
            };
        }
        Err(error) => {
            return RuntimeTransactionInspection {
                frames,
                routed_frames,
                message: ApplicationMessageStatus::MalformedTransport(error),
            };
        }
    };
    let message = match ApplicationEnvelope::decode(&payload) {
        Ok(message) => ApplicationMessageStatus::Message(message),
        Err(error) => ApplicationMessageStatus::MalformedEnvelope(error),
    };
    RuntimeTransactionInspection {
        frames,
        routed_frames,
        message,
    }
}
