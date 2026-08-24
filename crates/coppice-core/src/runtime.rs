//! Generic CPV1 application-envelope routing over canonical Core replay.

use crate::{
    application::{ApplicationEnvelopeError, ApplicationEnvelopeV1},
    identity::{CoreRuntimeId, ValidatedCoreRuntimeParameters},
    replay::{
        CandidateTransactionStatus, CoreBlockContext, CoreCanonicalBlockInput,
        CoreIronwoodCheckpoint, CoreReplay, CoreReplayConfiguration, CoreReplayError,
        CoreReplaySnapshotError, CoreReplayTip, CoreRewindError, IronwoodFrontier,
    },
    transport,
};
use orchard::{keys::IncomingViewingKey, note_encryption::IronwoodDomain};
use serde::{Deserialize, Serialize};
use zcash_note_encryption::try_note_decryption;

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
    Message(ApplicationEnvelopeV1),
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
    message: ApplicationMessageStatus,
}

impl RuntimeTransactionInspection {
    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
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
}

#[derive(Clone)]
pub struct CoreRuntime {
    parameters: ValidatedCoreRuntimeParameters,
    runtime_id: CoreRuntimeId,
    replay: CoreReplay,
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
        Ok(Self {
            parameters,
            runtime_id,
            replay,
        })
    }

    pub fn parameters(&self) -> &ValidatedCoreRuntimeParameters {
        &self.parameters
    }

    pub fn runtime_id(&self) -> CoreRuntimeId {
        self.runtime_id
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
        let mut replay = self.replay.clone();
        let core = replay.apply_block(block)?;
        let transactions = core
            .transactions()
            .iter()
            .enumerate()
            .map(|(core_index, transaction)| RuntimeTransactionContext {
                core_index,
                message: route_candidate(
                    transaction.candidate_status(),
                    &self.parameters,
                    self.runtime_id,
                ),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.replay = replay;
        Ok(RuntimeBlockContext { core, transactions })
    }

    /// Inspects application transport without advancing canonical replay.
    /// Canonical transaction/effect validation remains the responsibility of
    /// [`CoreReplay::apply_block`].
    pub fn inspect_transaction(
        &self,
        transaction: &zcash_primitives::transaction::Transaction,
    ) -> RuntimeTransactionInspection {
        inspect_transaction(transaction, &self.parameters)
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), CoreRewindError> {
        self.replay.rewind_to(height)
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

fn route_candidate(
    candidate: &CandidateTransactionStatus,
    parameters: &ValidatedCoreRuntimeParameters,
    runtime_id: CoreRuntimeId,
) -> ApplicationMessageStatus {
    let CandidateTransactionStatus::ValidatedFullTransaction(validated) = candidate else {
        return ApplicationMessageStatus::NotCandidate;
    };
    inspect_transaction_for(validated.transaction(), parameters, runtime_id).message
}

/// Routes one transaction at a validated runtime rendezvous without changing
/// replay state.
pub fn inspect_transaction(
    transaction: &zcash_primitives::transaction::Transaction,
    parameters: &ValidatedCoreRuntimeParameters,
) -> RuntimeTransactionInspection {
    inspect_transaction_for(transaction, parameters, parameters.core_runtime_id())
}

fn inspect_transaction_for(
    transaction: &zcash_primitives::transaction::Transaction,
    parameters: &ValidatedCoreRuntimeParameters,
    runtime_id: CoreRuntimeId,
) -> RuntimeTransactionInspection {
    let Some(bundle) = transaction.ironwood_bundle() else {
        return RuntimeTransactionInspection {
            frames: Box::new([]),
            message: ApplicationMessageStatus::NoMessage,
        };
    };
    let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(
        &parameters.parameters().rendezvous_ivk,
    ))
    .expect("validated Core runtime IVK");
    let prepared_ivk = ivk.prepare();
    let frames = bundle
        .actions()
        .iter()
        .filter_map(|action| {
            try_note_decryption(&IronwoodDomain::for_action(action), &prepared_ivk, action)
                .map(|(_, _, memo)| memo)
        })
        .filter(transport::is_frame)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let payload = match transport::reconstruct_frames(&frames, runtime_id.to_bytes()) {
        Ok(payload) => payload,
        Err(transport::Error::NoFrames | transport::Error::WrongRuntime) => {
            return RuntimeTransactionInspection {
                frames,
                message: ApplicationMessageStatus::NoMessage,
            };
        }
        Err(error) => {
            return RuntimeTransactionInspection {
                frames,
                message: ApplicationMessageStatus::MalformedTransport(error),
            };
        }
    };
    let message = match ApplicationEnvelopeV1::decode(&payload) {
        Ok(message) => ApplicationMessageStatus::Message(message),
        Err(error) => ApplicationMessageStatus::MalformedEnvelope(error),
    };
    RuntimeTransactionInspection { frames, message }
}
