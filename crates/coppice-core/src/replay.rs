//! Application-blind canonical Zcash replay and Ironwood tracking.
//!
//! [`CoreReplay`] validates a host-selected canonical block stream and emits
//! immutable contexts for later application dispatch. It does not select a
//! fork, decode application payloads, or persist application state.

use incrementalmerkletree::frontier::CommitmentTree;
use orchard::{note::Nullifier, tree::MerkleHashOrchard};
use std::{collections::BTreeMap, io::Cursor};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

/// Zcash transactions are bounded by the consensus block-size limit. Applying
/// the same limit before parsing prevents caller-controlled allocation spikes.
pub const MAX_FULL_TRANSACTION_LEN: usize = 2_000_000;

/// The authenticated Ironwood commitment frontier tracked by Core replay.
pub type IronwoodFrontier = CommitmentTree<MerkleHashOrchard, 32>;

/// Generic, explicitly configured Core replay retention requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreReplayConfiguration {
    activation_height: u32,
    retention_blocks: u32,
}

impl CoreReplayConfiguration {
    /// Constructs a replay configuration independent of application policy.
    pub fn new(
        activation_height: u32,
        retention_blocks: u32,
    ) -> Result<Self, CoreReplayConfigurationError> {
        if activation_height == 0 {
            return Err(CoreReplayConfigurationError::ZeroActivationHeight);
        }
        if retention_blocks == 0 {
            return Err(CoreReplayConfigurationError::ZeroRetention);
        }
        Ok(Self {
            activation_height,
            retention_blocks,
        })
    }

    /// First block height accepted by this replay instance.
    pub fn activation_height(&self) -> u32 {
        self.activation_height
    }

    /// Number of completed blocks retained for host-directed rewind.
    pub fn retention_blocks(&self) -> u32 {
        self.retention_blocks
    }
}

/// Invalid generic replay configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreReplayConfigurationError {
    ZeroActivationHeight,
    ZeroRetention,
}

/// A host-supplied authenticated frontier immediately before activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreReplayActivationCheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub ironwood_frontier: IronwoodFrontier,
    pub ironwood_tree_size: u32,
}

/// Canonical block input supplied by the host-selected Zcash chain source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreCanonicalBlockInput {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub branch_id: BranchId,
    pub transactions: Vec<CoreCanonicalTransactionInput>,
}

/// Canonical transaction metadata plus candidate-only full transaction bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreCanonicalTransactionInput {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub ironwood_nullifiers: Vec<[u8; 32]>,
    pub ironwood_commitments: Vec<[u8; 32]>,
    pub full_tx_required: bool,
    pub candidate_full_tx: Option<Vec<u8>>,
}

/// Current canonical replay position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreReplayTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

/// Authenticated Ironwood state after a canonical block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreIronwoodCheckpoint {
    pub height: u32,
    pub root: [u8; 32],
    pub tree_size: u32,
}

/// Ordered, validated Ironwood effects for one canonical transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreIronwoodEffects {
    nullifiers: Box<[[u8; 32]]>,
    commitments: Box<[[u8; 32]]>,
}

impl CoreIronwoodEffects {
    /// Nullifiers in their canonical transaction order.
    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }

    /// Commitments in their canonical transaction order.
    pub fn commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }
}

/// Full transaction bytes that Core has parsed and cross-checked against the
/// host-provided transaction ID and Ironwood effects.
#[derive(Clone, Debug)]
pub struct ValidatedFullTransaction {
    bytes: Box<[u8]>,
    transaction: Transaction,
}

impl ValidatedFullTransaction {
    /// The exact canonical bytes validated by Core.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The parsed transaction authenticated by the validation checks.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

impl PartialEq for ValidatedFullTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for ValidatedFullTransaction {}

/// Whether this transaction required candidate-only full transaction fetching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateTransactionStatus {
    NotCandidate,
    ValidatedFullTransaction(Box<ValidatedFullTransaction>),
}

impl CandidateTransactionStatus {
    /// Returns validated full transaction bytes only for a fetched candidate.
    pub fn validated_full_transaction(&self) -> Option<&ValidatedFullTransaction> {
        match self {
            Self::NotCandidate => None,
            Self::ValidatedFullTransaction(transaction) => Some(transaction),
        }
    }
}

/// Immutable canonical context emitted for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreTransactionContext {
    height: u32,
    block_hash: [u8; 32],
    tx_index: u32,
    txid: [u8; 32],
    ironwood_effects: CoreIronwoodEffects,
    candidate_status: CandidateTransactionStatus,
}

impl CoreTransactionContext {
    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn tx_index(&self) -> u32 {
        self.tx_index
    }

    pub fn txid(&self) -> [u8; 32] {
        self.txid
    }

    pub fn ironwood_effects(&self) -> &CoreIronwoodEffects {
        &self.ironwood_effects
    }

    pub fn candidate_status(&self) -> &CandidateTransactionStatus {
        &self.candidate_status
    }
}

/// Immutable canonical context emitted after a complete block commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreBlockContext {
    height: u32,
    block_hash: [u8; 32],
    prev_block_hash: [u8; 32],
    branch_id: BranchId,
    transactions: Box<[CoreTransactionContext]>,
    ironwood_checkpoint: CoreIronwoodCheckpoint,
}

impl CoreBlockContext {
    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn prev_block_hash(&self) -> [u8; 32] {
        self.prev_block_hash
    }

    pub fn branch_id(&self) -> BranchId {
        self.branch_id
    }

    pub fn transactions(&self) -> &[CoreTransactionContext] {
        &self.transactions
    }

    pub fn ironwood_checkpoint(&self) -> CoreIronwoodCheckpoint {
        self.ironwood_checkpoint
    }
}

/// Core-fatal canonical input failures. No state advances when `apply_block`
/// returns one of these errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreReplayError {
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
    ArithmeticOverflow,
}

/// Host-directed rewind failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRewindError {
    BeforeActivation,
    BeyondTip,
    SnapshotMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoreReplayUndo {
    applied_tip: CoreReplayTip,
    prior_tip: CoreReplayTip,
    prior_ironwood_frontier: IronwoodFrontier,
    checkpoint_undo: Vec<(u32, Option<CoreIronwoodCheckpoint>)>,
}

/// Parallel application-blind canonical replay state.
pub struct CoreReplay {
    configuration: CoreReplayConfiguration,
    ironwood_frontier: IronwoodFrontier,
    ironwood_checkpoints: BTreeMap<u32, CoreIronwoodCheckpoint>,
    tip: CoreReplayTip,
    history: BTreeMap<u32, CoreReplayUndo>,
}

impl CoreReplay {
    /// Starts replay from an authenticated pre-activation frontier.
    pub fn new(
        configuration: CoreReplayConfiguration,
        checkpoint: CoreReplayActivationCheckpoint,
    ) -> Result<Self, CoreReplayError> {
        let expected_height = configuration
            .activation_height
            .checked_sub(1)
            .ok_or(CoreReplayError::ArithmeticOverflow)?;
        let actual_size = u32::try_from(checkpoint.ironwood_frontier.size())
            .map_err(|_| CoreReplayError::InvalidActivationCheckpoint)?;
        if checkpoint.height != expected_height || actual_size != checkpoint.ironwood_tree_size {
            return Err(CoreReplayError::InvalidActivationCheckpoint);
        }

        let authenticated = CoreIronwoodCheckpoint {
            height: checkpoint.height,
            root: checkpoint.ironwood_frontier.root().to_bytes(),
            tree_size: actual_size,
        };
        let mut ironwood_checkpoints = BTreeMap::new();
        ironwood_checkpoints.insert(checkpoint.height, authenticated);
        Ok(Self {
            configuration,
            ironwood_frontier: checkpoint.ironwood_frontier,
            ironwood_checkpoints,
            tip: CoreReplayTip {
                height: checkpoint.height,
                block_hash: checkpoint.block_hash,
            },
            history: BTreeMap::new(),
        })
    }

    pub fn configuration(&self) -> CoreReplayConfiguration {
        self.configuration
    }

    pub fn tip(&self) -> CoreReplayTip {
        self.tip
    }

    pub fn ironwood_frontier(&self) -> &IronwoodFrontier {
        &self.ironwood_frontier
    }

    pub fn ironwood_checkpoints(&self) -> &BTreeMap<u32, CoreIronwoodCheckpoint> {
        &self.ironwood_checkpoints
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

    pub fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        if height == self.tip.height {
            Some(self.tip)
        } else {
            height
                .checked_add(1)
                .and_then(|next| self.history.get(&next))
                .map(|undo| undo.prior_tip)
        }
    }

    /// Atomically validates and applies one host-selected canonical block.
    pub fn apply_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<CoreBlockContext, CoreReplayError> {
        let expected_height = self
            .tip
            .height
            .checked_add(1)
            .ok_or(CoreReplayError::ArithmeticOverflow)?;
        if block.height != expected_height {
            return Err(CoreReplayError::NonSequentialHeight);
        }
        if block.prev_block_hash != self.tip.block_hash {
            return Err(CoreReplayError::PredecessorMismatch);
        }
        if block
            .transactions
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        {
            return Err(CoreReplayError::NonCanonicalTxOrder);
        }

        let mut frontier = self.ironwood_frontier.clone();
        let mut checkpoints = self.ironwood_checkpoints.clone();
        let mut transactions = Vec::with_capacity(block.transactions.len());

        for input in &block.transactions {
            let candidate_status = validate_candidate(block.branch_id, input)?;
            for nullifier in &input.ironwood_nullifiers {
                Option::<Nullifier>::from(Nullifier::from_bytes(nullifier))
                    .ok_or(CoreReplayError::NonCanonicalNullifier)?;
            }
            for commitment in &input.ironwood_commitments {
                let node =
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(commitment))
                        .ok_or(CoreReplayError::InvalidIronwoodCommitment)?;
                frontier
                    .append(node)
                    .map_err(|_| CoreReplayError::IronwoodAppendFailure)?;
            }
            transactions.push(CoreTransactionContext {
                height: block.height,
                block_hash: block.block_hash,
                tx_index: input.tx_index,
                txid: input.txid,
                ironwood_effects: CoreIronwoodEffects {
                    nullifiers: input.ironwood_nullifiers.clone().into_boxed_slice(),
                    commitments: input.ironwood_commitments.clone().into_boxed_slice(),
                },
                candidate_status,
            });
        }

        let tree_size =
            u32::try_from(frontier.size()).map_err(|_| CoreReplayError::ArithmeticOverflow)?;
        let ironwood_checkpoint = CoreIronwoodCheckpoint {
            height: block.height,
            root: frontier.root().to_bytes(),
            tree_size,
        };
        checkpoints.insert(block.height, ironwood_checkpoint);
        prune_checkpoints(self.configuration, block.height, &mut checkpoints)?;

        let tip = CoreReplayTip {
            height: block.height,
            block_hash: block.block_hash,
        };
        let undo = CoreReplayUndo {
            applied_tip: tip,
            prior_tip: self.tip,
            prior_ironwood_frontier: self.ironwood_frontier.clone(),
            checkpoint_undo: checkpoint_undo(&self.ironwood_checkpoints, &checkpoints),
        };

        self.ironwood_frontier = frontier;
        self.ironwood_checkpoints = checkpoints;
        self.tip = tip;
        self.history.insert(block.height, undo);
        let oldest_undo = block
            .height
            .saturating_sub(self.configuration.retention_blocks)
            .saturating_add(1);
        self.history.retain(|height, _| *height >= oldest_undo);

        Ok(CoreBlockContext {
            height: block.height,
            block_hash: block.block_hash,
            prev_block_hash: block.prev_block_hash,
            branch_id: block.branch_id,
            transactions: transactions.into_boxed_slice(),
            ironwood_checkpoint,
        })
    }

    /// Rewinds to a host-selected retained common ancestor and discards the
    /// abandoned suffix. Fork choice remains outside Core replay.
    pub fn rewind_to(&mut self, height: u32) -> Result<(), CoreRewindError> {
        let activation_checkpoint_height = self.configuration.activation_height - 1;
        if height < activation_checkpoint_height {
            return Err(CoreRewindError::BeforeActivation);
        }
        if height > self.tip.height {
            return Err(CoreRewindError::BeyondTip);
        }
        if height < self.oldest_rewind_height() {
            return Err(CoreRewindError::SnapshotMissing);
        }

        let mut frontier = self.ironwood_frontier.clone();
        let mut checkpoints = self.ironwood_checkpoints.clone();
        let mut tip = self.tip;
        let mut history = self.history.clone();
        while tip.height > height {
            let undo = history
                .remove(&tip.height)
                .ok_or(CoreRewindError::SnapshotMissing)?;
            if tip != undo.applied_tip {
                return Err(CoreRewindError::SnapshotMissing);
            }
            frontier = undo.prior_ironwood_frontier;
            apply_checkpoint_undo(&mut checkpoints, &undo.checkpoint_undo);
            tip = undo.prior_tip;
        }

        self.ironwood_frontier = frontier;
        self.ironwood_checkpoints = checkpoints;
        self.tip = tip;
        self.history = history;
        Ok(())
    }
}

fn validate_candidate(
    branch_id: BranchId,
    input: &CoreCanonicalTransactionInput,
) -> Result<CandidateTransactionStatus, CoreReplayError> {
    match (input.full_tx_required, input.candidate_full_tx.as_deref()) {
        (false, None) => Ok(CandidateTransactionStatus::NotCandidate),
        (false, Some(_)) => Err(CoreReplayError::CandidateFlagMismatch),
        (true, None) => Err(CoreReplayError::RequiredFullTransactionMissing),
        (true, Some(bytes)) => {
            if bytes.len() > MAX_FULL_TRANSACTION_LEN {
                return Err(CoreReplayError::OversizedTransaction);
            }
            let mut cursor = Cursor::new(bytes);
            let transaction = Transaction::read(&mut cursor, branch_id)
                .map_err(|_| CoreReplayError::InvalidFullTransaction)?;
            if cursor.position() != bytes.len() as u64 {
                return Err(CoreReplayError::InvalidFullTransaction);
            }
            let txid: [u8; 32] = transaction.txid().into();
            if txid != input.txid {
                return Err(CoreReplayError::TxidMismatch);
            }
            let (nullifiers, commitments) = extract_ironwood_effects(&transaction);
            if nullifiers != input.ironwood_nullifiers || commitments != input.ironwood_commitments
            {
                return Err(CoreReplayError::IronwoodEffectsMismatch);
            }
            Ok(CandidateTransactionStatus::ValidatedFullTransaction(
                Box::new(ValidatedFullTransaction {
                    bytes: bytes.into(),
                    transaction,
                }),
            ))
        }
    }
}

fn extract_ironwood_effects(transaction: &Transaction) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let Some(bundle) = transaction.ironwood_bundle() else {
        return (vec![], vec![]);
    };
    let mut nullifiers = Vec::with_capacity(bundle.actions().len());
    let mut commitments = Vec::with_capacity(bundle.actions().len());
    for action in bundle.actions() {
        nullifiers.push(action.nullifier().to_bytes());
        commitments.push(action.cmx().to_bytes());
    }
    (nullifiers, commitments)
}

fn prune_checkpoints(
    configuration: CoreReplayConfiguration,
    height: u32,
    checkpoints: &mut BTreeMap<u32, CoreIronwoodCheckpoint>,
) -> Result<(), CoreReplayError> {
    let next_height = height
        .checked_add(1)
        .ok_or(CoreReplayError::ArithmeticOverflow)?;
    let activation_checkpoint = configuration.activation_height - 1;
    let oldest =
        activation_checkpoint.max(next_height.saturating_sub(configuration.retention_blocks));
    checkpoints.retain(|checkpoint_height, _| *checkpoint_height >= oldest);
    Ok(())
}

fn checkpoint_undo(
    before: &BTreeMap<u32, CoreIronwoodCheckpoint>,
    after: &BTreeMap<u32, CoreIronwoodCheckpoint>,
) -> Vec<(u32, Option<CoreIronwoodCheckpoint>)> {
    before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|height| before.get(height) != after.get(height))
        .map(|height| (height, before.get(&height).copied()))
        .collect()
}

fn apply_checkpoint_undo(
    checkpoints: &mut BTreeMap<u32, CoreIronwoodCheckpoint>,
    undo: &[(u32, Option<CoreIronwoodCheckpoint>)],
) {
    for (height, checkpoint) in undo {
        match checkpoint {
            Some(checkpoint) => {
                checkpoints.insert(*height, *checkpoint);
            }
            None => {
                checkpoints.remove(height);
            }
        }
    }
}
