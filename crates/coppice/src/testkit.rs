//! Lightweight deterministic history builders for Coppice applications.

use coppice_core::replay::{
    CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplayTip,
    FullTransactionAcquisition,
};
use zcash_protocol::consensus::BranchId;

/// Builds an ordered synthetic canonical history without wallet-private data.
#[derive(Clone, Debug)]
pub struct CanonicalHistoryBuilder {
    tip: CoreReplayTip,
    branch_id: BranchId,
}

impl CanonicalHistoryBuilder {
    pub fn new(tip: CoreReplayTip, branch_id: BranchId) -> Self {
        Self { tip, branch_id }
    }
    pub fn tip(&self) -> CoreReplayTip {
        self.tip
    }

    /// Creates a compact-only synthetic transaction for application tests.
    /// Callers that need carrier or extended effects can fill the acquisition
    /// fields explicitly before handing it to `next_block`.
    pub fn transaction(
        tx_index: u32,
        txid: [u8; 32],
        ironwood_nullifiers: impl Into<Vec<[u8; 32]>>,
        ironwood_commitments: impl Into<Vec<[u8; 32]>>,
    ) -> CoreCanonicalTransactionInput {
        CoreCanonicalTransactionInput {
            tx_index,
            txid,
            ironwood_nullifiers: ironwood_nullifiers.into(),
            ironwood_commitments: ironwood_commitments.into(),
            full_transaction_acquisition: FullTransactionAcquisition::None,
            full_transaction: None,
        }
    }

    /// Starts a synthetic branch from a retained canonical position.
    pub fn fork_at(&self, tip: CoreReplayTip) -> Self {
        Self {
            tip,
            branch_id: self.branch_id,
        }
    }

    pub fn next_empty_block(&mut self, block_hash: [u8; 32]) -> CoreCanonicalBlockInput {
        self.next_block(block_hash, Vec::new())
    }

    pub fn next_block(
        &mut self,
        block_hash: [u8; 32],
        transactions: Vec<CoreCanonicalTransactionInput>,
    ) -> CoreCanonicalBlockInput {
        let height = self
            .tip
            .height
            .checked_add(1)
            .expect("test history height overflow");
        let block = CoreCanonicalBlockInput {
            height,
            block_hash,
            prev_block_hash: self.tip.block_hash,
            branch_id: self.branch_id,
            transactions,
        };
        self.tip = CoreReplayTip { height, block_hash };
        block
    }
}
