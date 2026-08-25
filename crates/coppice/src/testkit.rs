//! Lightweight deterministic history builders for Coppice applications.

use coppice_core::replay::{CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplayTip};
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
