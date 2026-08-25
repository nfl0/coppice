//! Generic compact-block host adapter for the Coppice application runtime.
//!
//! Application wallet policies, note selection, and persistence deliberately
//! live with their applications rather than in this package.

#![forbid(unsafe_code)]

pub mod chain;

pub use chain::{
    CanonicalRuntime, CompactBlockAdapterError, CompactBlockApplyError, FullTransactionSource,
    MAX_CANDIDATE_FULL_TX_BYTES, apply_compact_block, prepare_canonical_block,
    prepare_canonical_block_with_transaction_selector,
};
