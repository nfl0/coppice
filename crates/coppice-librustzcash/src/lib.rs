//! Generic compact-block host adapter for the Coppice application runtime.
//!
//! Application wallet policies, note selection, and persistence deliberately
//! live with their applications rather than in this package.

#![forbid(unsafe_code)]

pub mod chain;
mod reconcile;

pub use chain::{
    CanonicalCompactTransactionSummary, CanonicalRuntime, CompactBlockAdapterError,
    CompactBlockApplyError, FullTransactionSource, HistoricalTransactionAuthenticationError,
    MAX_CANDIDATE_FULL_TX_BYTES, MAX_FULL_TRANSACTION_BYTES, apply_compact_block,
    apply_compact_block_with_additional_rendezvous, apply_compact_block_with_rendezvous_policy,
    apply_compact_block_with_transaction_selector, authenticate_compact_transaction,
    prepare_canonical_block, prepare_canonical_block_with_additional_rendezvous,
    prepare_canonical_block_with_rendezvous_policy,
    prepare_canonical_block_with_transaction_selector,
};
pub use reconcile::{
    BootstrapError, BootstrapResult, CanonicalBlockSource, CanonicalTip,
    FrozenCanonicalBlockSource, ReconcileError, ReconcileKind, ReconcileOutcome, ReconcileResult,
    bootstrap_canonical_chain, bootstrap_canonical_chain_with_progress, reconcile_canonical_chain,
    reconcile_canonical_chain_with_progress, reconcile_canonical_chain_with_transaction_selector,
};
