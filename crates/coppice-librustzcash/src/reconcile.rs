//! Host-authoritative canonical-chain reconciliation for Coppice.
//!
//! This module is application-blind. The host selects canonical fork choice;
//! this adapter only discovers retained common ancestors, rewinds the supplied
//! runtime, and replays host-provided CompactBlocks.

use std::fmt::Debug;

use coppice_core::{replay::CoreReplayTip, runtime::CanonicalRuntime};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::Parameters;

use crate::{
    CanonicalCompactTransactionSummary, CompactBlockApplyError, FullTransactionSource,
    apply_compact_block_with_transaction_selector,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

impl From<CoreReplayTip> for CanonicalTip {
    fn from(tip: CoreReplayTip) -> Self {
        Self {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

pub trait CanonicalBlockSource {
    type Error: Debug;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error>;
    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error>;
}

/// Freezes canonical authority to a host-selected tip while retaining an
/// untrusted source only as block transport.
pub struct FrozenCanonicalBlockSource<S> {
    source: S,
    tip: CanonicalTip,
}

impl<S> FrozenCanonicalBlockSource<S> {
    pub const fn new(source: S, tip: CanonicalTip) -> Self {
        Self { source, tip }
    }
    pub fn source(&self) -> &S {
        &self.source
    }
    pub fn into_source(self) -> S {
        self.source
    }
}

impl<S: CanonicalBlockSource> CanonicalBlockSource for FrozenCanonicalBlockSource<S> {
    type Error = S::Error;
    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        Ok(self.tip)
    }
    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error> {
        self.source.compact_block(height)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileKind {
    AlreadyCurrent,
    Forward,
    Reorg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub kind: ReconcileKind,
    pub original_tip: CoreReplayTip,
    pub observed_host_tip: CanonicalTip,
    pub common_ancestor: Option<CoreReplayTip>,
    pub blocks_rewound: u32,
    pub blocks_applied: u32,
    pub final_tip: CoreReplayTip,
}

#[derive(Debug)]
pub enum ReconcileError<C: Debug, F: Debug, A: Debug, W: Debug> {
    CanonicalBlockSource(C),
    MissingCanonicalBlock {
        height: u32,
    },
    InvalidCanonicalIdentity {
        requested_height: u32,
    },
    CanonicalHistoryChanged {
        observed: CanonicalTip,
        current: CanonicalTip,
    },
    NoRetainedCommonAncestor,
    Rewind(W),
    CompactBlockApply {
        height: u32,
        error: CompactBlockApplyError<F, A>,
    },
    ProgressPersistenceFailed,
    ArithmeticOverflow,
}

pub type ReconcileResult<C, F, A, W> = Result<ReconcileOutcome, ReconcileError<C, F, A, W>>;

/// Bootstrap-specific failure before ordinary canonical reconciliation starts.
///
/// A bootstrap is intentionally only a forward replay from the authenticated
/// Core activation checkpoint. Refusing a partially advanced runtime prevents
/// a host from accidentally treating an arbitrary local tip as a trusted
/// application-install boundary.
#[derive(Debug)]
pub enum BootstrapError<C: Debug, F: Debug, A: Debug, W: Debug> {
    /// The supplied runtime is not positioned at the Core activation base.
    NotAtActivationBoundary {
        expected_height: u32,
        actual: CoreReplayTip,
    },
    /// Canonical source acquisition, replay, or persistence failed during the
    /// forward bootstrap. The wrapped taxonomy is unchanged.
    Reconcile(ReconcileError<C, F, A, W>),
}

pub type BootstrapResult<C, F, A, W> = Result<ReconcileOutcome, BootstrapError<C, F, A, W>>;

fn block_identity(block: &CompactBlock, requested_height: u32) -> Option<CanonicalTip> {
    let height = u32::try_from(block.height).ok()?;
    let block_hash: [u8; 32] = block.hash.as_slice().try_into().ok()?;
    (height == requested_height).then_some(CanonicalTip { height, block_hash })
}

fn checked_block<C, F, A, W>(
    source: &mut C,
    height: u32,
) -> Result<CompactBlock, ReconcileError<C::Error, F, A, W>>
where
    C: CanonicalBlockSource,
    C::Error: Debug,
    F: Debug,
    A: Debug,
    W: Debug,
{
    let block = source
        .compact_block(height)
        .map_err(ReconcileError::CanonicalBlockSource)?
        .ok_or(ReconcileError::MissingCanonicalBlock { height })?;
    block_identity(&block, height).ok_or(ReconcileError::InvalidCanonicalIdentity {
        requested_height: height,
    })?;
    Ok(block)
}

fn canonical_hash_at<C, F, A, W>(
    source: &mut C,
    observed_tip: CanonicalTip,
    activation_height: u32,
    height: u32,
) -> Result<[u8; 32], ReconcileError<C::Error, F, A, W>>
where
    C: CanonicalBlockSource,
    C::Error: Debug,
    F: Debug,
    A: Debug,
    W: Debug,
{
    if height == observed_tip.height {
        return Ok(observed_tip.block_hash);
    }
    let activation_base = activation_height
        .checked_sub(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    if height == activation_base {
        // Never request a pre-activation CompactBlock. The activation block's
        // predecessor identifies the host-selected activation base.
        let block = checked_block::<C, F, A, W>(source, activation_height)?;
        return block.prev_hash.as_slice().try_into().map_err(|_| {
            ReconcileError::InvalidCanonicalIdentity {
                requested_height: activation_height,
            }
        });
    }
    checked_block::<C, F, A, W>(source, height)?
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| ReconcileError::InvalidCanonicalIdentity {
            requested_height: height,
        })
}

/// Reconciles to the host-selected tip observed at the beginning of this
/// call. Ancestor discovery is mutation-free; after a rewind, replay is
/// deliberately block-atomic and resumable rather than range-transactional.
pub fn reconcile_canonical_chain<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
) -> ReconcileResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    reconcile_canonical_chain_with_transaction_selector(
        params,
        runtime,
        canonical_source,
        full_tx_source,
        |_| false,
        |_| true,
    )
}

/// Replays a newly installed runtime from the authenticated Core activation
/// checkpoint to the host-selected canonical tip.
///
/// This is a narrow lifecycle guard over the normal reconciliation path; it
/// does not introduce a second source of canonical truth or a trusted
/// application snapshot. Hosts may use the progress variant below to persist
/// an application checkpoint after each successful canonical block.
pub fn bootstrap_canonical_chain<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
) -> BootstrapResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    bootstrap_canonical_chain_with_progress(
        params,
        runtime,
        canonical_source,
        full_tx_source,
        |_| true,
    )
}

/// Reconciles while invoking `persist_progress` after a successful rewind and
/// after each successfully applied canonical block. Returning `false` stops
/// immediately at that durable boundary; the runtime remains at exactly the
/// state presented to the callback.
pub fn reconcile_canonical_chain_with_progress<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
    persist_progress: impl FnMut(&R) -> bool,
) -> ReconcileResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    reconcile_canonical_chain_with_transaction_selector(
        params,
        runtime,
        canonical_source,
        full_tx_source,
        |_| false,
        persist_progress,
    )
}

/// Progress-reporting form of [`bootstrap_canonical_chain`]. Returning
/// `false` from the callback stops at the last durable block boundary and
/// returns `ProgressPersistenceFailed`, exactly like normal reconciliation.
pub fn bootstrap_canonical_chain_with_progress<P, R, C, F>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
    persist_progress: impl FnMut(&R) -> bool,
) -> BootstrapResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
{
    let activation_base = runtime
        .core_parameters()
        .parameters()
        .runtime_activation_height
        .checked_sub(1)
        .expect("validated Core activation height is nonzero");
    let actual = runtime.tip();
    if actual.height != activation_base {
        return Err(BootstrapError::NotAtActivationBoundary {
            expected_height: activation_base,
            actual,
        });
    }
    reconcile_canonical_chain_with_progress(
        params,
        runtime,
        canonical_source,
        full_tx_source,
        persist_progress,
    )
    .map_err(BootstrapError::Reconcile)
}

/// Reconciles while allowing an optional supplemental host policy to request
/// selective full transactions. The composed runtime's application
/// acquisition requirement is always evaluated by the shared compact-block
/// path, so normal reconciliation needs no application-specific selector.
pub fn reconcile_canonical_chain_with_transaction_selector<P, R, C, F, S>(
    params: &P,
    runtime: &mut R,
    canonical_source: &mut C,
    full_tx_source: &mut F,
    mut select_full_transaction: S,
    mut persist_progress: impl FnMut(&R) -> bool,
) -> ReconcileResult<C::Error, F::Error, R::ApplyError, R::RewindError>
where
    P: Parameters,
    R: CanonicalRuntime,
    C: CanonicalBlockSource,
    F: FullTransactionSource,
    S: FnMut(&CanonicalCompactTransactionSummary<'_>) -> bool,
{
    let original_tip = runtime.tip();
    let observed_host_tip = canonical_source
        .canonical_tip()
        .map_err(ReconcileError::CanonicalBlockSource)?;
    if original_tip.height == observed_host_tip.height
        && original_tip.block_hash == observed_host_tip.block_hash
    {
        return Ok(ReconcileOutcome {
            kind: ReconcileKind::AlreadyCurrent,
            original_tip,
            observed_host_tip,
            common_ancestor: None,
            blocks_rewound: 0,
            blocks_applied: 0,
            final_tip: original_tip,
        });
    }

    let activation_height = runtime
        .core_parameters()
        .parameters()
        .runtime_activation_height;
    let activation_base = activation_height
        .checked_sub(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    let local_is_ancestor = if original_tip.height < observed_host_tip.height {
        canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
            canonical_source,
            observed_host_tip,
            activation_height,
            original_tip.height,
        )? == original_tip.block_hash
    } else {
        false
    };

    let (kind, common_ancestor, blocks_rewound) = if local_is_ancestor {
        (ReconcileKind::Forward, None, 0)
    } else {
        let search_top = original_tip.height.min(observed_host_tip.height);
        let search_floor = runtime.oldest_rewind_height().max(activation_base);
        let mut common = None;
        for height in (search_floor..=search_top).rev() {
            let Some(local) = runtime.retained_tip_at(height) else {
                continue;
            };
            let canonical_hash = canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
                canonical_source,
                observed_host_tip,
                activation_height,
                height,
            )?;
            if local.block_hash == canonical_hash {
                common = Some(local);
                break;
            }
        }
        let common = common.ok_or(ReconcileError::NoRetainedCommonAncestor)?;
        let rewound = original_tip
            .height
            .checked_sub(common.height)
            .ok_or(ReconcileError::ArithmeticOverflow)?;
        runtime
            .rewind_canonical_to(common.height)
            .map_err(ReconcileError::Rewind)?;
        if !persist_progress(runtime) {
            return Err(ReconcileError::ProgressPersistenceFailed);
        }
        (ReconcileKind::Reorg, Some(common), rewound)
    };

    let mut blocks_applied = 0u32;
    let start = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(ReconcileError::ArithmeticOverflow)?;
    if start <= observed_host_tip.height {
        for height in start..=observed_host_tip.height {
            let block = checked_block::<C, F::Error, R::ApplyError, R::RewindError>(
                canonical_source,
                height,
            )?;
            if height == observed_host_tip.height {
                let current = block_identity(&block, height).ok_or(
                    ReconcileError::InvalidCanonicalIdentity {
                        requested_height: height,
                    },
                )?;
                if current.block_hash != observed_host_tip.block_hash {
                    return Err(ReconcileError::CanonicalHistoryChanged {
                        observed: observed_host_tip,
                        current,
                    });
                }
            }
            apply_compact_block_with_transaction_selector(
                params,
                runtime,
                &block,
                full_tx_source,
                &mut select_full_transaction,
            )
            .map_err(|error| ReconcileError::CompactBlockApply { height, error })?;
            if !persist_progress(runtime) {
                return Err(ReconcileError::ProgressPersistenceFailed);
            }
            blocks_applied = blocks_applied
                .checked_add(1)
                .ok_or(ReconcileError::ArithmeticOverflow)?;
        }
    }

    let current_host_tip = canonical_source
        .canonical_tip()
        .map_err(ReconcileError::CanonicalBlockSource)?;
    if current_host_tip.height < observed_host_tip.height {
        return Err(ReconcileError::CanonicalHistoryChanged {
            observed: observed_host_tip,
            current: current_host_tip,
        });
    }
    if current_host_tip != observed_host_tip {
        let current_observed_hash = canonical_hash_at::<C, F::Error, R::ApplyError, R::RewindError>(
            canonical_source,
            current_host_tip,
            activation_height,
            observed_host_tip.height,
        )?;
        if current_observed_hash != observed_host_tip.block_hash {
            return Err(ReconcileError::CanonicalHistoryChanged {
                observed: observed_host_tip,
                current: CanonicalTip {
                    height: observed_host_tip.height,
                    block_hash: current_observed_hash,
                },
            });
        }
    }

    Ok(ReconcileOutcome {
        kind,
        original_tip,
        observed_host_tip,
        common_ancestor,
        blocks_rewound,
        blocks_applied,
        final_tip: runtime.tip(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice_core::{
        identity::{CoreRuntimeParameters, ZcashNetwork},
        replay::{
            CoreCanonicalBlockInput, CoreReplay, CoreReplayActivationCheckpoint,
            CoreReplayConfiguration, IronwoodFrontier,
        },
        runtime::CoreRuntime,
    };
    use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

    #[derive(Clone, Debug)]
    struct EmptySource {
        tip: CanonicalTip,
    }

    impl CanonicalBlockSource for EmptySource {
        type Error = ();

        fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
            Ok(self.tip)
        }

        fn compact_block(&mut self, _height: u32) -> Result<Option<CompactBlock>, Self::Error> {
            Ok(None)
        }
    }

    impl FullTransactionSource for EmptySource {
        type Error = ();

        fn full_transaction(&mut self, _txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }
    }

    fn parameters() -> LocalNetwork {
        let one = Some(BlockHeight::from_u32(1));
        let two = Some(BlockHeight::from_u32(2));
        LocalNetwork {
            overwinter: one,
            sapling: one,
            blossom: one,
            heartwood: one,
            canopy: one,
            nu5: two,
            nu6: two,
            nu6_1: two,
            nu6_2: two,
            nu6_3: two,
        }
    }

    fn runtime() -> CoreRuntime {
        let parameters = CoreRuntimeParameters {
            runtime_protocol_id: b"coppice.runtime".to_vec(),
            runtime_protocol_version: 1,
            zcash_network_domain: b"coppice-runtime-regtest-v1".to_vec(),
            zcash_network: ZcashNetwork::Regtest,
            runtime_activation_height: 10,
            carrier_protocol_id: b"CPV1".to_vec(),
            rendezvous_ivk: hex::decode(
                "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            rendezvous_receiver: hex::decode(
                "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }
        .validate()
        .unwrap();
        let replay = CoreReplay::new(
            CoreReplayConfiguration::new(10, 4).unwrap(),
            CoreReplayActivationCheckpoint {
                height: 9,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        CoreRuntime::new(parameters, replay).unwrap()
    }

    #[test]
    fn bootstrap_rejects_partially_advanced_runtime() {
        let mut runtime = runtime();
        runtime
            .apply_block(&CoreCanonicalBlockInput {
                height: 10,
                block_hash: [10; 32],
                prev_block_hash: [9; 32],
                branch_id: zcash_protocol::consensus::BranchId::Nu6_3,
                transactions: vec![],
            })
            .unwrap();
        let mut source = EmptySource {
            tip: CanonicalTip {
                height: 9,
                block_hash: [9; 32],
            },
        };
        let mut full = EmptySource { tip: source.tip };
        let error = bootstrap_canonical_chain(&parameters(), &mut runtime, &mut source, &mut full)
            .unwrap_err();
        assert!(matches!(
            error,
            BootstrapError::NotAtActivationBoundary {
                expected_height: 9,
                actual: CoreReplayTip { height: 10, .. }
            }
        ));
    }

    #[test]
    fn bootstrap_keeps_missing_canonical_blocks_fatal() {
        let mut runtime = runtime();
        let mut source = EmptySource {
            tip: CanonicalTip {
                height: 10,
                block_hash: [10; 32],
            },
        };
        let mut full = EmptySource { tip: source.tip };
        let error = bootstrap_canonical_chain(&parameters(), &mut runtime, &mut source, &mut full)
            .unwrap_err();
        assert!(matches!(
            error,
            BootstrapError::Reconcile(ReconcileError::MissingCanonicalBlock { height: 10 })
        ));
    }
}
