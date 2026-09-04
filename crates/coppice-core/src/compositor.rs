//! Generic atomic composition of Core and isolated deterministic applications.
//!
//! The compositor has no application registry and no cross-application call
//! path. It merely derives one application-scoped context per descriptor from
//! a single Core scan and commits the staged states together.

use crate::{
    application::{
        ApplicationAcquisitionRequirement, ApplicationCompactTransactionSummary,
        ApplicationDescriptor, ApplicationTip, CanonicalCompactTransactionSummary,
        CoppiceApplication,
    },
    carrier::CoreRendezvous,
    identity::ValidatedCoreRuntimeParameters,
    replay::{CoreCanonicalBlockInput, CoreReplayTip, CoreRewindError, FullTransactionAcquisition},
    runtime::{CanonicalRuntime, CoreRuntime, RuntimeBlockContext},
};
use std::fmt::Debug;

fn application_requests_extended_effects<A: CoppiceApplication>(
    application: &A,
    summary: &ApplicationCompactTransactionSummary<'_>,
    block_height: u32,
) -> bool {
    block_height >= application.descriptor().activation_height
        && matches!(
            application.full_transaction_acquisition(summary),
            ApplicationAcquisitionRequirement::ExtendedEffects
        )
}

/// A statically composed collection of isolated applications. Implementations
/// are supplied for an application and for tuples of two or three applications;
/// applications can also provide their own collection type when they need a
/// different static shape.
pub trait HostedApplications: Clone {
    type BlockOutput;

    fn descriptors(&self) -> Vec<ApplicationDescriptor>;
    fn application_tips(&self) -> Vec<ApplicationTip>;
    fn oldest_rewind_height(&self) -> u32;
    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip>;
    fn required_rewind_retention(&self) -> u32;
    fn requests_extended_effects(
        &self,
        _summary: &ApplicationCompactTransactionSummary<'_>,
        _block_height: u32,
    ) -> bool {
        false
    }
    fn apply_all(
        &mut self,
        block: &RuntimeBlockContext,
    ) -> Result<Self::BlockOutput, ApplicationHostError>;
    fn rewind_all_to(&mut self, height: u32) -> Result<(), ApplicationHostError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationHostError {
    DuplicateApplicationId,
    ApplicationActivationMismatch { key: ApplicationDescriptor },
    TipMismatch,
    RetainedHistoryMismatch,
    ApplicationFailed { key: ApplicationDescriptor },
    RewindFailed { key: ApplicationDescriptor },
}

impl<A> HostedApplications for A
where
    A: CoppiceApplication,
    A::ApplyError: Debug,
    A::RewindError: Debug,
{
    type BlockOutput = A::BlockOutput;

    fn descriptors(&self) -> Vec<ApplicationDescriptor> {
        vec![self.descriptor()]
    }
    fn application_tips(&self) -> Vec<ApplicationTip> {
        vec![self.tip()]
    }
    fn oldest_rewind_height(&self) -> u32 {
        self.oldest_rewind_height()
    }
    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        self.retained_tip_at(height)
    }
    fn required_rewind_retention(&self) -> u32 {
        self.rewind_retention_blocks()
    }
    fn requests_extended_effects(
        &self,
        summary: &ApplicationCompactTransactionSummary<'_>,
        block_height: u32,
    ) -> bool {
        application_requests_extended_effects(self, summary, block_height)
    }
    fn apply_all(
        &mut self,
        block: &RuntimeBlockContext,
    ) -> Result<Self::BlockOutput, ApplicationHostError> {
        let descriptor = self.descriptor();
        let context = block
            .for_application(descriptor)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: descriptor })?;
        self.apply_block(&context)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: descriptor })
    }
    fn rewind_all_to(&mut self, height: u32) -> Result<(), ApplicationHostError> {
        let descriptor = self.descriptor();
        self.rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: descriptor })
    }
}

// Keep tuple implementations explicit: the public API remains static and
// deterministic without requiring a registry or erased application state.
impl<A, B> HostedApplications for (A, B)
where
    A: CoppiceApplication,
    B: CoppiceApplication,
    A::ApplyError: Debug,
    A::RewindError: Debug,
    B::ApplyError: Debug,
    B::RewindError: Debug,
{
    type BlockOutput = (A::BlockOutput, B::BlockOutput);
    fn descriptors(&self) -> Vec<ApplicationDescriptor> {
        vec![self.0.descriptor(), self.1.descriptor()]
    }
    fn application_tips(&self) -> Vec<ApplicationTip> {
        vec![self.0.tip(), self.1.tip()]
    }
    fn oldest_rewind_height(&self) -> u32 {
        self.0
            .oldest_rewind_height()
            .max(self.1.oldest_rewind_height())
    }
    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        let tip = self.0.retained_tip_at(height)?;
        (self.1.retained_tip_at(height) == Some(tip)).then_some(tip)
    }
    fn required_rewind_retention(&self) -> u32 {
        self.0
            .rewind_retention_blocks()
            .max(self.1.rewind_retention_blocks())
    }
    fn requests_extended_effects(
        &self,
        summary: &ApplicationCompactTransactionSummary<'_>,
        block_height: u32,
    ) -> bool {
        application_requests_extended_effects(&self.0, summary, block_height)
            || application_requests_extended_effects(&self.1, summary, block_height)
    }
    fn apply_all(
        &mut self,
        block: &RuntimeBlockContext,
    ) -> Result<Self::BlockOutput, ApplicationHostError> {
        let a = self.0.descriptor();
        let b = self.1.descriptor();
        let a_context = block
            .for_application(a)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: a })?;
        let b_context = block
            .for_application(b)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: b })?;
        Ok((
            self.0
                .apply_block(&a_context)
                .map_err(|_| ApplicationHostError::ApplicationFailed { key: a })?,
            self.1
                .apply_block(&b_context)
                .map_err(|_| ApplicationHostError::ApplicationFailed { key: b })?,
        ))
    }
    fn rewind_all_to(&mut self, height: u32) -> Result<(), ApplicationHostError> {
        let a = self.0.descriptor();
        let b = self.1.descriptor();
        self.0
            .rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: a })?;
        self.1
            .rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: b })
    }
}

impl<A, B, C> HostedApplications for (A, B, C)
where
    A: CoppiceApplication,
    B: CoppiceApplication,
    C: CoppiceApplication,
    A::ApplyError: Debug,
    A::RewindError: Debug,
    B::ApplyError: Debug,
    B::RewindError: Debug,
    C::ApplyError: Debug,
    C::RewindError: Debug,
{
    type BlockOutput = (A::BlockOutput, B::BlockOutput, C::BlockOutput);

    fn descriptors(&self) -> Vec<ApplicationDescriptor> {
        vec![
            self.0.descriptor(),
            self.1.descriptor(),
            self.2.descriptor(),
        ]
    }

    fn application_tips(&self) -> Vec<ApplicationTip> {
        vec![self.0.tip(), self.1.tip(), self.2.tip()]
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.0
            .oldest_rewind_height()
            .max(self.1.oldest_rewind_height())
            .max(self.2.oldest_rewind_height())
    }

    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        let tip = self.0.retained_tip_at(height)?;
        (self.1.retained_tip_at(height) == Some(tip) && self.2.retained_tip_at(height) == Some(tip))
            .then_some(tip)
    }

    fn required_rewind_retention(&self) -> u32 {
        self.0
            .rewind_retention_blocks()
            .max(self.1.rewind_retention_blocks())
            .max(self.2.rewind_retention_blocks())
    }
    fn requests_extended_effects(
        &self,
        summary: &ApplicationCompactTransactionSummary<'_>,
        block_height: u32,
    ) -> bool {
        application_requests_extended_effects(&self.0, summary, block_height)
            || application_requests_extended_effects(&self.1, summary, block_height)
            || application_requests_extended_effects(&self.2, summary, block_height)
    }

    fn apply_all(
        &mut self,
        block: &RuntimeBlockContext,
    ) -> Result<Self::BlockOutput, ApplicationHostError> {
        let a = self.0.descriptor();
        let b = self.1.descriptor();
        let c = self.2.descriptor();
        let a_context = block
            .for_application(a)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: a })?;
        let b_context = block
            .for_application(b)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: b })?;
        let c_context = block
            .for_application(c)
            .map_err(|_| ApplicationHostError::ApplicationFailed { key: c })?;
        Ok((
            self.0
                .apply_block(&a_context)
                .map_err(|_| ApplicationHostError::ApplicationFailed { key: a })?,
            self.1
                .apply_block(&b_context)
                .map_err(|_| ApplicationHostError::ApplicationFailed { key: b })?,
            self.2
                .apply_block(&c_context)
                .map_err(|_| ApplicationHostError::ApplicationFailed { key: c })?,
        ))
    }

    fn rewind_all_to(&mut self, height: u32) -> Result<(), ApplicationHostError> {
        let a = self.0.descriptor();
        let b = self.1.descriptor();
        let c = self.2.descriptor();
        self.0
            .rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: a })?;
        self.1
            .rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: b })?;
        self.2
            .rewind_to(height)
            .map_err(|_| ApplicationHostError::RewindFailed { key: c })
    }
}

/// Generic Core plus isolated application composition. `A` can be one
/// application or a statically typed tuple of applications.
#[derive(Clone)]
pub struct CoppiceRuntime<A: HostedApplications> {
    core: CoreRuntime,
    applications: A,
}

#[derive(Clone, Debug)]
pub struct CoppiceRuntimeAppliedBlock<O> {
    pub core: RuntimeBlockContext,
    pub applications: O,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoppiceRuntimeError {
    Core(crate::replay::CoreReplayError),
    Applications(ApplicationHostError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoppiceRuntimeRewindError {
    Core(CoreRewindError),
    Applications(ApplicationHostError),
}

impl<A: HostedApplications> CoppiceRuntime<A> {
    pub fn new(core: CoreRuntime, applications: A) -> Result<Self, ApplicationHostError> {
        let descriptors = applications.descriptors();
        if descriptors.iter().enumerate().any(|(i, descriptor)| {
            descriptors[..i]
                .iter()
                .any(|prior| prior.key == descriptor.key)
        }) {
            return Err(ApplicationHostError::DuplicateApplicationId);
        }
        let runtime_activation = core.parameters().parameters().runtime_activation_height;
        if let Some(descriptor) = descriptors
            .iter()
            .find(|descriptor| descriptor.validate_for_runtime(runtime_activation).is_err())
        {
            return Err(ApplicationHostError::ApplicationActivationMismatch { key: *descriptor });
        }
        if applications.required_rewind_retention() > core.configuration().retention_blocks() {
            return Err(ApplicationHostError::RetainedHistoryMismatch);
        }
        // The application may retain less history than Core, in which case
        // the composed host uses the application's newer common horizon. It
        // must not advertise a rewind point older than the Core journal can
        // actually restore.
        if applications.oldest_rewind_height() < core.oldest_rewind_height() {
            return Err(ApplicationHostError::RetainedHistoryMismatch);
        }
        let tip = core.tip();
        if applications
            .application_tips()
            .into_iter()
            .any(|app_tip| app_tip.height != tip.height || app_tip.block_hash != tip.block_hash)
        {
            return Err(ApplicationHostError::TipMismatch);
        }
        Ok(Self { core, applications })
    }

    pub fn core(&self) -> &CoreRuntime {
        &self.core
    }
    pub fn into_parts(self) -> (CoreRuntime, A) {
        (self.core, self.applications)
    }
    pub fn applications(&self) -> &A {
        &self.applications
    }
    pub fn required_rewind_retention(&self) -> u32 {
        self.applications.required_rewind_retention()
    }

    /// Returns the single full-transaction acquisition requirement for one
    /// compact canonical transaction. Core-owned carrier candidacy is unioned
    /// with every active application's read-only extended-effect request.
    pub fn full_transaction_acquisition(
        &self,
        summary: &CanonicalCompactTransactionSummary<'_>,
    ) -> FullTransactionAcquisition {
        let block_height = self.core.tip().height.saturating_add(1);
        FullTransactionAcquisition::new(
            summary.rendezvous_candidate,
            self.applications
                .requests_extended_effects(&summary.application_view(), block_height),
        )
    }

    pub fn apply_block(
        &mut self,
        input: &CoreCanonicalBlockInput,
    ) -> Result<CoppiceRuntimeAppliedBlock<A::BlockOutput>, CoppiceRuntimeError> {
        let mut core = self.core.clone();
        let mut applications = self.applications.clone();
        let block = core.apply_block(input).map_err(CoppiceRuntimeError::Core)?;
        let output = applications
            .apply_all(&block)
            .map_err(CoppiceRuntimeError::Applications)?;
        let tip = core.tip();
        if applications
            .application_tips()
            .into_iter()
            .any(|app_tip| app_tip.height != tip.height || app_tip.block_hash != tip.block_hash)
        {
            return Err(CoppiceRuntimeError::Applications(
                ApplicationHostError::TipMismatch,
            ));
        }
        self.core = core;
        self.applications = applications;
        Ok(CoppiceRuntimeAppliedBlock {
            core: block,
            applications: output,
        })
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), CoppiceRuntimeRewindError> {
        let mut core = self.core.clone();
        let mut applications = self.applications.clone();
        core.rewind_to(height)
            .map_err(CoppiceRuntimeRewindError::Core)?;
        applications
            .rewind_all_to(height)
            .map_err(CoppiceRuntimeRewindError::Applications)?;
        let tip = core.tip();
        if applications
            .application_tips()
            .into_iter()
            .any(|app_tip| app_tip.height != tip.height || app_tip.block_hash != tip.block_hash)
        {
            return Err(CoppiceRuntimeRewindError::Applications(
                ApplicationHostError::TipMismatch,
            ));
        }
        self.core = core;
        self.applications = applications;
        Ok(())
    }
}

impl<A: HostedApplications> CanonicalRuntime for CoppiceRuntime<A> {
    type BlockOutput = CoppiceRuntimeAppliedBlock<A::BlockOutput>;
    type ApplyError = CoppiceRuntimeError;
    type RewindError = CoppiceRuntimeRewindError;
    fn core_parameters(&self) -> &ValidatedCoreRuntimeParameters {
        self.core.parameters()
    }
    fn rendezvous(&self) -> &CoreRendezvous {
        self.core.rendezvous()
    }
    fn tip(&self) -> CoreReplayTip {
        self.core.tip()
    }
    fn oldest_rewind_height(&self) -> u32 {
        self.core
            .oldest_rewind_height()
            .max(self.applications.oldest_rewind_height())
    }
    fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        let core = self.core.retained_tip_at(height)?;
        let app = self.applications.retained_tip_at(height)?;
        (core.height == app.height && core.block_hash == app.block_hash).then_some(core)
    }
    fn full_transaction_acquisition(
        &self,
        summary: &CanonicalCompactTransactionSummary<'_>,
    ) -> FullTransactionAcquisition {
        CoppiceRuntime::full_transaction_acquisition(self, summary)
    }
    fn apply_canonical_block(
        &mut self,
        input: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        self.apply_block(input)
    }
    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        self.rewind_to(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::{
            ApplicationAcquisitionRequirement, ApplicationBlockContext,
            ApplicationCompactTransactionSummary, ApplicationId, ApplicationKey, ApplicationTip,
            CanonicalCompactTransactionSummary, CoppiceApplication,
        },
        identity::{CoreRuntimeParameters, ZcashNetwork},
        replay::{
            CoreCanonicalBlockInput, CoreReplay, CoreReplayActivationCheckpoint,
            CoreReplayConfiguration, FullTransactionAcquisition, IronwoodFrontier,
        },
    };
    use zcash_protocol::consensus::BranchId;

    const ACTIVATION_HEIGHT: u32 = 10;
    const ACTIVATION_HASH: [u8; 32] = [9; 32];

    fn core(retention_blocks: u32) -> CoreRuntime {
        let parameters = CoreRuntimeParameters {
            zcash_network_domain: b"coppice-runtime-regtest".to_vec(),
            zcash_network: ZcashNetwork::Regtest,
            runtime_activation_height: ACTIVATION_HEIGHT,
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
            CoreReplayConfiguration::new(ACTIVATION_HEIGHT, retention_blocks).unwrap(),
            CoreReplayActivationCheckpoint {
                height: ACTIVATION_HEIGHT - 1,
                block_hash: ACTIVATION_HASH,
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        CoreRuntime::new(parameters, replay).unwrap()
    }

    fn block(core: &CoreRuntime, height: u32, hash: u8) -> CoreCanonicalBlockInput {
        CoreCanonicalBlockInput {
            height,
            block_hash: [hash; 32],
            prev_block_hash: core.tip().block_hash,
            branch_id: BranchId::Nu6_3,
            transactions: vec![],
        }
    }

    #[derive(Clone, Debug)]
    struct TestApplication {
        descriptor: ApplicationDescriptor,
        tip: ApplicationTip,
        value: u8,
        retention_blocks: u32,
        fail_apply: bool,
        fail_rewind: bool,
        request_extended_effects: bool,
        history: Vec<(ApplicationTip, u8)>,
    }

    impl TestApplication {
        fn new(id: u8, activation_height: u32, tip: ApplicationTip, retention_blocks: u32) -> Self {
            Self {
                descriptor: ApplicationDescriptor {
                    key: ApplicationKey::new(ApplicationId::from_bytes([id; 32])),
                    activation_height,
                },
                tip,
                value: 0,
                retention_blocks,
                fail_apply: false,
                fail_rewind: false,
                request_extended_effects: false,
                history: vec![],
            }
        }
    }

    impl CoppiceApplication for TestApplication {
        type BlockOutput = u8;
        type ApplyError = ();
        type RewindError = ();

        fn descriptor(&self) -> ApplicationDescriptor {
            self.descriptor
        }

        fn tip(&self) -> ApplicationTip {
            self.tip
        }

        fn state_root(&self) -> [u8; 32] {
            [self.value; 32]
        }

        fn full_transaction_acquisition(
            &self,
            _summary: &ApplicationCompactTransactionSummary<'_>,
        ) -> ApplicationAcquisitionRequirement {
            if self.request_extended_effects {
                ApplicationAcquisitionRequirement::ExtendedEffects
            } else {
                ApplicationAcquisitionRequirement::None
            }
        }

        fn apply_block(&mut self, block: &ApplicationBlockContext) -> Result<u8, ()> {
            let next_tip = block.tip();
            if self.tip.height.checked_add(1) != Some(next_tip.height) {
                return Err(());
            }
            if block
                .core()
                .is_some_and(|core| core.prev_block_hash() != self.tip.block_hash)
            {
                return Err(());
            }
            self.history.push((self.tip, self.value));
            if block.is_active() {
                self.value = self.value.checked_add(1).ok_or(())?;
            }
            self.tip = next_tip;
            if self.history.len() > self.retention_blocks as usize {
                self.history.remove(0);
            }
            if self.fail_apply {
                return Err(());
            }
            Ok(self.value)
        }

        fn rewind_to(&mut self, height: u32) -> Result<(), ()> {
            if height < CoppiceApplication::oldest_rewind_height(self) || height > self.tip.height {
                return Err(());
            }
            let mut tip = self.tip;
            let mut value = self.value;
            let mut history = self.history.clone();
            while tip.height > height {
                let (prior_tip, prior_value) = history.pop().ok_or(())?;
                tip = prior_tip;
                value = prior_value;
            }
            if self.fail_rewind {
                return Err(());
            }
            self.tip = tip;
            self.value = value;
            self.history = history;
            Ok(())
        }

        fn rewind_retention_blocks(&self) -> u32 {
            self.retention_blocks
        }

        fn oldest_rewind_height(&self) -> u32 {
            self.history
                .first()
                .map_or(self.tip.height, |(tip, _)| tip.height)
        }

        fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
            if height == self.tip.height {
                Some(self.tip)
            } else {
                self.history
                    .iter()
                    .find(|(tip, _)| tip.height == height)
                    .map(|(tip, _)| *tip)
            }
        }
    }

    fn apps(core: &CoreRuntime, b_retention: u32) -> (TestApplication, TestApplication) {
        let tip = ApplicationTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        };
        (
            TestApplication::new(1, ACTIVATION_HEIGHT, tip, 2),
            TestApplication::new(2, ACTIVATION_HEIGHT, tip, b_retention),
        )
    }

    fn compact_summary(carrier: bool) -> CanonicalCompactTransactionSummary<'static> {
        CanonicalCompactTransactionSummary {
            tx_index: 0,
            txid: [1; 32],
            ironwood_nullifiers: &[],
            ironwood_commitments: &[],
            action_count: 0,
            rendezvous_candidate: carrier,
        }
    }

    #[test]
    fn acquisition_union_is_independent_and_activation_aware() {
        let core = core(4);
        let tip = ApplicationTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        };
        let mut none = TestApplication::new(1, ACTIVATION_HEIGHT, tip, 2);
        assert_eq!(
            CoppiceRuntime::new(core.clone(), none.clone())
                .unwrap()
                .full_transaction_acquisition(&compact_summary(false)),
            FullTransactionAcquisition::None
        );
        assert_eq!(
            CoppiceRuntime::new(core.clone(), none.clone())
                .unwrap()
                .full_transaction_acquisition(&compact_summary(true)),
            FullTransactionAcquisition::Carrier
        );

        none.request_extended_effects = true;
        assert_eq!(
            CoppiceRuntime::new(core.clone(), none.clone())
                .unwrap()
                .full_transaction_acquisition(&compact_summary(false)),
            FullTransactionAcquisition::ExtendedEffects
        );
        assert_eq!(
            CoppiceRuntime::new(core.clone(), none.clone())
                .unwrap()
                .full_transaction_acquisition(&compact_summary(true)),
            FullTransactionAcquisition::CarrierAndExtendedEffects
        );

        let mut other = TestApplication::new(2, ACTIVATION_HEIGHT, tip, 2);
        other.request_extended_effects = true;
        assert_eq!(
            CoppiceRuntime::new(core.clone(), (none.clone(), other.clone()))
                .unwrap()
                .full_transaction_acquisition(&compact_summary(false)),
            FullTransactionAcquisition::ExtendedEffects
        );
        none.request_extended_effects = false;
        other.request_extended_effects = false;
        assert_eq!(
            CoppiceRuntime::new(core.clone(), (none.clone(), other.clone()))
                .unwrap()
                .full_transaction_acquisition(&compact_summary(true)),
            FullTransactionAcquisition::Carrier
        );

        let mut third = TestApplication::new(3, ACTIVATION_HEIGHT, tip, 2);
        third.request_extended_effects = true;
        assert_eq!(
            CoppiceRuntime::new(core.clone(), (none, other, third))
                .unwrap()
                .full_transaction_acquisition(&compact_summary(true)),
            FullTransactionAcquisition::CarrierAndExtendedEffects
        );

        let mut pre_activation = TestApplication::new(4, ACTIVATION_HEIGHT + 1, tip, 2);
        pre_activation.request_extended_effects = true;
        let mut runtime = CoppiceRuntime::new(core.clone(), pre_activation).unwrap();
        let before = (runtime.core().tip(), runtime.applications().state_root());
        assert_eq!(
            runtime.full_transaction_acquisition(&compact_summary(false)),
            FullTransactionAcquisition::None
        );
        assert_eq!(
            (runtime.core().tip(), runtime.applications().state_root()),
            before
        );
        runtime
            .apply_block(&block(&core, ACTIVATION_HEIGHT, 10))
            .unwrap();
        let active_before = (runtime.core().tip(), runtime.applications().state_root());
        assert_eq!(
            runtime.full_transaction_acquisition(&compact_summary(false)),
            FullTransactionAcquisition::ExtendedEffects
        );
        assert_eq!(
            (runtime.core().tip(), runtime.applications().state_root()),
            active_before
        );
    }

    #[test]
    fn application_failure_publishes_nothing_to_core_or_siblings() {
        let mut core = core(4);
        let (mut a, b) = apps(&core, 3);
        a.fail_apply = true;
        let mut runtime = CoppiceRuntime::new(core.clone(), (a, b)).unwrap();
        let input = block(&core, ACTIVATION_HEIGHT, 10);
        let before_core = runtime.core().clone();
        let before_a = runtime.applications().0.clone();
        let before_b = runtime.applications().1.clone();

        assert!(matches!(
            runtime.apply_block(&input),
            Err(CoppiceRuntimeError::Applications(
                ApplicationHostError::ApplicationFailed { .. }
            ))
        ));
        assert_eq!(runtime.core().tip(), before_core.tip());
        assert_eq!(
            runtime.core().ironwood_frontier(),
            before_core.ironwood_frontier()
        );
        assert_eq!(runtime.applications().0.value, before_a.value);
        assert_eq!(runtime.applications().0.tip, before_a.tip);
        assert_eq!(runtime.applications().1.value, before_b.value);
        assert_eq!(runtime.applications().1.tip, before_b.tip);
        core = before_core;
        assert_eq!(core.tip().height, ACTIVATION_HEIGHT - 1);
    }

    #[test]
    fn failed_rewind_publishes_nothing_to_core_or_any_application() {
        let core = core(4);
        let (a, mut b) = apps(&core, 3);
        b.fail_rewind = true;
        let mut runtime = CoppiceRuntime::new(core.clone(), (a, b)).unwrap();
        let first = block(&core, ACTIVATION_HEIGHT, 10);
        runtime.apply_block(&first).unwrap();
        let second = block(runtime.core(), ACTIVATION_HEIGHT + 1, 11);
        runtime.apply_block(&second).unwrap();
        let before_core = runtime.core().clone();
        let before_apps = runtime.applications().clone();

        assert!(matches!(
            runtime.rewind_to(ACTIVATION_HEIGHT - 1),
            Err(CoppiceRuntimeRewindError::Applications(
                ApplicationHostError::RewindFailed { .. }
            ))
        ));
        assert_eq!(runtime.core().tip(), before_core.tip());
        assert_eq!(runtime.applications().0.value, before_apps.0.value);
        assert_eq!(runtime.applications().1.value, before_apps.1.value);
        assert_eq!(runtime.applications().0.tip, before_apps.0.tip);
        assert_eq!(runtime.applications().1.tip, before_apps.1.tip);
    }

    #[test]
    fn duplicate_keys_and_independent_activation_are_enforced() {
        let core = core(4);
        let tip = ApplicationTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        };
        let duplicate = TestApplication::new(1, ACTIVATION_HEIGHT, tip, 2);
        assert!(matches!(
            CoppiceRuntime::new(core.clone(), (duplicate.clone(), duplicate)),
            Err(ApplicationHostError::DuplicateApplicationId)
        ));

        let a = TestApplication::new(1, ACTIVATION_HEIGHT, tip, 2);
        let b = TestApplication::new(2, ACTIVATION_HEIGHT + 1, tip, 2);
        let mut runtime = CoppiceRuntime::new(core.clone(), (a, b)).unwrap();
        let first = block(&core, ACTIVATION_HEIGHT, 10);
        runtime.apply_block(&first).unwrap();
        assert_eq!(runtime.applications().0.value, 1);
        assert_eq!(runtime.applications().1.value, 0);
        let second = block(runtime.core(), ACTIVATION_HEIGHT + 1, 11);
        runtime.apply_block(&second).unwrap();
        assert_eq!(runtime.applications().0.value, 2);
        assert_eq!(runtime.applications().1.value, 1);
        assert_eq!(runtime.applications().0.tip, runtime.applications().1.tip);
        assert_eq!(runtime.applications().0.tip.height, ACTIVATION_HEIGHT + 1);
    }

    #[test]
    fn common_horizon_is_the_maximum_application_requirement_and_never_older_than_core() {
        let core = core(4);
        let mut runtime = CoppiceRuntime::new(core.clone(), apps(&core, 3)).unwrap();
        for height in ACTIVATION_HEIGHT..=ACTIVATION_HEIGHT + 2 {
            let input = block(runtime.core(), height, height as u8);
            runtime.apply_block(&input).unwrap();
        }

        assert_eq!(runtime.required_rewind_retention(), 3);
        assert_eq!(runtime.oldest_rewind_height(), 10);
        assert!(runtime.oldest_rewind_height() >= runtime.core().oldest_rewind_height());
        assert_eq!(runtime.retained_tip_at(10).unwrap().height, 10);
        assert!(runtime.retained_tip_at(9).is_none());
        runtime.rewind_to(10).unwrap();
        assert_eq!(runtime.core().tip().height, 10);
        assert_eq!(runtime.applications().0.tip.height, 10);
        assert_eq!(runtime.applications().1.tip.height, 10);
        assert_eq!(
            runtime.core().tip().block_hash,
            runtime.applications().0.tip.block_hash
        );
        assert_eq!(
            runtime.core().tip().block_hash,
            runtime.applications().1.tip.block_hash
        );
    }

    #[test]
    fn core_staging_publishes_only_after_explicit_handoff() {
        let mut runtime = core(4);
        let base_tip = runtime.tip();
        let input = block(&runtime, ACTIVATION_HEIGHT, 10);
        let staged = runtime.stage_block(&input).unwrap();

        assert_eq!(runtime.tip(), base_tip);
        assert_eq!(staged.base_tip(), base_tip);
        assert_eq!(staged.runtime().tip().height, ACTIVATION_HEIGHT);
        assert_eq!(staged.output().core().height(), ACTIVATION_HEIGHT);

        let output = runtime.publish_staged(staged).unwrap();
        assert_eq!(output.core().height(), ACTIVATION_HEIGHT);
        assert_eq!(runtime.tip().height, ACTIVATION_HEIGHT);

        let rewind = runtime.stage_rewind(ACTIVATION_HEIGHT - 1).unwrap();
        assert_eq!(runtime.tip().height, ACTIVATION_HEIGHT);
        runtime.publish_staged(rewind).unwrap();
        assert_eq!(runtime.tip(), base_tip);
    }

    #[test]
    fn stale_core_stage_cannot_overwrite_a_new_tip() {
        let mut runtime = core(4);
        let first = runtime
            .stage_block(&block(&runtime, ACTIVATION_HEIGHT, 10))
            .unwrap();
        let stale = runtime
            .stage_block(&block(&runtime, ACTIVATION_HEIGHT, 11))
            .unwrap();
        runtime.publish_staged(first).unwrap();
        assert_eq!(
            runtime.publish_staged(stale),
            Err(crate::runtime::StagedCorePublishError::BaseTipChanged)
        );
        assert_eq!(runtime.tip().block_hash, [10; 32]);
    }
}
