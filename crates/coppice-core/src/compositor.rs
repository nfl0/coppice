//! Generic atomic composition of Core and isolated deterministic applications.
//!
//! The compositor has no application registry and no cross-application call
//! path. It merely derives one application-scoped context per descriptor from
//! a single Core scan and commits the staged states together.

use crate::{
    application::{ApplicationDescriptor, ApplicationTip, CoppiceApplication},
    carrier::CoreRendezvous,
    identity::ValidatedCoreRuntimeParameters,
    replay::{CoreCanonicalBlockInput, CoreReplayTip, CoreRewindError},
    runtime::{CanonicalRuntime, CoreRuntime, RuntimeBlockContext},
};
use std::fmt::Debug;

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
    fn apply_all(
        &mut self,
        block: &RuntimeBlockContext,
    ) -> Result<Self::BlockOutput, ApplicationHostError>;
    fn rewind_all_to(&mut self, height: u32) -> Result<(), ApplicationHostError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationHostError {
    DuplicateApplicationKey,
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
            return Err(ApplicationHostError::DuplicateApplicationKey);
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
