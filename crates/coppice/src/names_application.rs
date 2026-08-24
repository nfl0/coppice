//! Coppice Names v1 identity and generic application-envelope adapters.
//!
//! These APIs are additive. Production replay and carrier decoding continue to
//! use the existing qualified path until the runtime cutover is implemented.

use coppice_core::application::{
    ApplicationDescriptor, ApplicationEnvelopeError, ApplicationEnvelopeV1, ApplicationId,
    ApplicationKey, derive_application_id,
};

use crate::{
    config::{DeploymentEncodingError, DeploymentParameters},
    envelope::{self, Operation},
};

/// Exact application-family identity bytes frozen for Coppice Names.
///
/// The application version is carried separately, so later versions retain
/// the family ID and use a different `ApplicationKey::version`.
pub const NAMES_CANONICAL_APPLICATION_IDENTITY: &[u8] = b"coppice.names";
pub const NAMES_V1_APPLICATION_VERSION: u16 = 1;

pub fn names_application_id() -> ApplicationId {
    derive_application_id(NAMES_CANONICAL_APPLICATION_IDENTITY)
        .expect("the frozen Names application identity is nonempty")
}

pub fn names_v1_application_key() -> ApplicationKey {
    ApplicationKey::new(names_application_id(), NAMES_V1_APPLICATION_VERSION)
}

/// Names v1 initially shares the runtime activation height. This descriptor is
/// not an input to `CoreRuntimeId`; later applications may activate at later
/// heights without changing that runtime identity.
pub fn names_v1_application_descriptor(runtime_activation_height: u32) -> ApplicationDescriptor {
    ApplicationDescriptor {
        key: names_v1_application_key(),
        activation_height: runtime_activation_height,
    }
}

/// The existing Coppice Names deployment identifier, preserved byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamesDeploymentId([u8; 32]);

impl NamesDeploymentId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_parameters(
        parameters: &DeploymentParameters,
    ) -> Result<Self, DeploymentEncodingError> {
        parameters.deployment_id().map(Self)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesApplicationEnvelopeError {
    Application(ApplicationEnvelopeError),
    WrongApplication,
    Operation(envelope::Error),
}

pub fn encode_names_v1_envelope(
    operation: &Operation,
) -> Result<Vec<u8>, NamesApplicationEnvelopeError> {
    let payload =
        envelope::encode_operation(operation).map_err(NamesApplicationEnvelopeError::Operation)?;
    ApplicationEnvelopeV1::new(names_v1_application_key(), payload)
        .map_err(NamesApplicationEnvelopeError::Application)
        .map(|value| value.encode())
}

pub fn decode_names_v1_envelope(bytes: &[u8]) -> Result<Operation, NamesApplicationEnvelopeError> {
    let application =
        ApplicationEnvelopeV1::decode(bytes).map_err(NamesApplicationEnvelopeError::Application)?;
    if application.key() != names_v1_application_key() {
        return Err(NamesApplicationEnvelopeError::WrongApplication);
    }
    envelope::decode_operation(application.payload())
        .map_err(NamesApplicationEnvelopeError::Operation)
}
