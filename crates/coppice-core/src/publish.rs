//! Generic CAPP-in-CPCF publication preparation.
//!
//! Wallet construction is host-specific, but every builder gets the exact
//! envelope and ordered memo frames that Core will later inspect.

use crate::{
    application::{ApplicationEnvelope, ApplicationEnvelopeError, ApplicationKey},
    identity::CoreRuntimeId,
    runtime::{ApplicationMessageStatus, RuntimeTransactionInspection, inspect_transaction},
    transport,
};
use zcash_primitives::transaction::Transaction;

/// Canonical generic publication material. Application-specific transaction
/// policy (fees, bond selection, authorisation, pending local state) layers on
/// top of this primitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedApplicationPublication {
    key: ApplicationKey,
    envelope: Vec<u8>,
    frames: Box<[[u8; 512]]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationPreparationError {
    Envelope(ApplicationEnvelopeError),
    Framing(transport::Error),
}

impl PreparedApplicationPublication {
    pub fn prepare(
        runtime_id: CoreRuntimeId,
        key: ApplicationKey,
        payload: Vec<u8>,
    ) -> Result<Self, PublicationPreparationError> {
        let envelope = ApplicationEnvelope::new(key, payload)
            .map_err(PublicationPreparationError::Envelope)?
            .encode();
        let frames = transport::encode_frames(runtime_id.to_bytes(), &envelope)
            .map_err(PublicationPreparationError::Framing)?
            .into_boxed_slice();
        Ok(Self {
            key,
            envelope,
            frames,
        })
    }

    pub const fn key(&self) -> ApplicationKey {
        self.key
    }
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }

    /// Verifies a constructed transaction against Core's authoritative
    /// inspection rules, including the exact configured rendezvous receiver.
    pub fn verify_constructed_transaction(
        &self,
        transaction: &Transaction,
        parameters: &crate::identity::ValidatedCoreRuntimeParameters,
    ) -> Result<RuntimeTransactionInspection, PublicationVerificationError> {
        let inspection = inspect_transaction(transaction, parameters);
        if inspection.frames() != self.frames() {
            return Err(PublicationVerificationError::FrameMismatch);
        }
        match inspection.message() {
            ApplicationMessageStatus::Message(message)
                if message.key() == self.key && message.encode() == self.envelope =>
            {
                Ok(inspection)
            }
            _ => Err(PublicationVerificationError::RouteMismatch),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationVerificationError {
    FrameMismatch,
    RouteMismatch,
}
