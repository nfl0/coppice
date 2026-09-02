//! Generic CPV1 transport limits and rendezvous candidate detection.

use crate::identity::ValidatedCoreRuntimeParameters;
use orchard::{
    Address,
    keys::{IncomingViewingKey, PreparedIncomingViewingKey},
    note_encryption::{CompactAction, IronwoodDomain},
};
use zcash_note_encryption::{try_compact_note_decryption, try_note_decryption};

pub const CPV1_PROTOCOL_ID: &[u8] = b"CPV1";

pub const CPV1_MAX_FRAMES: u8 = 32;
pub const CPV1_START_FRAME_HEADER_LEN: usize = 74;
pub const CPV1_START_CHUNK_CAPACITY: usize = 438;
pub const CPV1_CONTINUATION_FRAME_HEADER_LEN: usize = 7;
pub const CPV1_CONTINUATION_CHUNK_CAPACITY: usize = 505;

/// Maximum payload authenticated by one canonical CPV1 bulletin.
pub const MAX_CPV1_PAYLOAD_LEN: usize = 16_093;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousError {
    InvalidIncomingViewingKey,
    InvalidReceiver,
    ReceiverMismatch,
}

/// Decrypted note data exposed only after an exact rendezvous-receiver match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousNote {
    pub value: u64,
    pub memo: [u8; 512],
}

/// The validated generic Core rendezvous context.
///
/// Decryption under one Orchard IVK can succeed for many diversified
/// receivers. Core therefore carries the exact configured receiver alongside
/// the prepared IVK and requires both values at every carrier boundary.
#[derive(Clone, Debug)]
pub struct CoreRendezvous {
    prepared_ivk: PreparedIncomingViewingKey,
    receiver: [u8; 43],
}

impl CoreRendezvous {
    /// Constructs the context from the already validated generic runtime
    /// parameters. The validation invariant makes this infallible.
    pub fn from_validated(parameters: &ValidatedCoreRuntimeParameters) -> Self {
        Self::try_new(
            &parameters.parameters().rendezvous_ivk,
            &parameters.parameters().rendezvous_receiver,
        )
        .expect("validated Core rendezvous must remain valid")
    }

    /// Constructs and validates a generic rendezvous context from its raw
    /// protocol inputs.
    pub fn try_new(
        rendezvous_ivk: &[u8; 64],
        rendezvous_receiver: &[u8; 43],
    ) -> Result<Self, RendezvousError> {
        let ivk =
            Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(rendezvous_ivk))
                .ok_or(RendezvousError::InvalidIncomingViewingKey)?;
        let receiver =
            Option::<Address>::from(Address::from_raw_address_bytes(rendezvous_receiver))
                .ok_or(RendezvousError::InvalidReceiver)?;
        if ivk.diversifier_index(&receiver).is_none() {
            return Err(RendezvousError::ReceiverMismatch);
        }

        Ok(Self {
            prepared_ivk: ivk.prepare(),
            receiver: *rendezvous_receiver,
        })
    }

    pub const fn receiver(&self) -> &[u8; 43] {
        &self.receiver
    }

    /// Detects a rendezvous output from compact Ironwood data.
    pub fn compact_action_is_rendezvous(&self, action: &CompactAction) -> bool {
        let domain = IronwoodDomain::for_compact_action(action);
        try_compact_note_decryption(&domain, &self.prepared_ivk, action)
            .is_some_and(|(_, recipient)| recipient.to_raw_address_bytes() == self.receiver)
    }

    /// Returns the memo only when a full Ironwood action decrypts to the exact
    /// configured receiver. This is the authoritative full-transaction
    /// boundary used before CPV1 routing.
    pub fn action_note<A>(&self, action: &orchard::Action<A>) -> Option<RendezvousNote> {
        try_note_decryption(
            &IronwoodDomain::for_action(action),
            &self.prepared_ivk,
            action,
        )
        .and_then(|(note, recipient, memo)| {
            (recipient.to_raw_address_bytes() == self.receiver).then_some(RendezvousNote {
                value: note.value().inner(),
                memo,
            })
        })
    }

    /// Returns the memo only for the exact configured receiver.
    pub fn action_memo<A>(&self, action: &orchard::Action<A>) -> Option<[u8; 512]> {
        self.action_note(action).map(|note| note.memo)
    }

    pub fn action_is_rendezvous<A>(&self, action: &orchard::Action<A>) -> bool {
        self.action_note(action).is_some()
    }
}

/// Detects a rendezvous output from compact Ironwood data.
///
/// The context includes both the generic public incoming viewing key and the
/// exact receiver configured for this runtime. Applications do not
/// participate in candidate classification.
pub fn compact_action_is_rendezvous(action: &CompactAction, rendezvous: &CoreRendezvous) -> bool {
    rendezvous.compact_action_is_rendezvous(action)
}
