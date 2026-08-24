//! Generic CPV1 transport limits and rendezvous candidate detection.

use orchard::{keys::IncomingViewingKey, note_encryption::IronwoodDomain};
use zcash_note_encryption::try_compact_note_decryption;

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
}

/// Detects a rendezvous output from compact Ironwood data.
///
/// The rendezvous is represented only by the generic public incoming viewing
/// key bytes. Applications do not participate in candidate classification.
pub fn compact_action_is_rendezvous(
    action: &orchard::note_encryption::CompactAction,
    rendezvous_ivk: &[u8; 64],
) -> Result<bool, RendezvousError> {
    let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(rendezvous_ivk))
        .ok_or(RendezvousError::InvalidIncomingViewingKey)?;
    let domain = IronwoodDomain::for_compact_action(action);
    Ok(try_compact_note_decryption(&domain, &ivk.prepare(), action).is_some())
}
