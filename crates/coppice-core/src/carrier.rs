//! Generic CPV1 transport limits.

pub const CPV1_PROTOCOL_ID: &[u8] = b"CPV1";

/// Maximum payload authenticated by one canonical CPV1 bulletin.
pub const MAX_CPV1_PAYLOAD_LEN: usize = 16_093;
