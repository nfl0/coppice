//! Generic CPV1 transport limits.

pub const CPV1_PROTOCOL_ID: &[u8] = b"CPV1";

pub const CPV1_MAX_FRAMES: u8 = 32;
pub const CPV1_START_FRAME_HEADER_LEN: usize = 74;
pub const CPV1_START_CHUNK_CAPACITY: usize = 438;
pub const CPV1_CONTINUATION_FRAME_HEADER_LEN: usize = 7;
pub const CPV1_CONTINUATION_CHUNK_CAPACITY: usize = 505;

/// Maximum payload authenticated by one canonical CPV1 bulletin.
pub const MAX_CPV1_PAYLOAD_LEN: usize = 16_093;
