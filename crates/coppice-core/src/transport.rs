//! Canonical CPV1 framing owned by the generic runtime.

use crate::{carrier, hash};

pub const ZIP302_ARBITRARY_DATA: u8 = 0xff;
pub const MAGIC: &[u8; 4] = b"CPV1";
pub const START_FRAME_TYPE: u8 = 0x00;
pub const CONT_FRAME_TYPE: u8 = 0x01;

const PREFIX_LEN: usize = 1 + MAGIC.len();
const FRAME_TYPE_OFFSET: usize = PREFIX_LEN;
const FRAME_INDEX_OFFSET: usize = FRAME_TYPE_OFFSET + 1;
const START_RUNTIME_OFFSET: usize = FRAME_INDEX_OFFSET + 1;
const START_FRAME_COUNT_OFFSET: usize = START_RUNTIME_OFFSET + 32;
const START_PAYLOAD_LENGTH_OFFSET: usize = START_FRAME_COUNT_OFFSET + 1;
const START_DIGEST_OFFSET: usize = START_PAYLOAD_LENGTH_OFFSET + 2;
const PAYLOAD_DIGEST_PERSONALIZATION: [u8; 16] = *b"CoppicePayloadV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoFrames,
    EmptyPayload,
    PayloadTooLarge,
    FrameCount,
    FrameCountMismatch,
    WrongMagic,
    NoStart,
    MultipleStart,
    InvalidStartIndex,
    InvalidContIndex,
    IndexOutOfRange,
    DuplicateIndex,
    MissingIndex,
    UnexpectedIndex,
    UnknownFrameType,
    WrongRuntime,
    Padding,
    DigestMismatch,
}

pub fn required_frames(payload_len: usize) -> Result<usize, Error> {
    if payload_len == 0 {
        return Err(Error::EmptyPayload);
    }
    if payload_len > carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge);
    }
    let count = if payload_len <= carrier::CPV1_START_CHUNK_CAPACITY {
        1
    } else {
        1 + (payload_len - carrier::CPV1_START_CHUNK_CAPACITY)
            .div_ceil(carrier::CPV1_CONTINUATION_CHUNK_CAPACITY)
    };
    if count == 0 || count > usize::from(carrier::CPV1_MAX_FRAMES) {
        return Err(Error::FrameCount);
    }
    Ok(count)
}

pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    hash::hash(&PAYLOAD_DIGEST_PERSONALIZATION, payload)
}

pub fn encode_frames(runtime_id: [u8; 32], payload: &[u8]) -> Result<Vec<[u8; 512]>, Error> {
    let frame_count = required_frames(payload.len())?;
    let digest = payload_digest(payload);
    let mut frames = Vec::with_capacity(frame_count);
    let start_chunk_len = payload.len().min(carrier::CPV1_START_CHUNK_CAPACITY);
    let mut start = [0u8; 512];
    write_prefix(&mut start, START_FRAME_TYPE, 0);
    start[START_RUNTIME_OFFSET..START_RUNTIME_OFFSET + runtime_id.len()]
        .copy_from_slice(&runtime_id);
    start[START_FRAME_COUNT_OFFSET] = frame_count as u8;
    start[START_PAYLOAD_LENGTH_OFFSET..START_PAYLOAD_LENGTH_OFFSET + 2]
        .copy_from_slice(&(payload.len() as u16).to_be_bytes());
    start[START_DIGEST_OFFSET..START_DIGEST_OFFSET + digest.len()].copy_from_slice(&digest);
    start[carrier::CPV1_START_FRAME_HEADER_LEN
        ..carrier::CPV1_START_FRAME_HEADER_LEN + start_chunk_len]
        .copy_from_slice(&payload[..start_chunk_len]);
    frames.push(start);

    let mut offset = start_chunk_len;
    while offset < payload.len() {
        let frame_index = u8::try_from(frames.len()).map_err(|_| Error::FrameCount)?;
        let chunk_len = (payload.len() - offset).min(carrier::CPV1_CONTINUATION_CHUNK_CAPACITY);
        let mut continuation = [0u8; 512];
        write_prefix(&mut continuation, CONT_FRAME_TYPE, frame_index);
        continuation[carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN
            ..carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN + chunk_len]
            .copy_from_slice(&payload[offset..offset + chunk_len]);
        frames.push(continuation);
        offset += chunk_len;
    }
    Ok(frames)
}

pub fn reconstruct_frames(
    frames: &[[u8; 512]],
    expected_runtime_id: [u8; 32],
) -> Result<Vec<u8>, Error> {
    if frames.is_empty() {
        return Err(Error::NoFrames);
    }
    if frames.len() > usize::from(carrier::CPV1_MAX_FRAMES) {
        return Err(Error::FrameCount);
    }
    let mut indexed: [Option<&[u8; 512]>; 32] = [None; 32];
    let mut start = None;
    for frame in frames {
        ensure_prefix(frame)?;
        let kind = frame[FRAME_TYPE_OFFSET];
        let index = frame[FRAME_INDEX_OFFSET];
        if index >= carrier::CPV1_MAX_FRAMES {
            return Err(Error::IndexOutOfRange);
        }
        match kind {
            START_FRAME_TYPE => {
                if index != 0 {
                    return Err(Error::InvalidStartIndex);
                }
                if start.replace(frame).is_some() {
                    return Err(Error::MultipleStart);
                }
            }
            CONT_FRAME_TYPE => {
                if index == 0 {
                    return Err(Error::InvalidContIndex);
                }
            }
            _ => return Err(Error::UnknownFrameType),
        }
        if indexed[usize::from(index)].replace(frame).is_some() {
            return Err(Error::DuplicateIndex);
        }
    }
    let start = start.ok_or(Error::NoStart)?;
    let (frame_count, payload_length) = start_metadata(start, expected_runtime_id)?;
    if indexed[frame_count..].iter().any(Option::is_some) {
        return Err(Error::UnexpectedIndex);
    }
    if indexed[..frame_count].iter().any(Option::is_none) {
        return Err(Error::MissingIndex);
    }
    if frames.len() != frame_count {
        return Err(Error::FrameCountMismatch);
    }
    let digest: [u8; 32] = start[START_DIGEST_OFFSET..START_DIGEST_OFFSET + 32]
        .try_into()
        .map_err(|_| Error::WrongMagic)?;
    let start_chunk_len = payload_length.min(carrier::CPV1_START_CHUNK_CAPACITY);
    let mut payload = Vec::with_capacity(payload_length);
    payload.extend_from_slice(
        &start[carrier::CPV1_START_FRAME_HEADER_LEN
            ..carrier::CPV1_START_FRAME_HEADER_LEN + start_chunk_len],
    );
    let mut offset = start_chunk_len;
    for frame in indexed.iter().take(frame_count).skip(1) {
        let frame = frame.expect("complete CPV1 frame set checked above");
        let remaining = payload_length
            .checked_sub(offset)
            .ok_or(Error::FrameCountMismatch)?;
        let chunk_len = remaining.min(carrier::CPV1_CONTINUATION_CHUNK_CAPACITY);
        if chunk_len == 0 {
            return Err(Error::FrameCountMismatch);
        }
        ensure_zero_padding(
            frame,
            carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN + chunk_len,
        )?;
        payload.extend_from_slice(
            &frame[carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN
                ..carrier::CPV1_CONTINUATION_FRAME_HEADER_LEN + chunk_len],
        );
        offset += chunk_len;
    }
    if payload.len() != payload_length || payload_digest(&payload) != digest {
        return Err(Error::DigestMismatch);
    }
    Ok(payload)
}

pub fn start_metadata(
    memo: &[u8; 512],
    expected_runtime_id: [u8; 32],
) -> Result<(usize, usize), Error> {
    ensure_prefix(memo)?;
    if memo[FRAME_TYPE_OFFSET] != START_FRAME_TYPE {
        return if memo[FRAME_TYPE_OFFSET] == CONT_FRAME_TYPE {
            Err(Error::NoStart)
        } else {
            Err(Error::UnknownFrameType)
        };
    }
    if memo[FRAME_INDEX_OFFSET] != 0 {
        return Err(Error::InvalidStartIndex);
    }
    if memo[START_RUNTIME_OFFSET..START_RUNTIME_OFFSET + 32] != expected_runtime_id {
        return Err(Error::WrongRuntime);
    }
    let frame_count = usize::from(memo[START_FRAME_COUNT_OFFSET]);
    if frame_count == 0 || frame_count > usize::from(carrier::CPV1_MAX_FRAMES) {
        return Err(Error::FrameCount);
    }
    let payload_length = usize::from(u16::from_be_bytes([
        memo[START_PAYLOAD_LENGTH_OFFSET],
        memo[START_PAYLOAD_LENGTH_OFFSET + 1],
    ]));
    if required_frames(payload_length)? != frame_count {
        return Err(Error::FrameCountMismatch);
    }
    let chunk_len = payload_length.min(carrier::CPV1_START_CHUNK_CAPACITY);
    ensure_zero_padding(memo, carrier::CPV1_START_FRAME_HEADER_LEN + chunk_len)?;
    Ok((frame_count, payload_length))
}

pub fn is_frame(memo: &[u8; 512]) -> bool {
    memo[..PREFIX_LEN]
        == [
            ZIP302_ARBITRARY_DATA,
            MAGIC[0],
            MAGIC[1],
            MAGIC[2],
            MAGIC[3],
        ]
}

fn write_prefix(memo: &mut [u8; 512], frame_type: u8, frame_index: u8) {
    memo[0] = ZIP302_ARBITRARY_DATA;
    memo[1..PREFIX_LEN].copy_from_slice(MAGIC);
    memo[FRAME_TYPE_OFFSET] = frame_type;
    memo[FRAME_INDEX_OFFSET] = frame_index;
}

fn ensure_prefix(memo: &[u8; 512]) -> Result<(), Error> {
    is_frame(memo).then_some(()).ok_or(Error::WrongMagic)
}

fn ensure_zero_padding(memo: &[u8; 512], first_padding_byte: usize) -> Result<(), Error> {
    if memo[first_padding_byte..].iter().any(|byte| *byte != 0) {
        Err(Error::Padding)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips_boundaries_and_is_runtime_bound() {
        for length in [1, 438, 439, 944, carrier::MAX_CPV1_PAYLOAD_LEN] {
            let payload = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let frames = encode_frames([0x11; 32], &payload).unwrap();
            assert_eq!(reconstruct_frames(&frames, [0x11; 32]), Ok(payload));
            assert_eq!(
                reconstruct_frames(&frames, [0x22; 32]),
                Err(Error::WrongRuntime)
            );
        }
    }

    #[test]
    fn malformed_sets_are_rejected_deterministically() {
        let frames = encode_frames([0x11; 32], &[7; 944]).unwrap();
        let mut duplicate = frames.clone();
        duplicate[2] = duplicate[1];
        assert_eq!(
            reconstruct_frames(&duplicate, [0x11; 32]),
            Err(Error::DuplicateIndex)
        );
        let mut bad_padding = frames;
        bad_padding[2][511] = 1;
        assert_eq!(
            reconstruct_frames(&bad_padding, [0x11; 32]),
            Err(Error::Padding)
        );
    }
}
