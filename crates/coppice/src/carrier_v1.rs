//! Canonical Coppice v1 carrier framing over raw Ironwood memo plaintexts.
//!
//! Operation serialization is provided by [`crate::envelope`]. The carrier has
//! an explicit frame index, but no nonce or per-frame length; reconstruction is
//! scoped to one transaction.

use crate::{constants, crypto};

pub const ZIP302_ARBITRARY_DATA: u8 = 0xff;
pub const MAGIC: &[u8; 4] = b"CPV1";
pub const START_FRAME_TYPE: u8 = 0x00;
pub const CONT_FRAME_TYPE: u8 = 0x01;

const PREFIX_LEN: usize = 1 + MAGIC.len();
const FRAME_TYPE_OFFSET: usize = PREFIX_LEN;
const FRAME_INDEX_OFFSET: usize = FRAME_TYPE_OFFSET + 1;
const START_DEPLOYMENT_OFFSET: usize = FRAME_INDEX_OFFSET + 1;
const START_FRAME_COUNT_OFFSET: usize = START_DEPLOYMENT_OFFSET + 32;
const START_PAYLOAD_LENGTH_OFFSET: usize = START_FRAME_COUNT_OFFSET + 1;
const START_DIGEST_OFFSET: usize = START_PAYLOAD_LENGTH_OFFSET + 2;

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
    WrongDeployment,
    Padding,
    DigestMismatch,
    Hash(crypto::Error),
}

/// Returns the exact v1 frame count for a non-empty, bounded payload.
pub fn required_frames(payload_len: usize) -> Result<usize, Error> {
    if payload_len == 0 {
        return Err(Error::EmptyPayload);
    }
    if payload_len > constants::MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge);
    }

    let count = if payload_len <= constants::START_CHUNK_CAP {
        1
    } else {
        1 + (payload_len - constants::START_CHUNK_CAP).div_ceil(constants::CONT_CHUNK_CAP)
    };
    if count == 0 || count > usize::from(constants::MAX_FRAMES) {
        return Err(Error::FrameCount);
    }
    Ok(count)
}

pub fn payload_digest(payload: &[u8]) -> Result<[u8; 32], Error> {
    crypto::hash("CoppicePayloadV1", payload).map_err(Error::Hash)
}

/// Encodes one deterministic v1 carrier as complete 512-byte memo plaintexts.
pub fn encode_frames_v1(deployment_id: [u8; 32], payload: &[u8]) -> Result<Vec<[u8; 512]>, Error> {
    let frame_count = required_frames(payload.len())?;
    let digest = payload_digest(payload)?;
    let mut frames = Vec::with_capacity(frame_count);

    let start_chunk_len = payload.len().min(constants::START_CHUNK_CAP);
    let mut start = [0u8; 512];
    write_prefix(&mut start, START_FRAME_TYPE, 0);
    start[START_DEPLOYMENT_OFFSET..START_DEPLOYMENT_OFFSET + deployment_id.len()]
        .copy_from_slice(&deployment_id);
    start[START_FRAME_COUNT_OFFSET] = frame_count as u8;
    start[START_PAYLOAD_LENGTH_OFFSET..START_PAYLOAD_LENGTH_OFFSET + 2]
        .copy_from_slice(&(payload.len() as u16).to_be_bytes());
    start[START_DIGEST_OFFSET..START_DIGEST_OFFSET + digest.len()].copy_from_slice(&digest);
    start[constants::START_FRAME_HEADER..constants::START_FRAME_HEADER + start_chunk_len]
        .copy_from_slice(&payload[..start_chunk_len]);
    frames.push(start);

    let mut offset = start_chunk_len;
    while offset < payload.len() {
        let frame_index = u8::try_from(frames.len()).map_err(|_| Error::FrameCount)?;
        let chunk_len = (payload.len() - offset).min(constants::CONT_CHUNK_CAP);
        let mut cont = [0u8; 512];
        write_prefix(&mut cont, CONT_FRAME_TYPE, frame_index);
        cont[constants::CONT_FRAME_HEADER..constants::CONT_FRAME_HEADER + chunk_len]
            .copy_from_slice(&payload[offset..offset + chunk_len]);
        frames.push(cont);
        offset += chunk_len;
    }

    debug_assert_eq!(frames.len(), frame_count);
    Ok(frames)
}

/// Validates the START metadata and returns `(frame_count, payload_length)`.
pub fn start_metadata(
    memo: &[u8; 512],
    expected_deployment_id: [u8; 32],
) -> Result<(usize, usize), Error> {
    ensure_prefix(memo)?;
    match memo[FRAME_TYPE_OFFSET] {
        START_FRAME_TYPE => {}
        CONT_FRAME_TYPE => return Err(Error::NoStart),
        _ => return Err(Error::UnknownFrameType),
    }
    if memo[FRAME_INDEX_OFFSET] != 0 {
        return Err(Error::InvalidStartIndex);
    }

    if memo[START_DEPLOYMENT_OFFSET..START_DEPLOYMENT_OFFSET + 32] != expected_deployment_id {
        return Err(Error::WrongDeployment);
    }

    let frame_count = usize::from(memo[START_FRAME_COUNT_OFFSET]);
    if frame_count == 0 || frame_count > usize::from(constants::MAX_FRAMES) {
        return Err(Error::FrameCount);
    }
    let payload_length = usize::from(u16::from_be_bytes([
        memo[START_PAYLOAD_LENGTH_OFFSET],
        memo[START_PAYLOAD_LENGTH_OFFSET + 1],
    ]));
    let required = required_frames(payload_length)?;
    if frame_count != required {
        return Err(Error::FrameCountMismatch);
    }
    let start_chunk_len = payload_length.min(constants::START_CHUNK_CAP);
    ensure_zero_padding(memo, constants::START_FRAME_HEADER + start_chunk_len)?;
    Ok((frame_count, payload_length))
}

/// Reconstructs an arbitrarily action-ordered set of raw v1 memo plaintexts.
pub fn reconstruct_frames_v1(
    frames: &[[u8; 512]],
    expected_deployment_id: [u8; 32],
) -> Result<Vec<u8>, Error> {
    if frames.is_empty() {
        return Err(Error::NoFrames);
    }
    if frames.len() > usize::from(constants::MAX_FRAMES) {
        return Err(Error::FrameCount);
    }

    let mut indexed: [Option<&[u8; 512]>; 32] = [None; 32];
    let mut start = None;
    for frame in frames {
        ensure_prefix(frame)?;
        let kind = frame[FRAME_TYPE_OFFSET];
        let index = frame[FRAME_INDEX_OFFSET];
        if index >= constants::MAX_FRAMES {
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
        let slot = &mut indexed[usize::from(index)];
        if slot.replace(frame).is_some() {
            return Err(Error::DuplicateIndex);
        }
    }

    let start = start.ok_or(Error::NoStart)?;
    let (frame_count, payload_length) = start_metadata(start, expected_deployment_id)?;
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
    let start_chunk_len = payload_length.min(constants::START_CHUNK_CAP);
    let mut payload = Vec::with_capacity(payload_length);
    payload.extend_from_slice(
        &start[constants::START_FRAME_HEADER..constants::START_FRAME_HEADER + start_chunk_len],
    );

    let mut offset = start_chunk_len;
    for frame in indexed.iter().take(frame_count).skip(1) {
        let frame = frame.expect("complete index set checked above");
        let remaining = payload_length
            .checked_sub(offset)
            .ok_or(Error::FrameCountMismatch)?;
        let chunk_len = remaining.min(constants::CONT_CHUNK_CAP);
        if chunk_len == 0 {
            return Err(Error::FrameCountMismatch);
        }
        ensure_zero_padding(frame, constants::CONT_FRAME_HEADER + chunk_len)?;
        payload.extend_from_slice(
            &frame[constants::CONT_FRAME_HEADER..constants::CONT_FRAME_HEADER + chunk_len],
        );
        offset += chunk_len;
    }

    if payload.len() != payload_length || offset != payload_length {
        return Err(Error::FrameCountMismatch);
    }
    if payload_digest(&payload)? != digest {
        return Err(Error::DigestMismatch);
    }
    Ok(payload)
}

pub fn is_v1_frame(memo: &[u8; 512]) -> bool {
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
    if is_v1_frame(memo) {
        Ok(())
    } else {
        Err(Error::WrongMagic)
    }
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

    const DEPLOYMENT_ID: [u8; 32] = [
        0x0f, 0x76, 0x9b, 0x29, 0xc0, 0xed, 0x5c, 0x5f, 0x9a, 0x10, 0x13, 0x00, 0xe1, 0x5c, 0x84,
        0x6c, 0xa1, 0x5a, 0xea, 0xe2, 0x19, 0x80, 0x43, 0xda, 0x3e, 0x78, 0x5f, 0x83, 0x9a, 0x56,
        0xf5, 0xd7,
    ];

    fn expected_frames(vector: &serde_json::Value) -> Vec<[u8; 512]> {
        vector["frame_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|frame| {
                hex::decode(frame.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect()
    }

    fn payload_from_expected_frames(frames: &[[u8; 512]], payload_length: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(payload_length);
        let start_chunk_len = payload_length.min(constants::START_CHUNK_CAP);
        payload.extend_from_slice(
            &frames[0]
                [constants::START_FRAME_HEADER..constants::START_FRAME_HEADER + start_chunk_len],
        );
        let mut offset = start_chunk_len;
        for frame in frames.iter().skip(1) {
            let chunk_len = (payload_length - offset).min(constants::CONT_CHUNK_CAP);
            payload.extend_from_slice(
                &frame[constants::CONT_FRAME_HEADER..constants::CONT_FRAME_HEADER + chunk_len],
            );
            offset += chunk_len;
        }
        assert_eq!(offset, payload_length);
        payload
    }

    fn patterned_payload(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn all_carrier_vectors_match_byte_for_byte() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/carrier.json")).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 6);
        assert_eq!(fixture["start_chunk_cap"], constants::START_CHUNK_CAP);
        assert_eq!(fixture["cont_chunk_cap"], constants::CONT_CHUNK_CAP);
        assert_eq!(fixture["start_header"], constants::START_FRAME_HEADER);
        assert_eq!(fixture["cont_header"], constants::CONT_FRAME_HEADER);
        assert_eq!(fixture["frame_index_offset"], FRAME_INDEX_OFFSET);
        assert_eq!(fixture["max_frames"], constants::MAX_FRAMES);
        assert_eq!(fixture["max_payload_len"], constants::MAX_PAYLOAD_LEN);

        let permutation = &fixture["permutation_cases"][0];
        assert_eq!(permutation["frame_order"], serde_json::json!([2, 0, 1]));
        let permutation_payload = patterned_payload(944);
        let permutation_frames = encode_frames_v1(DEPLOYMENT_ID, &permutation_payload).unwrap();
        let shuffled = permutation["frame_order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| permutation_frames[index.as_u64().unwrap() as usize])
            .collect::<Vec<_>>();
        assert_eq!(
            reconstruct_frames_v1(&shuffled, DEPLOYMENT_ID).unwrap(),
            permutation_payload
        );
        assert_eq!(
            fixture["negative_cases"],
            serde_json::json!([
                {"id":"duplicate-index","expected_error":"DuplicateIndex"},
                {"id":"missing-index","expected_error":"MissingIndex"},
                {"id":"out-of-range-index","expected_error":"IndexOutOfRange"}
            ])
        );

        for vector in vectors {
            let payload_length = vector["payload_length"].as_u64().unwrap() as usize;
            let expected = expected_frames(vector);
            assert_eq!(expected.len(), vector["expected_frame_count"]);
            assert_eq!(required_frames(payload_length).unwrap(), expected.len());

            let payload = match vector["payload_hex"].as_str() {
                Some(payload_hex) => hex::decode(payload_hex).unwrap(),
                None => payload_from_expected_frames(&expected, payload_length),
            };
            assert_eq!(payload.len(), payload_length, "{} payload", vector["id"]);
            assert_eq!(
                hex::encode(payload_digest(&payload).unwrap()),
                vector["payload_digest_hex"].as_str().unwrap(),
                "{} digest",
                vector["id"]
            );

            let encoded = encode_frames_v1(DEPLOYMENT_ID, &payload).unwrap();
            assert_eq!(encoded, expected, "{} frames", vector["id"]);
            assert!(
                encoded
                    .iter()
                    .enumerate()
                    .all(|(index, frame)| usize::from(frame[FRAME_INDEX_OFFSET]) == index)
            );
            assert_eq!(
                reconstruct_frames_v1(&expected, DEPLOYMENT_ID).unwrap(),
                payload,
                "{} reconstruction",
                vector["id"]
            );
        }
    }

    #[test]
    fn required_frame_boundaries_are_exact() {
        assert_eq!(required_frames(1).unwrap(), 1);
        assert_eq!(required_frames(constants::START_CHUNK_CAP).unwrap(), 1);
        assert_eq!(required_frames(constants::START_CHUNK_CAP + 1).unwrap(), 2);
        assert_eq!(required_frames(943).unwrap(), 2);
        assert_eq!(required_frames(944).unwrap(), 3);
        assert_eq!(required_frames(constants::MAX_PAYLOAD_LEN).unwrap(), 32);
        assert_eq!(
            required_frames(constants::MAX_PAYLOAD_LEN + 1),
            Err(Error::PayloadTooLarge)
        );
    }

    fn assert_rejected(label: &str, frames: &[[u8; 512]]) {
        assert!(
            reconstruct_frames_v1(frames, DEPLOYMENT_ID).is_err(),
            "{label}"
        );
    }

    #[test]
    fn canonical_negative_cases_are_rejected_without_panics() {
        assert_eq!(
            encode_frames_v1(DEPLOYMENT_ID, &[]),
            Err(Error::EmptyPayload)
        );
        assert_eq!(
            encode_frames_v1(DEPLOYMENT_ID, &vec![0; constants::MAX_PAYLOAD_LEN + 1]),
            Err(Error::PayloadTooLarge)
        );
        assert_rejected("empty frame set", &[]);

        let one = encode_frames_v1(DEPLOYMENT_ID, b"one").unwrap();
        let mut frame_count_zero = one.clone();
        frame_count_zero[0][START_FRAME_COUNT_OFFSET] = 0;
        assert_rejected("frame count zero", &frame_count_zero);
        let mut frame_count_large = one.clone();
        frame_count_large[0][START_FRAME_COUNT_OFFSET] = constants::MAX_FRAMES + 1;
        assert_rejected("frame count over 32", &frame_count_large);

        let mut wrong_count = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        wrong_count[0][START_FRAME_COUNT_OFFSET] = 1;
        assert_rejected("wrong required frame count", &wrong_count);

        let mut reversed = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        reversed.reverse();
        assert_eq!(
            reconstruct_frames_v1(&reversed, DEPLOYMENT_ID).unwrap(),
            vec![0; 439]
        );

        let mut duplicate_start = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        duplicate_start[1] = duplicate_start[0];
        assert_rejected("duplicate START", &duplicate_start);

        let mut unknown_type = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        unknown_type[1][FRAME_TYPE_OFFSET] = 0x02;
        assert_rejected("unknown frame type", &unknown_type);

        let mut wrong_deployment = one.clone();
        wrong_deployment[0][START_DEPLOYMENT_OFFSET] ^= 1;
        assert_rejected("wrong deployment ID", &wrong_deployment);

        let mut payload_length_mismatch = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        payload_length_mismatch[0][START_PAYLOAD_LENGTH_OFFSET..START_PAYLOAD_LENGTH_OFFSET + 2]
            .copy_from_slice(&438u16.to_be_bytes());
        assert_rejected("payload length mismatch", &payload_length_mismatch);

        let mut digest_mutation = one.clone();
        digest_mutation[0][START_DIGEST_OFFSET] ^= 1;
        assert_rejected("payload digest mutation", &digest_mutation);

        let mut start_padding = one.clone();
        start_padding[0][constants::START_FRAME_HEADER + 3] = 1;
        assert_rejected("START padding nonzero", &start_padding);

        let mut cont_padding = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        cont_padding[1][constants::CONT_FRAME_HEADER + 1] = 1;
        assert_rejected("CONT padding nonzero", &cont_padding);

        let valid_multi = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 944]).unwrap();
        let missing_final = valid_multi[..2].to_vec();
        assert_eq!(
            reconstruct_frames_v1(&missing_final, DEPLOYMENT_ID),
            Err(Error::MissingIndex)
        );
        let missing_middle = vec![valid_multi[0], valid_multi[2]];
        assert_eq!(
            reconstruct_frames_v1(&missing_middle, DEPLOYMENT_ID),
            Err(Error::MissingIndex)
        );
        let mut extra_cont = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        let mut extra = extra_cont[1];
        extra[FRAME_INDEX_OFFSET] = 2;
        extra_cont.push(extra);
        assert_eq!(
            reconstruct_frames_v1(&extra_cont, DEPLOYMENT_ID),
            Err(Error::UnexpectedIndex)
        );

        let truncated = valid_multi[..2].to_vec();
        assert_eq!(
            reconstruct_frames_v1(&truncated, DEPLOYMENT_ID),
            Err(Error::MissingIndex)
        );

        let mut conflicting = encode_frames_v1(DEPLOYMENT_ID, b"first").unwrap();
        let second = encode_frames_v1(DEPLOYMENT_ID, b"second").unwrap();
        conflicting.extend(second);
        assert_rejected("conflicting second operation", &conflicting);

        let mut bad_start_index = one.clone();
        bad_start_index[0][FRAME_INDEX_OFFSET] = 5;
        assert_eq!(
            reconstruct_frames_v1(&bad_start_index, DEPLOYMENT_ID),
            Err(Error::InvalidStartIndex)
        );
        let mut old_no_index = one[0];
        old_no_index.copy_within(FRAME_INDEX_OFFSET + 1.., FRAME_INDEX_OFFSET);
        old_no_index[511] = 0;
        assert_eq!(
            reconstruct_frames_v1(&[old_no_index], DEPLOYMENT_ID),
            Err(Error::InvalidStartIndex)
        );
        let mut cont_zero = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        cont_zero[1][FRAME_INDEX_OFFSET] = 0;
        assert_eq!(
            reconstruct_frames_v1(&cont_zero, DEPLOYMENT_ID),
            Err(Error::InvalidContIndex)
        );
        let mut out_of_range = encode_frames_v1(DEPLOYMENT_ID, &vec![0; 439]).unwrap();
        out_of_range[1][FRAME_INDEX_OFFSET] = 32;
        assert_eq!(
            reconstruct_frames_v1(&out_of_range, DEPLOYMENT_ID),
            Err(Error::IndexOutOfRange)
        );
        let mut duplicate_index = valid_multi.clone();
        duplicate_index[2][FRAME_INDEX_OFFSET] = 1;
        assert_eq!(
            reconstruct_frames_v1(&duplicate_index, DEPLOYMENT_ID),
            Err(Error::DuplicateIndex)
        );

        let mut no_start = valid_multi[1..].to_vec();
        no_start[0][FRAME_INDEX_OFFSET] = 1;
        assert_eq!(
            reconstruct_frames_v1(&no_start, DEPLOYMENT_ID),
            Err(Error::NoStart)
        );

        let mut foreign_chunk = valid_multi.clone();
        let other = encode_frames_v1(DEPLOYMENT_ID, &patterned_payload(944)).unwrap();
        foreign_chunk[1] = other[1];
        assert_eq!(
            reconstruct_frames_v1(&foreign_chunk, DEPLOYMENT_ID),
            Err(Error::DigestMismatch)
        );
    }

    #[test]
    fn arbitrary_frame_permutations_reconstruct_exact_payload() {
        let payload = patterned_payload(5_555);
        let frames = encode_frames_v1(DEPLOYMENT_ID, &payload).unwrap();
        assert!(frames.len() > 3);

        let mut reverse = frames.clone();
        reverse.reverse();
        assert_eq!(
            reconstruct_frames_v1(&reverse, DEPLOYMENT_ID).unwrap(),
            payload
        );

        let mut rotation = frames.clone();
        rotation.rotate_left(3);
        assert_eq!(
            reconstruct_frames_v1(&rotation, DEPLOYMENT_ID).unwrap(),
            payload
        );

        let mut shuffled = frames;
        shuffled.sort_by_key(|frame| (frame[FRAME_INDEX_OFFSET].wrapping_mul(11)) % 17);
        assert_eq!(
            reconstruct_frames_v1(&shuffled, DEPLOYMENT_ID).unwrap(),
            payload
        );
    }

    #[test]
    fn max_vector_payload_is_reconstructed_from_its_normative_frames() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/carrier.json")).unwrap();
        let vector = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"] == "payload-16093")
            .unwrap();
        let frames = expected_frames(vector);
        let payload = reconstruct_frames_v1(&frames, DEPLOYMENT_ID).unwrap();
        assert_eq!(payload.len(), constants::MAX_PAYLOAD_LEN);
        assert_eq!(payload, patterned_payload(constants::MAX_PAYLOAD_LEN));
    }

    #[test]
    #[ignore = "explicit deterministic normative carrier-vector regeneration"]
    fn regenerate_carrier_vectors() {
        let lengths = [1, 438, 439, 943, 944, constants::MAX_PAYLOAD_LEN];
        let vectors = lengths
            .into_iter()
            .map(|payload_length| {
                let payload = patterned_payload(payload_length);
                let frames = encode_frames_v1(DEPLOYMENT_ID, &payload).unwrap();
                serde_json::json!({
                    "id": format!("payload-{payload_length}"),
                    "requirement_ids": ["P-CARRIER-002", "P-CARRIER-003"],
                    "payload_length": payload_length,
                    "payload_hex": if payload_length == constants::MAX_PAYLOAD_LEN {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::String(hex::encode(&payload))
                    },
                    "payload_digest_hex": hex::encode(payload_digest(&payload).unwrap()),
                    "expected_frame_count": frames.len(),
                    "frame_hex": frames.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let fixture = serde_json::json!({
            "status": "FROZEN_COMPLETE",
            "requirement_ids": ["P-CARRIER-002", "P-CARRIER-003"],
            "deployment_id_hex": hex::encode(DEPLOYMENT_ID),
            "frame_size": 512,
            "frame_index_offset": FRAME_INDEX_OFFSET,
            "start_header": constants::START_FRAME_HEADER,
            "start_chunk_cap": constants::START_CHUNK_CAP,
            "cont_header": constants::CONT_FRAME_HEADER,
            "cont_chunk_cap": constants::CONT_CHUNK_CAP,
            "max_frames": constants::MAX_FRAMES,
            "max_payload_len": constants::MAX_PAYLOAD_LEN,
            "permutation_cases": [{
                "id": "payload-944-shuffled",
                "payload_length": 944,
                "frame_order": [2, 0, 1]
            }],
            "negative_cases": [
                {"id": "duplicate-index", "expected_error": "DuplicateIndex"},
                {"id": "missing-index", "expected_error": "MissingIndex"},
                {"id": "out-of-range-index", "expected_error": "IndexOutOfRange"}
            ],
            "vectors": vectors,
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/carrier.json"
        );
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    }
}
