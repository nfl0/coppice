//! Ironwood carrier detection and bulletin decoding.
use crate::{
    carrier_v1,
    config::Rendezvous,
    envelope::{self, Operation},
};
use orchard::{keys::IncomingViewingKey, note_encryption::IronwoodDomain};
use zcash_note_encryption::{try_compact_note_decryption, try_note_decryption};
use zcash_primitives::transaction::Transaction;

#[derive(Debug)]
pub enum Error {
    NotFound,
    Envelope,
    Build,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1CarrierError {
    NotFound,
    Malformed,
    Build,
}
/// Returns the deployment's public incoming capability. It contains no spending authority.
pub fn bulletin_ivk(rendezvous: Rendezvous) -> Result<IncomingViewingKey, Error> {
    Option::from(IncomingViewingKey::from_bytes(&rendezvous.orchard_ivk)).ok_or(Error::Build)
}
pub fn bulletin_address(rendezvous: Rendezvous) -> Result<orchard::Address, Error> {
    Option::from(orchard::Address::from_raw_address_bytes(
        &rendezvous.orchard_receiver,
    ))
    .ok_or(Error::Build)
}
/// Detects a rendez-vous output from compact Ironwood data without fetching the full transaction.
pub fn compact_action_is_bulletin(
    action: &orchard::note_encryption::CompactAction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let domain = IronwoodDomain::for_compact_action(action);
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    Ok(try_compact_note_decryption(&domain, &ivk, action).is_some())
}

pub fn transaction_has_bulletin_output(
    tx: &Transaction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let Some(bundle) = tx.ironwood_bundle() else {
        return Ok(false);
    };
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    Ok(bundle.actions().iter().any(|action| {
        let domain = IronwoodDomain::for_action(action);
        try_note_decryption(&domain, &ivk, action).is_some()
    }))
}
pub fn decode_bulletin(tx: &Transaction) -> Result<Operation, Error> {
    decode_bulletin_for(tx, crate::config::TESTNET_V0.rendezvous)
}

pub fn decode_bulletin_for(tx: &Transaction, rendezvous: Rendezvous) -> Result<Operation, Error> {
    let b = tx.ironwood_bundle().ok_or(Error::NotFound)?;
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    let mut frames = Vec::new();
    let mut saw_coppice = false;
    for action in b.actions() {
        let domain = IronwoodDomain::for_action(action);
        if let Some((_, _, memo)) = try_note_decryption(&domain, &ivk, action) {
            if memo.starts_with(crate::DOMAIN) {
                saw_coppice = true;
                frames.push(envelope::frame_from_memo(&memo).map_err(|_| Error::Envelope)?);
            }
        }
    }
    if !saw_coppice {
        return Err(Error::NotFound);
    }
    let p = envelope::reconstruct(frames).map_err(|_| Error::Envelope)?;
    envelope::decode_operation(&p).map_err(|_| Error::Envelope)
}

/// Decodes the explicit canonical v1 carrier path. The V0 decoder above is
/// intentionally retained for legacy replay compatibility.
pub fn decode_v1_bulletin_for(
    tx: &Transaction,
    rendezvous: Rendezvous,
    deployment_id: [u8; 32],
) -> Result<Operation, V1CarrierError> {
    let bundle = tx.ironwood_bundle().ok_or(V1CarrierError::NotFound)?;
    let ivk = bulletin_ivk(rendezvous)
        .map_err(|_| V1CarrierError::Build)?
        .prepare();
    let memos = bundle.actions().iter().filter_map(|action| {
        let domain = IronwoodDomain::for_action(action);
        try_note_decryption(&domain, &ivk, action).map(|(_, _, memo)| memo)
    });
    decode_v1_memos_for(memos, deployment_id)
}

fn decode_v1_memos_for(
    memos: impl IntoIterator<Item = [u8; 512]>,
    deployment_id: [u8; 32],
) -> Result<Operation, V1CarrierError> {
    let mut frames = Vec::new();
    let mut saw_cont_before_start = false;
    let mut declared_frame_count = None;
    let mut complete = false;

    for memo in memos {
        if !carrier_v1::is_v1_frame(&memo) {
            if declared_frame_count.is_some() && !complete {
                return Err(V1CarrierError::Malformed);
            }
            continue;
        }

        if declared_frame_count.is_none() {
            match memo[5] {
                carrier_v1::CONT_FRAME_TYPE => {
                    saw_cont_before_start = true;
                }
                carrier_v1::START_FRAME_TYPE => {
                    let (frame_count, _) = match carrier_v1::start_metadata(&memo, deployment_id) {
                        Ok(metadata) => metadata,
                        Err(carrier_v1::Error::WrongDeployment) => {
                            return Err(V1CarrierError::NotFound);
                        }
                        Err(_) => return Err(V1CarrierError::Malformed),
                    };
                    if saw_cont_before_start {
                        return Err(V1CarrierError::Malformed);
                    }
                    frames.push(memo);
                    declared_frame_count = Some(frame_count);
                    complete = frame_count == 1;
                }
                _ => return Err(V1CarrierError::Malformed),
            }
            continue;
        }

        if complete {
            return Err(V1CarrierError::Malformed);
        }
        if memo[5] != carrier_v1::CONT_FRAME_TYPE {
            return Err(V1CarrierError::Malformed);
        }
        frames.push(memo);
        let Some(frame_count) = declared_frame_count else {
            return Err(V1CarrierError::Malformed);
        };
        complete = frames.len() == frame_count;
    }

    let Some(frame_count) = declared_frame_count else {
        return Err(V1CarrierError::NotFound);
    };
    if !complete || frames.len() != frame_count {
        return Err(V1CarrierError::Malformed);
    }

    let payload = carrier_v1::reconstruct_frames_v1(&frames, deployment_id)
        .map_err(|_| V1CarrierError::Malformed)?;
    envelope::decode_operation(&payload).map_err(|_| V1CarrierError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT_ID: [u8; 32] = [0x11; 32];

    #[test]
    fn v1_decrypted_memo_ordering_is_strict() {
        let payload = envelope::encode_operation(&Operation::Commit {
            commitment: [0x22; 32],
        })
        .unwrap();
        let frames = carrier_v1::encode_frames_v1(DEPLOYMENT_ID, &payload).unwrap();
        assert_eq!(
            decode_v1_memos_for(frames, DEPLOYMENT_ID),
            Ok(Operation::Commit {
                commitment: [0x22; 32]
            })
        );

        let other = carrier_v1::encode_frames_v1([0x33; 32], &payload).unwrap();
        assert_eq!(
            decode_v1_memos_for(other, DEPLOYMENT_ID),
            Err(V1CarrierError::NotFound)
        );

        let multi_payload = vec![0x44; 440];
        let multi = carrier_v1::encode_frames_v1(DEPLOYMENT_ID, &multi_payload).unwrap();
        let mut cont_first = multi.clone();
        cont_first.swap(0, 1);
        assert_eq!(
            decode_v1_memos_for(cont_first, DEPLOYMENT_ID),
            Err(V1CarrierError::Malformed)
        );
        let mut extra = multi.clone();
        extra.push(multi[1]);
        assert_eq!(
            decode_v1_memos_for(extra, DEPLOYMENT_ID),
            Err(V1CarrierError::Malformed)
        );
    }
}
