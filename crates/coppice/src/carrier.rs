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
    Build,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1CarrierError {
    NotFound,
    Malformed,
    Build,
}

/// Read-only result of decrypting and reconstructing one canonical v1 bulletin.
///
/// This intentionally has no `Debug`: an unpublished REVEAL payload contains
/// its registration secret.
pub struct V1BulletinInspection {
    operation: Operation,
    payload: Vec<u8>,
    frames: Vec<[u8; 512]>,
}

impl V1BulletinInspection {
    pub fn operation(&self) -> &Operation {
        &self.operation
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }
}
/// Returns the configured public incoming capability. It contains no spending authority.
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

/// Decodes the explicit canonical CPV1 carrier path.
pub fn decode_v1_bulletin_for(
    tx: &Transaction,
    rendezvous: Rendezvous,
    deployment_id: [u8; 32],
) -> Result<Operation, V1CarrierError> {
    inspect_v1_bulletin_for(tx, rendezvous, deployment_id).map(|inspection| inspection.operation)
}

/// Decrypts the exact CPV1 rendezvous frames from a finished Ironwood
/// transaction and reconstructs their canonical indexed payload.
pub fn inspect_v1_bulletin_for(
    tx: &Transaction,
    rendezvous: Rendezvous,
    deployment_id: [u8; 32],
) -> Result<V1BulletinInspection, V1CarrierError> {
    let bundle = tx.ironwood_bundle().ok_or(V1CarrierError::NotFound)?;
    let ivk = bulletin_ivk(rendezvous)
        .map_err(|_| V1CarrierError::Build)?
        .prepare();
    let frames = bundle
        .actions()
        .iter()
        .filter_map(|action| {
            let domain = IronwoodDomain::for_action(action);
            try_note_decryption(&domain, &ivk, action).map(|(_, _, memo)| memo)
        })
        .filter(carrier_v1::is_v1_frame)
        .collect::<Vec<_>>();
    let payload = reconstruct_v1_memos_for(&frames, deployment_id)?;
    let operation = envelope::decode_operation(&payload).map_err(|_| V1CarrierError::Malformed)?;
    Ok(V1BulletinInspection {
        operation,
        payload,
        frames,
    })
}

#[cfg(test)]
fn decode_v1_memos_for(
    memos: impl IntoIterator<Item = [u8; 512]>,
    deployment_id: [u8; 32],
) -> Result<Operation, V1CarrierError> {
    // Ironwood Action order is deliberately irrelevant. The transaction
    // builder may randomize action positions; indexed reconstruction below is
    // the sole carrier-order authority.
    let frames = memos
        .into_iter()
        .filter(carrier_v1::is_v1_frame)
        .collect::<Vec<_>>();
    let payload = reconstruct_v1_memos_for(&frames, deployment_id)?;
    envelope::decode_operation(&payload).map_err(|_| V1CarrierError::Malformed)
}

fn reconstruct_v1_memos_for(
    frames: &[[u8; 512]],
    deployment_id: [u8; 32],
) -> Result<Vec<u8>, V1CarrierError> {
    if frames.is_empty() {
        return Err(V1CarrierError::NotFound);
    }

    let payload = match carrier_v1::reconstruct_frames_v1(frames, deployment_id) {
        Ok(payload) => payload,
        Err(carrier_v1::Error::WrongDeployment) => return Err(V1CarrierError::NotFound),
        Err(_) => return Err(V1CarrierError::Malformed),
    };
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT_ID: [u8; 32] = [0x11; 32];

    #[test]
    fn v1_decrypted_memo_reconstruction_is_index_ordered() {
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

        let multi_payload = envelope::encode_operation(&Operation::Reveal {
            name: "shuffled".to_owned(),
            owner_pk: [1; 32],
            bond_tag: [2; 32],
            bond_anchor_height: 100,
            bond_anchor: [3; 32],
            bond_proof: vec![4; 4_960],
            address: vec![5; crate::constants::MAX_ADDRESS_LEN],
            secret: [6; 32],
        })
        .unwrap();
        let multi = carrier_v1::encode_frames_v1(DEPLOYMENT_ID, &multi_payload).unwrap();
        assert_eq!(multi.len(), 12);
        let mut builder_shuffled = multi.clone();
        builder_shuffled.rotate_left(5);
        builder_shuffled.swap(1, 8);
        assert_eq!(
            decode_v1_memos_for(builder_shuffled, DEPLOYMENT_ID),
            envelope::decode_operation(&multi_payload).map_err(|_| V1CarrierError::Malformed)
        );
        let mut extra = multi.clone();
        extra.push(multi[1]);
        assert_eq!(
            decode_v1_memos_for(extra, DEPLOYMENT_ID),
            Err(V1CarrierError::Malformed)
        );
    }
}
