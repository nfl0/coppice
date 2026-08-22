//! Ironwood carrier detection and bulletin decoding.
use crate::{
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
