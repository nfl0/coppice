//! Public Ironwood rendezvous construction and compact candidate detection.
//!
//! CPV1 framing, runtime binding, and application-envelope routing are owned
//! by `coppice-core`.

use crate::config::Rendezvous;
use orchard::{keys::IncomingViewingKey, note_encryption::IronwoodDomain};
use zcash_note_encryption::try_compact_note_decryption;

#[derive(Debug)]
pub enum Error {
    Build,
}

/// Returns the configured public incoming capability. It contains no spending
/// authority.
pub fn bulletin_ivk(rendezvous: Rendezvous) -> Result<IncomingViewingKey, Error> {
    Option::from(IncomingViewingKey::from_bytes(&rendezvous.orchard_ivk)).ok_or(Error::Build)
}

pub fn bulletin_address(rendezvous: Rendezvous) -> Result<orchard::Address, Error> {
    Option::from(orchard::Address::from_raw_address_bytes(
        &rendezvous.orchard_receiver,
    ))
    .ok_or(Error::Build)
}

/// Detects a rendezvous output from compact Ironwood data without fetching
/// unrelated full transactions.
pub fn compact_action_is_bulletin(
    action: &orchard::note_encryption::CompactAction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let domain = IronwoodDomain::for_compact_action(action);
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    Ok(try_compact_note_decryption(&domain, &ivk, action).is_some())
}
