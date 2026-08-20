//! Coppice POC: strict envelope and deterministic replay. No consensus code is modified.
pub mod bond;
pub mod carrier;
pub mod constants;
pub mod envelope;
pub mod incremental;
pub mod ironwood;
pub mod name_tree;
pub mod owner;
pub mod replay;
pub mod spent;
pub mod state;
pub mod vectors;

pub const DOMAIN: &[u8] = constants::PROTOCOL_ID;
pub const DEFAULT_TAG_BITS: usize = constants::DEFAULT_TEST_TAG_BITS as usize;

pub fn txid_matches_tag(txid: &[u8; 32], tag: u16, bits: usize) -> bool {
    if bits == 0 || bits > 16 {
        return false;
    }
    let prefix = u16::from_be_bytes([txid[0], txid[1]]);
    (prefix >> (16 - bits)) == (tag >> (16 - bits))
}

/// Coppice uses the most-significant `tag_bits` of the txid's canonical byte encoding.
/// The POC tag is zero, so a candidate has that prefix equal to zero.
pub fn is_coppice_candidate(txid: &zcash_primitives::transaction::TxId, tag_bits: u8) -> bool {
    if tag_bits == 0 || tag_bits > 16 {
        return false;
    }
    let raw: [u8; 32] = (*txid).into();
    txid_matches_tag(&raw, 0, tag_bits as usize)
}

#[cfg(test)]
mod tag_tests {
    use super::*;
    use zcash_primitives::transaction::TxId;
    #[test]
    fn candidate_bit_order_is_big_endian_prefix() {
        let mut matching = [0u8; 32];
        matching[1] = 0x0f;
        let mut nonmatching = [0u8; 32];
        nonmatching[1] = 0x10;
        assert!(is_coppice_candidate(&TxId::from_bytes(matching), 12));
        assert!(!is_coppice_candidate(&TxId::from_bytes(nonmatching), 12));
        assert!(!is_coppice_candidate(&TxId::from_bytes([0; 32]), 0));
        assert!(!is_coppice_candidate(&TxId::from_bytes([0; 32]), 17));
    }
}
