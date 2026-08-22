//! Canonical RedPallas owner authorization for the POC state machine.
use crate::{constants, crypto, envelope::Operation, legacy_state::NameRecord};
use orchard::primitives::redpallas::{Signature, SigningKey, SpendAuth, VerificationKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub type OwnerSigningKey = SigningKey<SpendAuth>;
pub type OwnerVerificationKey = VerificationKey<SpendAuth>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerKeyError;
pub fn parse_owner_key(bytes: [u8; 32]) -> Result<OwnerVerificationKey, OwnerKeyError> {
    OwnerVerificationKey::try_from(bytes).map_err(|_| OwnerKeyError)
}
pub fn owner_key_bytes(key: &OwnerVerificationKey) -> [u8; 32] {
    key.into()
}
pub fn name_id(name: &str) -> [u8; 32] {
    crypto::hash("CoppiceNameV1", name.as_bytes()).expect("fixed v1 name hash label")
}
pub fn canonical_record_bytes(r: &NameRecord) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&r.owner_pk);
    b.extend_from_slice(&r.bond_tag);
    b.extend_from_slice(&r.sequence.to_be_bytes());
    b.push(if matches!(r.status, crate::legacy_state::Status::Active) {
        1
    } else {
        2
    });
    b.extend_from_slice(&(r.address.len() as u16).to_be_bytes());
    b.extend_from_slice(&r.address);
    b
}
pub fn record_hash(r: &NameRecord) -> [u8; 32] {
    let mut b = constants::NAME_RECORD_DOMAIN.to_vec();
    b.extend_from_slice(&canonical_record_bytes(r));
    Sha256::digest(b).into()
}
pub fn authorization_message(op: &Operation, previous: &NameRecord) -> Option<Vec<u8>> {
    let mut b = constants::OWNER_SIGNATURE_DOMAIN.to_vec();
    b.extend_from_slice(&(constants::PROTOCOL_ID.len() as u16).to_be_bytes());
    b.extend_from_slice(constants::PROTOCOL_ID);
    b.extend_from_slice(&(constants::NETWORK_ID.len() as u16).to_be_bytes());
    b.extend_from_slice(constants::NETWORK_ID);
    match op {
        Operation::Update {
            name,
            sequence,
            address,
            ..
        } => {
            b.push(2);
            b.extend_from_slice(&name_id(name));
            b.extend_from_slice(&previous.sequence.to_be_bytes());
            b.extend_from_slice(&sequence.to_be_bytes());
            b.extend_from_slice(&record_hash(previous));
            b.extend_from_slice(&Sha256::digest(address));
        }
        Operation::Release { name, sequence, .. } => {
            b.push(3);
            b.extend_from_slice(&name_id(name));
            b.extend_from_slice(&previous.sequence.to_be_bytes());
            b.extend_from_slice(&sequence.to_be_bytes());
            b.extend_from_slice(&record_hash(previous));
        }
        _ => return None,
    }
    Some(b)
}
pub fn sign_operation(
    key: &OwnerSigningKey,
    op: &Operation,
    previous: &NameRecord,
) -> Option<Vec<u8>> {
    let msg = authorization_message(op, previous)?;
    Some(<[u8; 64]>::from(&key.sign(OsRng, &msg)).to_vec())
}

/// Builds and signs the canonical next UPDATE for `name`.
pub fn signed_update(
    key: &OwnerSigningKey,
    name: &str,
    address: Vec<u8>,
    previous: &NameRecord,
) -> Option<Operation> {
    let sequence = previous.sequence.checked_add(1)?;
    let mut operation = Operation::Update {
        name: name.to_owned(),
        sequence,
        address,
        signature: vec![],
    };
    let signature = sign_operation(key, &operation, previous)?;
    if let Operation::Update {
        signature: output, ..
    } = &mut operation
    {
        *output = signature;
    }
    Some(operation)
}

/// Builds and signs the canonical next RELEASE for `name`.
pub fn signed_release(
    key: &OwnerSigningKey,
    name: &str,
    previous: &NameRecord,
) -> Option<Operation> {
    let sequence = previous.sequence.checked_add(1)?;
    let mut operation = Operation::Release {
        name: name.to_owned(),
        sequence,
        signature: vec![],
    };
    let signature = sign_operation(key, &operation, previous)?;
    if let Operation::Release {
        signature: output, ..
    } = &mut operation
    {
        *output = signature;
    }
    Some(operation)
}

pub fn verify_operation(key_bytes: [u8; 32], op: &Operation, previous: &NameRecord) -> bool {
    let Ok(key) = parse_owner_key(key_bytes) else {
        return false;
    };
    let sig = match op {
        Operation::Update { signature, .. } | Operation::Release { signature, .. } => signature,
        _ => return false,
    };
    let Ok(bytes): Result<[u8; 64], _> = sig.as_slice().try_into() else {
        return false;
    };
    let msg = match authorization_message(op, previous) {
        Some(v) => v,
        None => return false,
    };
    key.verify(&msg, &Signature::from(bytes)).is_ok()
}

#[cfg(test)]
mod name_vectors {
    use super::*;

    #[test]
    fn p_name_001_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/names.json")).unwrap();

        for vector in fixture["vectors"].as_array().unwrap() {
            let name = vector["input_utf8"].as_str().unwrap();
            let valid = vector["valid"].as_bool().unwrap();
            assert_eq!(crate::envelope::valid_name(name), valid, "{name:?}");

            if valid {
                let expected: [u8; 32] =
                    hex::decode(vector["expected_name_id_hex"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                assert_eq!(name_id(name), expected, "{name:?}");
            }
        }
    }
}
