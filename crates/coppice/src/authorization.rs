use crate::{owner, registration::address_digest};

const OWNER_SIGNATURE_PREFIX: &[u8] = b"CoppiceOwnerSigV1";

fn prefix(deployment_id: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OWNER_SIGNATURE_PREFIX.len() + 32);
    bytes.extend_from_slice(OWNER_SIGNATURE_PREFIX);
    bytes.extend_from_slice(&deployment_id);
    bytes
}

pub fn update_authorization_message(
    deployment_id: [u8; 32],
    name: &str,
    previous_record_hash: [u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    new_address: &[u8],
) -> Vec<u8> {
    let mut bytes = prefix(deployment_id);
    bytes.push(0x03);
    bytes.extend_from_slice(&owner::name_id(name));
    bytes.extend_from_slice(&previous_record_hash);
    bytes.extend_from_slice(&previous_sequence.to_be_bytes());
    bytes.extend_from_slice(&next_sequence.to_be_bytes());
    bytes.extend_from_slice(&address_digest(new_address));
    bytes
}

pub fn release_authorization_message(
    deployment_id: [u8; 32],
    name: &str,
    previous_record_hash: [u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
) -> Vec<u8> {
    let mut bytes = prefix(deployment_id);
    bytes.push(0x04);
    bytes.extend_from_slice(&owner::name_id(name));
    bytes.extend_from_slice(&previous_record_hash);
    bytes.extend_from_slice(&previous_sequence.to_be_bytes());
    bytes.extend_from_slice(&next_sequence.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const DEPLOYMENT_ID: &str = "0f769b29c0ed5c5f9a101300e15c846ca15aeae2198043da3e785f839a56f5d7";

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn operations_fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/operations.json")).unwrap()
    }

    fn vector<'a>(fixture: &'a Value, id: &str) -> &'a Value {
        fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some(id))
            .unwrap()
    }

    fn expected_bytes(fixture: &Value, id: &str) -> Vec<u8> {
        hex::decode(vector(fixture, id)["expected_hex"].as_str().unwrap()).unwrap()
    }

    fn previous_record_hash() -> [u8; 32] {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/records.json")).unwrap();
        let active = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some("active"))
            .unwrap();
        fixed32(active["record_hash_hex"].as_str().unwrap())
    }

    #[test]
    fn update_owner_message_vector_matches() {
        let fixture = operations_fixture();
        let actual = update_authorization_message(
            fixed32(DEPLOYMENT_ID),
            "alice",
            previous_record_hash(),
            0,
            1,
            b"u1synthetic-new-address",
        );
        assert_eq!(actual, expected_bytes(&fixture, "update-owner-message"));
    }

    #[test]
    fn release_owner_message_vector_matches() {
        let fixture = operations_fixture();
        let actual = release_authorization_message(
            fixed32(DEPLOYMENT_ID),
            "alice",
            previous_record_hash(),
            0,
            1,
        );
        assert_eq!(actual, expected_bytes(&fixture, "release-owner-message"));
    }
}
