//! Canonical machine-readable identity for Core semantics and wire constants.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RULESET_DOMAIN: &str = "coppice-core-semantics";
pub const RULESET_PERSONALIZATION: &[u8] = b"CoppiceCoreRule";

const EMBEDDED_MANIFEST: &[u8] = include_bytes!("../../../ruleset/core.json");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    clauses: Vec<Clause>,
    constants: Constants,
    domain: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Clause {
    effect: Vec<String>,
    id: String,
    inputs: Vec<String>,
    rule_type: String,
    when: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Constants {
    application_envelope_header_bytes: usize,
    application_envelope_magic_hex: String,
    carrier_continuation_header_bytes: usize,
    carrier_frame_bytes: usize,
    carrier_magic_hex: String,
    carrier_max_frames: u8,
    carrier_max_payload_bytes: usize,
    carrier_start_header_bytes: usize,
}

fn validate_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn parsed_manifest() -> Manifest {
    let manifest: Manifest =
        serde_json::from_slice(EMBEDDED_MANIFEST).expect("embedded Core ruleset is valid JSON");
    assert_eq!(
        manifest.domain, RULESET_DOMAIN,
        "Core ruleset domain mismatch"
    );
    assert_eq!(
        manifest.constants.application_envelope_header_bytes,
        crate::application::APPLICATION_ENVELOPE_HEADER_LEN
    );
    assert_eq!(
        manifest.constants.application_envelope_magic_hex,
        hex_string(&crate::application::APPLICATION_ENVELOPE_MAGIC)
    );
    assert_eq!(
        manifest.constants.carrier_continuation_header_bytes,
        crate::carrier::CARRIER_CONTINUATION_FRAME_HEADER_LEN
    );
    assert_eq!(manifest.constants.carrier_frame_bytes, 512);
    assert_eq!(
        manifest.constants.carrier_magic_hex,
        hex_string(crate::transport::MAGIC)
    );
    assert_eq!(
        manifest.constants.carrier_max_frames,
        crate::carrier::MAX_CARRIER_FRAMES
    );
    assert_eq!(
        manifest.constants.carrier_max_payload_bytes,
        crate::carrier::MAX_CARRIER_PAYLOAD_LEN
    );
    assert_eq!(
        manifest.constants.carrier_start_header_bytes,
        crate::carrier::CARRIER_START_FRAME_HEADER_LEN
    );
    let mut identifiers = BTreeSet::new();
    for clause in &manifest.clauses {
        assert!(
            validate_ascii(&clause.id)
                && validate_ascii(&clause.rule_type)
                && clause.inputs.iter().all(|value| validate_ascii(value))
                && clause.when.iter().all(|value| validate_ascii(value))
                && clause.effect.iter().all(|value| validate_ascii(value)),
            "Core ruleset strings must be nonempty printable ASCII"
        );
        assert!(
            identifiers.insert(clause.id.as_str()),
            "Core ruleset clause identifiers must be unique"
        );
    }
    manifest
}

fn hex_string(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

pub fn canonical_manifest() -> Vec<u8> {
    let value: Value = serde_json::to_value(parsed_manifest()).expect("manifest is serializable");
    serde_json::to_vec(&value).expect("manifest is serializable")
}

pub fn clause_ids() -> BTreeSet<String> {
    parsed_manifest()
        .clauses
        .into_iter()
        .map(|clause| clause.id)
        .collect()
}

pub fn ruleset_fingerprint() -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(RULESET_PERSONALIZATION)
        .hash(&canonical_manifest())
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_manifest_is_canonical_and_bound_to_code_constants() {
        assert_eq!(
            EMBEDDED_MANIFEST
                .strip_suffix(b"\n")
                .unwrap_or(EMBEDDED_MANIFEST),
            canonical_manifest()
        );
        assert_ne!(ruleset_fingerprint(), [0; 32]);
        assert!(!clause_ids().is_empty());
    }
}
