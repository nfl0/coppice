use coppice::{
    carrier_v1,
    config::{DeploymentParameters, Rendezvous},
    constants,
    envelope::{self, Operation},
    names_application::{
        NAMES_CANONICAL_APPLICATION_IDENTITY, NAMES_V1_APPLICATION_VERSION,
        NamesApplicationEnvelopeError, NamesDeploymentId, decode_names_v1_envelope,
        encode_names_v1_envelope, names_application_id, names_v1_application_descriptor,
        names_v1_application_key,
    },
};
use coppice_core::{
    application::{
        APPLICATION_ENVELOPE_HEADER_LEN, APPLICATION_ID_PERSONALIZATION, ApplicationDescriptor,
        ApplicationEnvelopeError, ApplicationEnvelopeV1, ApplicationId, ApplicationKey,
        MAX_APPLICATION_ENVELOPE_LEN, derive_application_id,
    },
    identity::{CoreRuntimeId, CoreRuntimeParameters, ZcashNetwork},
};
use zcash_protocol::consensus::NetworkType;

fn fixed32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn runtime_fixture() -> (serde_json::Value, CoreRuntimeParameters) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/core_runtime_id.json")).unwrap();
    let input = &fixture["input"];
    let parameters = CoreRuntimeParameters {
        runtime_protocol_id: hex::decode(input["runtime_protocol_id_hex"].as_str().unwrap())
            .unwrap(),
        runtime_protocol_version: input["runtime_protocol_version"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        zcash_network_domain: hex::decode(input["zcash_network_domain_hex"].as_str().unwrap())
            .unwrap(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: input["runtime_activation_height"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        carrier_protocol_id: hex::decode(input["carrier_protocol_id_hex"].as_str().unwrap())
            .unwrap(),
        rendezvous_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        rendezvous_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    (fixture, parameters)
}

fn names_deployment_fixture() -> (serde_json::Value, DeploymentParameters) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
    let input = &fixture["input"];
    let parameters = DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: input["activation_height"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: input["commit_ttl_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        reuse_delay_blocks: input["reuse_delay_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        bond_note_max_age_blocks: input["bond_note_max_age_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    };
    (fixture, parameters)
}

#[test]
fn three_identity_vector_and_future_transport_binding_match() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/application_envelopes.json"
    ))
    .unwrap();
    let derivation = &fixture["application_id_derivation"];
    let names = &fixture["names_v1"];
    let (_, runtime_parameters) = runtime_fixture();
    let (deployment_fixture, names_parameters) = names_deployment_fixture();

    let core_runtime_id = runtime_parameters.core_runtime_id().unwrap();
    let names_deployment_id = NamesDeploymentId::from_parameters(&names_parameters).unwrap();
    assert_eq!(
        core_runtime_id,
        CoreRuntimeId::from_bytes(fixed32(names["core_runtime_id_hex"].as_str().unwrap()))
    );
    assert_eq!(
        names_deployment_id,
        NamesDeploymentId::from_bytes(fixed32(names["names_deployment_id_hex"].as_str().unwrap()))
    );
    assert_eq!(
        hex::encode(names_deployment_id.to_bytes()),
        deployment_fixture["expected_deployment_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_ne!(core_runtime_id.to_bytes(), names_deployment_id.to_bytes());

    assert_eq!(
        hex::encode(APPLICATION_ID_PERSONALIZATION),
        derivation["personalization_hex"].as_str().unwrap()
    );
    assert_eq!(
        NAMES_CANONICAL_APPLICATION_IDENTITY,
        &hex::decode(
            derivation["canonical_application_identity_hex"]
                .as_str()
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        names_application_id(),
        ApplicationId::from_bytes(fixed32(
            derivation["expected_application_id_hex"].as_str().unwrap()
        ))
    );
    assert_eq!(
        NAMES_V1_APPLICATION_VERSION,
        names["application_version"].as_u64().unwrap() as u16
    );

    let operation_payload = hex::decode(names["operation_payload_hex"].as_str().unwrap()).unwrap();
    let operation = envelope::decode_operation(&operation_payload).unwrap();
    let encoded = encode_names_v1_envelope(&operation).unwrap();
    assert_eq!(
        encoded,
        hex::decode(names["expected_envelope_hex"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        encoded.len(),
        names["expected_envelope_length"].as_u64().unwrap() as usize
    );
    assert_eq!(decode_names_v1_envelope(&encoded), Ok(operation));
    assert_eq!(MAX_APPLICATION_ENVELOPE_LEN, constants::MAX_PAYLOAD_LEN);

    let frames = carrier_v1::encode_frames_v1(core_runtime_id.to_bytes(), &encoded).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].as_slice(),
        hex::decode(
            names["expected_future_runtime_cpv1_frame_hex"]
                .as_str()
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        carrier_v1::reconstruct_frames_v1(&frames, core_runtime_id.to_bytes()).unwrap(),
        encoded
    );
    assert_eq!(
        carrier_v1::reconstruct_frames_v1(&frames, names_deployment_id.to_bytes()),
        Err(carrier_v1::Error::WrongDeployment)
    );
}

#[test]
fn core_runtime_identity_is_independent_of_names_policy_and_application_activation() {
    let envelope_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/application_envelopes.json"
    ))
    .unwrap();
    let (_, runtime_parameters) = runtime_fixture();
    let (_, names_parameters) = names_deployment_fixture();
    let runtime_id = runtime_parameters.core_runtime_id().unwrap();
    let names_id = NamesDeploymentId::from_parameters(&names_parameters).unwrap();

    let mut mutations = Vec::new();
    let mut changed = names_parameters.clone();
    changed.minimum_bond_value += 1;
    mutations.push(changed);
    let mut changed = names_parameters.clone();
    changed.commit_ttl_blocks += 1;
    mutations.push(changed);
    let mut changed = names_parameters.clone();
    changed.reuse_delay_blocks += 1;
    mutations.push(changed);
    let mut changed = names_parameters;
    changed.bond_note_max_age_blocks += 1;
    mutations.push(changed);

    for changed in mutations {
        assert_ne!(
            NamesDeploymentId::from_parameters(&changed).unwrap(),
            names_id
        );
        assert_eq!(runtime_parameters.core_runtime_id().unwrap(), runtime_id);
    }

    let names_at_runtime =
        names_v1_application_descriptor(runtime_parameters.runtime_activation_height);
    assert_eq!(
        u64::from(names_at_runtime.activation_height),
        envelope_fixture["names_v1"]["application_activation_height"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        names_at_runtime.validate_for_runtime(runtime_parameters.runtime_activation_height),
        Ok(())
    );
    let later_application = ApplicationDescriptor {
        key: ApplicationKey::new(derive_application_id(b"example.future").unwrap(), 1),
        activation_height: runtime_parameters.runtime_activation_height + 100,
    };
    assert_eq!(
        later_application.validate_for_runtime(runtime_parameters.runtime_activation_height),
        Ok(())
    );
    assert_eq!(runtime_parameters.core_runtime_id().unwrap(), runtime_id);
}

#[test]
fn routing_is_exact_and_unknown_applications_remain_structural_envelopes() {
    let commit = Operation::Commit {
        commitment: [0x42; 32],
    };
    let encoded = encode_names_v1_envelope(&commit).unwrap();
    let decoded = ApplicationEnvelopeV1::decode(&encoded).unwrap();
    assert_eq!(decoded.key(), names_v1_application_key());
    assert_eq!(decode_names_v1_envelope(&encoded), Ok(commit));

    let unknown_id = derive_application_id(b"example.unknown").unwrap();
    let unknown = ApplicationEnvelopeV1::new(
        ApplicationKey::new(unknown_id, 1),
        decoded.payload().to_vec(),
    )
    .unwrap()
    .encode();
    assert!(ApplicationEnvelopeV1::decode(&unknown).is_ok());
    assert_eq!(
        decode_names_v1_envelope(&unknown),
        Err(NamesApplicationEnvelopeError::WrongApplication)
    );

    let unknown_version = ApplicationEnvelopeV1::new(
        ApplicationKey::new(names_application_id(), 2),
        decoded.payload().to_vec(),
    )
    .unwrap()
    .encode();
    assert!(ApplicationEnvelopeV1::decode(&unknown_version).is_ok());
    assert_eq!(
        decode_names_v1_envelope(&unknown_version),
        Err(NamesApplicationEnvelopeError::WrongApplication)
    );

    assert_eq!(
        ApplicationEnvelopeV1::decode(&encoded[..APPLICATION_ENVELOPE_HEADER_LEN - 1]),
        Err(ApplicationEnvelopeError::TooShort)
    );
    let mut wrong_magic = encoded;
    wrong_magic[3] ^= 1;
    assert_eq!(
        ApplicationEnvelopeV1::decode(&wrong_magic),
        Err(ApplicationEnvelopeError::WrongMagic)
    );
}
