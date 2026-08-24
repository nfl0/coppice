use crate::hash;
use orchard::keys::IncomingViewingKey;

/// BLAKE2b-256 personalization for generic runtime identities.
pub const CORE_RUNTIME_ID_PERSONALIZATION: [u8; 16] = *b"CoppiceRuntime1\0";
pub const CORE_RUNTIME_PROTOCOL_ID_V1: &[u8] = b"coppice.runtime";
pub const CORE_RUNTIME_PROTOCOL_VERSION_V1: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoreRuntimeId([u8; 32]);

impl CoreRuntimeId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZcashNetwork {
    Main,
    Test,
    Regtest,
}

impl ZcashNetwork {
    pub const fn code(self) -> u8 {
        match self {
            Self::Main => 0x01,
            Self::Test => 0x02,
            Self::Regtest => 0x03,
        }
    }
}

/// Parameters that identify one generic runtime deployment.
///
/// Application identities, application activation heights, and policy
/// parameters are deliberately absent. Applications may activate independently
/// without changing the runtime identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreRuntimeParameters {
    pub runtime_protocol_id: Vec<u8>,
    pub runtime_protocol_version: u16,
    pub zcash_network_domain: Vec<u8>,
    pub zcash_network: ZcashNetwork,
    pub runtime_activation_height: u32,
    pub carrier_protocol_id: Vec<u8>,
    pub rendezvous_ivk: [u8; 64],
    pub rendezvous_receiver: [u8; 43],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRuntimeIdentityError {
    EmptyRuntimeProtocolId,
    RuntimeProtocolVersion,
    EmptyZcashNetworkDomain,
    RuntimeActivationHeight,
    EmptyCarrierProtocolId,
    LengthTooLarge,
    InvalidRendezvousIvk,
    InvalidRendezvousReceiver,
    RendezvousMismatch,
}

impl CoreRuntimeParameters {
    /// Validates all generic runtime context before it can derive an identity.
    pub fn validate(self) -> Result<ValidatedCoreRuntimeParameters, CoreRuntimeIdentityError> {
        self.validate_structure()?;

        let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(
            &self.rendezvous_ivk,
        ))
        .ok_or(CoreRuntimeIdentityError::InvalidRendezvousIvk)?;
        let receiver = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(
            &self.rendezvous_receiver,
        ))
        .ok_or(CoreRuntimeIdentityError::InvalidRendezvousReceiver)?;
        if ivk.diversifier_index(&receiver).is_none() {
            return Err(CoreRuntimeIdentityError::RendezvousMismatch);
        }

        Ok(ValidatedCoreRuntimeParameters { parameters: self })
    }

    fn validate_structure(&self) -> Result<(), CoreRuntimeIdentityError> {
        if self.runtime_protocol_id.is_empty() {
            return Err(CoreRuntimeIdentityError::EmptyRuntimeProtocolId);
        }
        if self.runtime_protocol_version == 0 {
            return Err(CoreRuntimeIdentityError::RuntimeProtocolVersion);
        }
        if self.zcash_network_domain.is_empty() {
            return Err(CoreRuntimeIdentityError::EmptyZcashNetworkDomain);
        }
        if self.runtime_activation_height == 0 {
            return Err(CoreRuntimeIdentityError::RuntimeActivationHeight);
        }
        if self.carrier_protocol_id.is_empty() {
            return Err(CoreRuntimeIdentityError::EmptyCarrierProtocolId);
        }

        for len in [
            self.runtime_protocol_id.len(),
            self.zcash_network_domain.len(),
            self.carrier_protocol_id.len(),
            self.rendezvous_ivk.len(),
            self.rendezvous_receiver.len(),
        ] {
            u16::try_from(len).map_err(|_| CoreRuntimeIdentityError::LengthTooLarge)?;
        }

        Ok(())
    }
}

/// Generic runtime context that has passed structural and cryptographic
/// validation. Only this type can derive `CoreRuntimeId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCoreRuntimeParameters {
    parameters: CoreRuntimeParameters,
}

impl ValidatedCoreRuntimeParameters {
    pub const fn parameters(&self) -> &CoreRuntimeParameters {
        &self.parameters
    }

    pub fn into_parameters(self) -> CoreRuntimeParameters {
        self.parameters
    }

    pub fn canonical_preimage(&self) -> Vec<u8> {
        fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
            let len =
                u16::try_from(bytes.len()).expect("validated runtime context length must fit u16");
            output.extend_from_slice(&len.to_be_bytes());
            output.extend_from_slice(bytes);
        }

        let mut output = Vec::new();
        put_bytes(&mut output, &self.parameters.runtime_protocol_id);
        output.extend_from_slice(&self.parameters.runtime_protocol_version.to_be_bytes());
        put_bytes(&mut output, &self.parameters.zcash_network_domain);
        output.push(self.parameters.zcash_network.code());
        output.extend_from_slice(&self.parameters.runtime_activation_height.to_be_bytes());
        put_bytes(&mut output, &self.parameters.carrier_protocol_id);
        put_bytes(&mut output, &self.parameters.rendezvous_ivk);
        put_bytes(&mut output, &self.parameters.rendezvous_receiver);
        output
    }

    pub fn core_runtime_id(&self) -> CoreRuntimeId {
        let preimage = self.canonical_preimage();
        CoreRuntimeId::from_bytes(hash::hash(&CORE_RUNTIME_ID_PERSONALIZATION, &preimage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_parameters() -> (serde_json::Value, CoreRuntimeParameters) {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/core_runtime_id.json"))
                .unwrap();
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
            zcash_network: match input["zcash_network"].as_str().unwrap() {
                "Main" => ZcashNetwork::Main,
                "Test" => ZcashNetwork::Test,
                "Regtest" => ZcashNetwork::Regtest,
                other => panic!("unknown Zcash network {other}"),
            },
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

    #[test]
    fn runtime_identity_vector_matches() {
        let (fixture, parameters) = vector_parameters();
        let validated = parameters.validate().unwrap();
        assert_eq!(
            hex::encode(CORE_RUNTIME_ID_PERSONALIZATION),
            fixture["personalization_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(validated.canonical_preimage()),
            fixture["canonical_preimage_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(validated.core_runtime_id().to_bytes()),
            fixture["expected_core_runtime_id_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn every_runtime_identity_field_is_bound() {
        let (_, parameters) = vector_parameters();
        let expected = parameters.clone().validate().unwrap().core_runtime_id();
        let mut mutations = Vec::new();

        let mut changed = parameters.clone();
        changed.runtime_protocol_id.push(b'2');
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.runtime_protocol_version += 1;
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.zcash_network_domain.push(b'2');
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.zcash_network = ZcashNetwork::Test;
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.runtime_activation_height += 1;
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.carrier_protocol_id.push(b'2');
        mutations.push(changed);

        for changed in mutations {
            assert_ne!(changed.validate().unwrap().core_runtime_id(), expected);
        }

        let mut alternate = parameters;
        alternate.rendezvous_ivk = hex::decode(
            "3c6ec816597b0ab356ec564a094ab4649a770e145bc327f1168e00b45c0c46146a0efaad6c366747a1bb45ae4bb15b4afc5d856b465757a183f104a0fb0fd318",
        )
        .unwrap()
        .try_into()
        .unwrap();
        alternate.rendezvous_receiver = hex::decode(
            "6135f04526a269e5e05e2f255344256bc4f9addbc3d09e22f239fc776455468301dfcc9540c5e59dd2c983",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_ne!(alternate.validate().unwrap().core_runtime_id(), expected);
    }

    #[test]
    fn invalid_runtime_parameters_are_rejected() {
        let (_, parameters) = vector_parameters();

        let mut changed = parameters.clone();
        changed.runtime_protocol_id.clear();
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::EmptyRuntimeProtocolId)
        );
        let mut changed = parameters.clone();
        changed.runtime_protocol_version = 0;
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::RuntimeProtocolVersion)
        );
        let mut changed = parameters.clone();
        changed.zcash_network_domain.clear();
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::EmptyZcashNetworkDomain)
        );
        let mut changed = parameters.clone();
        changed.runtime_activation_height = 0;
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::RuntimeActivationHeight)
        );
        let mut changed = parameters;
        changed.carrier_protocol_id.clear();
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::EmptyCarrierProtocolId)
        );

        let (_, mut changed) = vector_parameters();
        changed.runtime_protocol_id = vec![0; usize::from(u16::MAX) + 1];
        assert_eq!(
            changed.validate(),
            Err(CoreRuntimeIdentityError::LengthTooLarge)
        );
    }

    #[test]
    fn rendezvous_must_be_individually_valid_and_correspond() {
        let (_, parameters) = vector_parameters();

        let mut invalid_ivk = parameters.clone();
        invalid_ivk.rendezvous_ivk = [0xff; 64];
        assert_eq!(
            invalid_ivk.validate(),
            Err(CoreRuntimeIdentityError::InvalidRendezvousIvk)
        );

        let mut invalid_receiver = parameters.clone();
        invalid_receiver.rendezvous_receiver = [0xff; 43];
        assert_eq!(
            invalid_receiver.validate(),
            Err(CoreRuntimeIdentityError::InvalidRendezvousReceiver)
        );

        let mut mismatched = parameters;
        mismatched.rendezvous_receiver = hex::decode(
            "6135f04526a269e5e05e2f255344256bc4f9addbc3d09e22f239fc776455468301dfcc9540c5e59dd2c983",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(
            mismatched.validate(),
            Err(CoreRuntimeIdentityError::RendezvousMismatch)
        );
    }
}
