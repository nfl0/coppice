use crate::hash;

/// BLAKE2b-256 personalization for generic runtime identities.
pub const CORE_RUNTIME_ID_PERSONALIZATION: [u8; 16] = *b"CoppiceRuntime1\0";

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
}

impl CoreRuntimeParameters {
    pub fn validate(&self) -> Result<(), CoreRuntimeIdentityError> {
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

    pub fn canonical_preimage(&self) -> Result<Vec<u8>, CoreRuntimeIdentityError> {
        self.validate()?;

        fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CoreRuntimeIdentityError> {
            let len =
                u16::try_from(bytes.len()).map_err(|_| CoreRuntimeIdentityError::LengthTooLarge)?;
            output.extend_from_slice(&len.to_be_bytes());
            output.extend_from_slice(bytes);
            Ok(())
        }

        let mut output = Vec::new();
        put_bytes(&mut output, &self.runtime_protocol_id)?;
        output.extend_from_slice(&self.runtime_protocol_version.to_be_bytes());
        put_bytes(&mut output, &self.zcash_network_domain)?;
        output.push(self.zcash_network.code());
        output.extend_from_slice(&self.runtime_activation_height.to_be_bytes());
        put_bytes(&mut output, &self.carrier_protocol_id)?;
        put_bytes(&mut output, &self.rendezvous_ivk)?;
        put_bytes(&mut output, &self.rendezvous_receiver)?;
        Ok(output)
    }

    pub fn core_runtime_id(&self) -> Result<CoreRuntimeId, CoreRuntimeIdentityError> {
        let preimage = self.canonical_preimage()?;
        Ok(CoreRuntimeId::from_bytes(hash::hash(
            &CORE_RUNTIME_ID_PERSONALIZATION,
            &preimage,
        )))
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
        assert_eq!(
            hex::encode(CORE_RUNTIME_ID_PERSONALIZATION),
            fixture["personalization_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(parameters.canonical_preimage().unwrap()),
            fixture["canonical_preimage_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(parameters.core_runtime_id().unwrap().to_bytes()),
            fixture["expected_core_runtime_id_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn every_runtime_identity_field_is_bound() {
        let (_, parameters) = vector_parameters();
        let expected = parameters.core_runtime_id().unwrap();
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
        let mut changed = parameters.clone();
        changed.rendezvous_ivk[0] ^= 1;
        mutations.push(changed);
        let mut changed = parameters.clone();
        changed.rendezvous_receiver[0] ^= 1;
        mutations.push(changed);

        for changed in mutations {
            assert_ne!(changed.core_runtime_id().unwrap(), expected);
        }
    }

    #[test]
    fn invalid_runtime_parameters_are_rejected() {
        let (_, parameters) = vector_parameters();

        let mut changed = parameters.clone();
        changed.runtime_protocol_id.clear();
        assert_eq!(
            changed.core_runtime_id(),
            Err(CoreRuntimeIdentityError::EmptyRuntimeProtocolId)
        );
        let mut changed = parameters.clone();
        changed.runtime_protocol_version = 0;
        assert_eq!(
            changed.core_runtime_id(),
            Err(CoreRuntimeIdentityError::RuntimeProtocolVersion)
        );
        let mut changed = parameters.clone();
        changed.zcash_network_domain.clear();
        assert_eq!(
            changed.core_runtime_id(),
            Err(CoreRuntimeIdentityError::EmptyZcashNetworkDomain)
        );
        let mut changed = parameters.clone();
        changed.runtime_activation_height = 0;
        assert_eq!(
            changed.core_runtime_id(),
            Err(CoreRuntimeIdentityError::RuntimeActivationHeight)
        );
        let mut changed = parameters;
        changed.carrier_protocol_id.clear();
        assert_eq!(
            changed.core_runtime_id(),
            Err(CoreRuntimeIdentityError::EmptyCarrierProtocolId)
        );
    }
}
