//! Frozen protocol parameters exposed to wallet integrations.

use crate::{constants, crypto};
use zcash_protocol::consensus::NetworkType;

/// Public incoming capability and receiver used for Coppice bulletin outputs.
/// These bytes contain no spending authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rendezvous {
    pub orchard_ivk: [u8; 64],
    pub orchard_receiver: [u8; 43],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentParameters {
    pub network_id: Vec<u8>,
    pub address_network: NetworkType,
    pub activation_height: u32,

    pub minimum_bond_value: u64,
    pub commit_ttl_blocks: u32,
    pub reuse_delay_blocks: u32,
    pub bond_note_max_age_blocks: u32,

    pub rendezvous: Rendezvous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentEncodingError {
    LengthTooLarge,
    Hash(crypto::Error),
}

fn network_type_code(network: NetworkType) -> u8 {
    match network {
        NetworkType::Main => 0x01,
        NetworkType::Test => 0x02,
        NetworkType::Regtest => 0x03,
    }
}

impl DeploymentParameters {
    pub fn canonical_preimage(&self) -> Result<Vec<u8>, DeploymentEncodingError> {
        fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), DeploymentEncodingError> {
            let len = u16::try_from(len).map_err(|_| DeploymentEncodingError::LengthTooLarge)?;
            out.extend_from_slice(&len.to_be_bytes());
            Ok(())
        }

        let mut out = Vec::new();
        put_len(&mut out, self.network_id.len())?;
        out.extend_from_slice(&self.network_id);
        out.push(network_type_code(self.address_network));
        out.extend_from_slice(&self.activation_height.to_be_bytes());
        out.extend_from_slice(&self.minimum_bond_value.to_be_bytes());
        out.extend_from_slice(&self.commit_ttl_blocks.to_be_bytes());
        out.extend_from_slice(&self.reuse_delay_blocks.to_be_bytes());
        out.extend_from_slice(&self.bond_note_max_age_blocks.to_be_bytes());
        put_len(&mut out, self.rendezvous.orchard_ivk.len())?;
        out.extend_from_slice(&self.rendezvous.orchard_ivk);
        put_len(&mut out, self.rendezvous.orchard_receiver.len())?;
        out.extend_from_slice(&self.rendezvous.orchard_receiver);
        Ok(out)
    }

    pub fn deployment_id(&self) -> Result<[u8; 32], DeploymentEncodingError> {
        let preimage = self.canonical_preimage()?;
        crypto::hash("CoppiceDeployV1", &preimage).map_err(DeploymentEncodingError::Hash)
    }
}

impl Default for Rendezvous {
    fn default() -> Self {
        TESTNET_V0.rendezvous
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoppiceConfig {
    pub protocol_id: &'static [u8],
    pub network_id: &'static [u8],
    pub activation_height: u32,
    pub ironwood_activation_height: u32,
    pub minimum_bond_value: u64,
    pub rendezvous: Rendezvous,
}

/// Public-testnet POC parameters. `COPPICE_POC_V2` intentionally does not
/// decode the superseded direct-REGISTER experiment.
pub const TESTNET_V0: CoppiceConfig = CoppiceConfig {
    protocol_id: constants::PROTOCOL_ID,
    network_id: constants::NETWORK_ID,
    activation_height: constants::TESTNET_V0_ACTIVATION_HEIGHT,
    ironwood_activation_height: constants::TESTNET_IRONWOOD_ACTIVATION_HEIGHT,
    minimum_bond_value: constants::MINIMUM_BOND_VALUE,
    rendezvous: Rendezvous {
        orchard_ivk: constants::TESTNET_RENDEZVOUS_IVK,
        orchard_receiver: constants::TESTNET_RENDEZVOUS_RECEIVER,
    },
};

/// Local Z3 regtest parameters. These are playground parameters, not a public
/// network deployment or proposed production constants.
pub const REGTEST_V0: CoppiceConfig = CoppiceConfig {
    protocol_id: constants::PROTOCOL_ID,
    network_id: constants::NETWORK_ID,
    activation_height: constants::REGTEST_V0_ACTIVATION_HEIGHT,
    ironwood_activation_height: constants::REGTEST_IRONWOOD_ACTIVATION_HEIGHT,
    minimum_bond_value: constants::MINIMUM_BOND_VALUE,
    rendezvous: Rendezvous {
        orchard_ivk: constants::REGTEST_RENDEZVOUS_IVK,
        orchard_receiver: constants::REGTEST_RENDEZVOUS_RECEIVER,
    },
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_vector_matches() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &fixture["input"];

        let parameters = DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: match input["network_type"].as_str().unwrap() {
                "Main" => NetworkType::Main,
                "Test" => NetworkType::Test,
                "Regtest" => NetworkType::Regtest,
                other => panic!("unknown network type {other}"),
            },
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

        let expected_preimage =
            hex::decode(fixture["canonical_preimage_hex"].as_str().unwrap()).unwrap();
        let expected_deployment_id: [u8; 32] =
            hex::decode(fixture["expected_deployment_id_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            fixture["expected_deployment_id_hex"].as_str().unwrap(),
            "0f769b29c0ed5c5f9a101300e15c846ca15aeae2198043da3e785f839a56f5d7"
        );

        assert_eq!(parameters.canonical_preimage().unwrap(), expected_preimage);
        assert_eq!(parameters.deployment_id().unwrap(), expected_deployment_id);
    }

    #[test]
    fn deployment_network_type_codes_are_explicit() {
        assert_eq!(network_type_code(NetworkType::Main), 0x01);
        assert_eq!(network_type_code(NetworkType::Test), 0x02);
        assert_eq!(network_type_code(NetworkType::Regtest), 0x03);
    }

    #[test]
    fn deployment_preimage_rejects_lengths_that_do_not_fit_u16() {
        let parameters = DeploymentParameters {
            network_id: vec![0; usize::from(u16::MAX) + 1],
            address_network: NetworkType::Regtest,
            activation_height: 10,
            minimum_bond_value: 100_000_000,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous {
                orchard_ivk: [0; 64],
                orchard_receiver: [0; 43],
            },
        };

        assert_eq!(
            parameters.canonical_preimage(),
            Err(DeploymentEncodingError::LengthTooLarge)
        );
    }
}
