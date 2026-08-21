//! Frozen protocol parameters exposed to wallet integrations.

use crate::constants;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoppiceConfig {
    pub protocol_id: &'static [u8],
    pub network_id: &'static [u8],
    pub activation_height: u32,
    pub ironwood_activation_height: u32,
    pub tag_bits: u8,
    pub minimum_bond_value: u64,
}

/// Public-testnet POC parameters. `COPPICE_POC_V2` intentionally does not
/// decode the superseded direct-REGISTER experiment.
/// `tag_bits` is a discovery parameter for this deployment, not a claim about
/// a future mainnet parameter.
pub const TESTNET_V0: CoppiceConfig = CoppiceConfig {
    protocol_id: constants::PROTOCOL_ID,
    network_id: constants::NETWORK_ID,
    activation_height: constants::TESTNET_V0_ACTIVATION_HEIGHT,
    ironwood_activation_height: constants::TESTNET_IRONWOOD_ACTIVATION_HEIGHT,
    tag_bits: constants::DEFAULT_TEST_TAG_BITS,
    minimum_bond_value: constants::MINIMUM_BOND_VALUE,
};

/// Local Z3 regtest parameters. These are playground parameters, not a public
/// network deployment or proposed production constants.
pub const REGTEST_V0: CoppiceConfig = CoppiceConfig {
    protocol_id: constants::PROTOCOL_ID,
    network_id: constants::NETWORK_ID,
    activation_height: constants::REGTEST_V0_ACTIVATION_HEIGHT,
    ironwood_activation_height: constants::REGTEST_IRONWOOD_ACTIVATION_HEIGHT,
    tag_bits: constants::REGTEST_TAG_BITS,
    minimum_bond_value: constants::MINIMUM_BOND_VALUE,
};
