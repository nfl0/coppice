pub const PROTOCOL_ID: &[u8] = b"COPPICE_POC_V1";
/// Frozen historical Testnet V0 network-domain bytes. The spelling is retained
/// because changing it would invalidate existing signatures and BondProofs.
pub const POC_NETWORK_ID: &[u8] = b"poc-local";
pub const NETWORK_ID: &[u8] = POC_NETWORK_ID;
pub const TESTNET_V0_ACTIVATION_HEIGHT: u32 = 4_288_414;
pub const TESTNET_IRONWOOD_ACTIVATION_HEIGHT: u32 = 4_134_000;
/// Local-only Z3 regtest deployment. This is independent from Testnet V0.
pub const REGTEST_V0_ACTIVATION_HEIGHT: u32 = 10;
pub const REGTEST_IRONWOOD_ACTIVATION_HEIGHT: u32 = 2;
/// POC discovery width chosen for fast local transaction construction.
pub const REGTEST_TAG_BITS: u8 = 8;
/// Minimum private registration bond: 1 ZEC, denominated in zatoshis.
pub const MINIMUM_BOND_VALUE: u64 = 100_000_000;
pub const MAX_NAME_LEN: usize = 63;
pub const MAX_FRAMES: u8 = 32;
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024;
/// Zcash transactions are bounded by the consensus block-size limit. Applying
/// the same limit before parsing prevents caller-controlled allocation spikes.
pub const MAX_TRANSACTION_BYTES: usize = 2_000_000;
/// POC parameter, not a frozen production choice.
pub const DEFAULT_TEST_TAG_BITS: u8 = 12;
pub const NAME_ID_DOMAIN: &[u8] = b"CoppiceName";
pub const NAME_RECORD_DOMAIN: &[u8] = b"CoppiceRecordV1";
pub const OWNER_SIGNATURE_DOMAIN: &[u8] = b"CoppiceOwnerSigV0";
pub const REGISTRATION_COMMITMENT_DOMAIN: &[u8] = b"CoppiceCommitV0";
pub const COMMITMENT_SET_DOMAIN: &[u8] = b"CoppiceCommitSetV0";
/// A reveal must be mined in a block strictly after its commitment.
pub const MIN_COMMIT_CONFIRMATIONS: u32 = 1;
pub const BOND_TAG_DOMAIN: &[u8; 16] = b"CoppiceBondTagV0";
pub const BOND_OWNER_DOMAIN: &[u8] = b"CoppiceOwnerV0";
pub const BOND_CONTEXT_DOMAIN: &[u8] = b"CoppiceCtxV0";
pub const BOND_REGISTRATION_DOMAIN: &[u8] = b"CoppiceRegisterV1";
pub const BOND_PROTOCOL_DOMAIN: &[u8] = b"CoppiceProtoV0";
pub const STATE_ROOT_DOMAIN: &[u8] = b"CoppiceStateV0";
pub const NAME_TREE_EMPTY_DOMAIN: &[u8] = b"CoppiceNameEmptyV0";
pub const NAME_TREE_LEAF_DOMAIN: &[u8] = b"CoppiceNameLeafV0";
pub const NAME_TREE_NODE_DOMAIN: &[u8] = b"CoppiceNameNodeV0";
pub const SPENT_TREE_EMPTY_DOMAIN: &[u8] = b"CoppiceSpentEmptyV0";
pub const SPENT_TREE_LEAF_DOMAIN: &[u8] = b"CoppiceSpentLeafV0";
pub const SPENT_TREE_NODE_DOMAIN: &[u8] = b"CoppiceSpentNodeV0";
