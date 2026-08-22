pub const PROTOCOL_ID: &[u8] = b"COPPICE_POC_V2";
/// Frozen historical Testnet V0 network-domain bytes. The spelling is retained
/// because changing it would invalidate existing signatures and BondProofs.
pub const POC_NETWORK_ID: &[u8] = b"poc-local";
pub const NETWORK_ID: &[u8] = POC_NETWORK_ID;
pub const TESTNET_V0_ACTIVATION_HEIGHT: u32 = 4_288_414;
pub const TESTNET_IRONWOOD_ACTIVATION_HEIGHT: u32 = 4_134_000;
/// Local-only Z3 regtest deployment. This is independent from Testnet V0.
pub const REGTEST_V0_ACTIVATION_HEIGHT: u32 = 10;
pub const REGTEST_IRONWOOD_ACTIVATION_HEIGHT: u32 = 2;
/// Public incoming capability used by the historical Testnet V0 tooling.
pub const TESTNET_RENDEZVOUS_IVK: [u8; 64] = [
    60, 110, 200, 22, 89, 123, 10, 179, 86, 236, 86, 74, 9, 74, 180, 100, 154, 119, 14, 20, 91,
    195, 39, 241, 22, 142, 0, 180, 92, 12, 70, 20, 106, 14, 250, 173, 108, 54, 103, 71, 161, 187,
    69, 174, 75, 177, 91, 74, 252, 93, 133, 107, 70, 87, 87, 161, 131, 241, 4, 160, 251, 15, 211,
    24,
];
pub const TESTNET_RENDEZVOUS_RECEIVER: [u8; 43] = [
    97, 53, 240, 69, 38, 162, 105, 229, 224, 94, 47, 37, 83, 68, 37, 107, 196, 249, 173, 219, 195,
    208, 158, 34, 242, 57, 252, 119, 100, 85, 70, 131, 1, 223, 204, 149, 64, 197, 229, 157, 210,
    201, 131,
];
/// Public incoming capability for the local Z3 regtest deployment.
pub const REGTEST_RENDEZVOUS_IVK: [u8; 64] = [
    101, 222, 178, 179, 238, 122, 198, 144, 32, 84, 63, 64, 242, 17, 34, 203, 109, 193, 244, 32,
    26, 50, 159, 205, 249, 213, 227, 187, 45, 251, 186, 190, 41, 213, 66, 53, 47, 227, 108, 60,
    123, 36, 194, 152, 157, 201, 208, 0, 11, 158, 4, 244, 68, 224, 93, 196, 83, 139, 222, 57, 92,
    14, 96, 8,
];
pub const REGTEST_RENDEZVOUS_RECEIVER: [u8; 43] = [
    158, 197, 158, 77, 68, 123, 162, 133, 8, 108, 195, 69, 108, 173, 246, 32, 4, 161, 155, 106,
    121, 137, 199, 38, 218, 170, 153, 68, 166, 205, 191, 37, 247, 191, 165, 26, 250, 21, 182, 109,
    165, 56, 129,
];
/// Minimum private registration bond: 1 ZEC, denominated in zatoshis.
pub const MINIMUM_BOND_VALUE: u64 = 100_000_000;
pub const MAX_NAME_LEN: usize = 63;
pub const MAX_FRAMES: u8 = 32;
pub const MAX_ADDRESS_LEN: usize = 512;
pub const MAX_BOND_PROOF_LEN: usize = 8_192;
pub const START_FRAME_HEADER: usize = 74;
pub const START_CHUNK_CAP: usize = 438;
pub const CONT_FRAME_HEADER: usize = 7;
pub const CONT_CHUNK_CAP: usize = 505;
pub const MAX_PAYLOAD_LEN: usize = 16_093;
/// Zcash transactions are bounded by the consensus block-size limit. Applying
/// the same limit before parsing prevents caller-controlled allocation spikes.
pub const MAX_TRANSACTION_LEN: usize = 2_000_000;
/// V0 compatibility spelling retained for existing serialized replay callers.
pub const MAX_TRANSACTION_BYTES: usize = MAX_TRANSACTION_LEN;
pub const NAME_ID_DOMAIN: &[u8] = b"CoppiceName";
pub const NAME_RECORD_DOMAIN: &[u8] = b"CoppiceRecordV1";
pub const OWNER_SIGNATURE_DOMAIN: &[u8] = b"CoppiceOwnerSigV0";
pub const REGISTRATION_COMMITMENT_DOMAIN: &[u8] = b"CoppiceCommitV0";
pub const COMMITMENT_SET_DOMAIN: &[u8] = b"CoppiceCommitSetV0";
/// A reveal must be mined in a block strictly after its commitment.
pub const MIN_COMMIT_CONFIRMATIONS: u32 = 1;
/// Legacy V0 bond-tag domain used only by the compatibility replay path.
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
