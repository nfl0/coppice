//! Panic-free adaptation of hostile protobuf CompactBlocks into canonical Coppice inputs.
//!
//! [`FullTransactionSource`] is untrusted transport. Bytes returned for a requested
//! txid become authoritative only after the core runtime parses them under the
//! canonical branch ID and verifies their txid and compact/full Ironwood effects.

use std::fmt::Debug;

use coppice_core::{
    carrier::{self, CoreRendezvous},
    identity::{ValidatedCoreRuntimeParameters, ZcashNetwork},
    replay::{CoreCanonicalBlockInput, CoreCanonicalTransactionInput, FullTransactionAcquisition},
};
use orchard::note_encryption::CompactAction;
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactTx};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType, Parameters},
    constants::MAX_BLOCK_BYTES,
};

/// The cumulative full-transaction acquisition budget is the consensus
/// maximum serialized Zcash block size. It bounds bytes retained before Core
/// parses any selected transaction.
pub const MAX_FULL_TRANSACTION_BYTES: usize = MAX_BLOCK_BYTES;

/// Compatibility alias retained for callers using the pre-selector name.
pub const MAX_CANDIDATE_FULL_TX_BYTES: usize = MAX_FULL_TRANSACTION_BYTES;

pub use coppice_core::runtime::CanonicalRuntime;

/// Supplies raw serialized transactions when compact carrier detection or a
/// caller's selective extended-effect policy makes the full transaction
/// mandatory.
pub trait FullTransactionSource {
    type Error: Debug;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Compact facts validated before any external fetch. The references borrow
/// the adapter's canonicalized compact vectors and are valid only for the
/// selector callback invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCompactTransactionSummary<'a> {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub ironwood_nullifiers: &'a [[u8; 32]],
    pub ironwood_commitments: &'a [[u8; 32]],
    pub action_count: usize,
    pub rendezvous_candidate: bool,
}

#[derive(Debug)]
pub enum CompactBlockAdapterError<SourceError: Debug> {
    NetworkMismatch,
    InvalidBlockHeight,
    InvalidBlockHash,
    InvalidPrevBlockHash,
    NonSequentialHeight {
        expected: u32,
        actual: u32,
    },
    PredecessorMismatch,
    InvalidTxIndex {
        transaction: usize,
    },
    InvalidTxid {
        transaction: usize,
    },
    NonCanonicalTxOrder,
    InvalidIronwoodCompactAction {
        tx_index: u32,
        action_index: usize,
    },
    CandidateDetection {
        tx_index: u32,
        action_index: usize,
    },
    FullTransactionSource(SourceError),
    RequiredFullTransactionMissing {
        txid: [u8; 32],
        tx_index: u32,
    },
    FullTransactionTooLarge {
        txid: [u8; 32],
        tx_index: u32,
        len: usize,
        limit: usize,
    },
    FullTransactionBudgetExceeded {
        txid: [u8; 32],
        tx_index: u32,
        attempted: usize,
        limit: usize,
    },
}

#[derive(Debug)]
pub enum CompactBlockApplyError<SourceError: Debug, RuntimeError: Debug> {
    Prepare(CompactBlockAdapterError<SourceError>),
    Runtime(RuntimeError),
}

struct ValidatedCompactTx {
    input: CoreCanonicalTransactionInput,
    rendezvous_candidate: bool,
}

fn exact_32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn validate_transaction<SourceError: Debug>(
    transaction: usize,
    compact_tx: &CompactTx,
    rendezvous: &CoreRendezvous,
) -> Result<ValidatedCompactTx, CompactBlockAdapterError<SourceError>> {
    let tx_index = u32::try_from(compact_tx.index)
        .map_err(|_| CompactBlockAdapterError::InvalidTxIndex { transaction })?;
    let txid =
        exact_32(&compact_tx.txid).ok_or(CompactBlockAdapterError::InvalidTxid { transaction })?;
    let mut ironwood_nullifiers = Vec::with_capacity(compact_tx.ironwood_actions.len());
    let mut ironwood_commitments = Vec::with_capacity(compact_tx.ironwood_actions.len());
    let mut candidate = false;

    for (action_index, encoded) in compact_tx.ironwood_actions.iter().enumerate() {
        let action = CompactAction::try_from(encoded).map_err(|_| {
            CompactBlockAdapterError::InvalidIronwoodCompactAction {
                tx_index,
                action_index,
            }
        })?;
        ironwood_nullifiers.push(action.nullifier().to_bytes());
        ironwood_commitments.push(action.cmx().to_bytes());
        let hit = carrier::compact_action_is_rendezvous(&action, rendezvous);
        candidate |= hit;
    }

    Ok(ValidatedCompactTx {
        input: CoreCanonicalTransactionInput {
            tx_index,
            txid,
            ironwood_nullifiers,
            ironwood_commitments,
            full_transaction_acquisition: FullTransactionAcquisition::new(candidate, false),
            full_transaction: None,
        },
        rendezvous_candidate: candidate,
    })
}

/// Validates an entire compact block before making the first external fetch,
/// then fetches each requested transaction exactly once in canonical order.
pub fn prepare_canonical_block<P, R, S>(
    params: &P,
    runtime: &R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
) -> Result<CoreCanonicalBlockInput, CompactBlockAdapterError<S::Error>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
{
    prepare_canonical_block_with_transaction_selector(
        params,
        runtime,
        compact_block,
        full_tx_source,
        |_summary| false,
    )
}

/// Like [`prepare_canonical_block`], with a bounded, caller-owned selective
/// full-transaction policy. Applications that need extended public Ironwood
/// effects can request a full transaction from the validated compact summary;
/// Core still parses and cross-checks every selected response. Compact carrier
/// detection always remains mandatory independently of this policy.
pub fn prepare_canonical_block_with_transaction_selector<P, R, S, F>(
    params: &P,
    runtime: &R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
    mut select_full_transaction: F,
) -> Result<CoreCanonicalBlockInput, CompactBlockAdapterError<S::Error>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
    F: FnMut(&CanonicalCompactTransactionSummary<'_>) -> bool,
{
    if !network_matches(params.network_type(), runtime.core_parameters()) {
        return Err(CompactBlockAdapterError::NetworkMismatch);
    }
    let height = u32::try_from(compact_block.height)
        .map_err(|_| CompactBlockAdapterError::InvalidBlockHeight)?;
    let block_hash =
        exact_32(&compact_block.hash).ok_or(CompactBlockAdapterError::InvalidBlockHash)?;
    let prev_block_hash =
        exact_32(&compact_block.prev_hash).ok_or(CompactBlockAdapterError::InvalidPrevBlockHash)?;
    let expected_height = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(CompactBlockAdapterError::InvalidBlockHeight)?;
    if height != expected_height {
        return Err(CompactBlockAdapterError::NonSequentialHeight {
            expected: expected_height,
            actual: height,
        });
    }
    if prev_block_hash != runtime.tip().block_hash {
        return Err(CompactBlockAdapterError::PredecessorMismatch);
    }

    // Phase A: validate and classify every represented transaction before any fetch.
    let rendezvous = runtime.rendezvous();
    let mut validated = Vec::with_capacity(compact_block.vtx.len());
    for (transaction, compact_tx) in compact_block.vtx.iter().enumerate() {
        let mut tx = validate_transaction(transaction, compact_tx, rendezvous)?;
        if validated
            .last()
            .is_some_and(|prior: &ValidatedCompactTx| prior.input.tx_index >= tx.input.tx_index)
        {
            return Err(CompactBlockAdapterError::NonCanonicalTxOrder);
        }
        let request_extended_effects =
            select_full_transaction(&CanonicalCompactTransactionSummary {
                tx_index: tx.input.tx_index,
                txid: tx.input.txid,
                ironwood_nullifiers: &tx.input.ironwood_nullifiers,
                ironwood_commitments: &tx.input.ironwood_commitments,
                action_count: tx.input.ironwood_nullifiers.len(),
                rendezvous_candidate: tx.rendezvous_candidate,
            });
        tx.input.full_transaction_acquisition =
            FullTransactionAcquisition::new(tx.rendezvous_candidate, request_extended_effects);
        validated.push(tx);
    }

    // Phase B: fetch raw bytes only for compact candidates or selected
    // extended-effect transactions.
    let mut full_transaction_bytes = 0usize;
    for tx in &mut validated {
        if tx
            .input
            .full_transaction_acquisition
            .requires_full_transaction()
        {
            let bytes = full_tx_source
                .full_transaction(tx.input.txid)
                .map_err(CompactBlockAdapterError::FullTransactionSource)?
                .ok_or(CompactBlockAdapterError::RequiredFullTransactionMissing {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                })?;
            if bytes.len() > MAX_FULL_TRANSACTION_BYTES {
                return Err(CompactBlockAdapterError::FullTransactionTooLarge {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                    len: bytes.len(),
                    limit: MAX_FULL_TRANSACTION_BYTES,
                });
            }
            let attempted = full_transaction_bytes.checked_add(bytes.len()).ok_or(
                CompactBlockAdapterError::FullTransactionBudgetExceeded {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                    attempted: usize::MAX,
                    limit: MAX_FULL_TRANSACTION_BYTES,
                },
            )?;
            if attempted > MAX_FULL_TRANSACTION_BYTES {
                return Err(CompactBlockAdapterError::FullTransactionBudgetExceeded {
                    txid: tx.input.txid,
                    tx_index: tx.input.tx_index,
                    attempted,
                    limit: MAX_FULL_TRANSACTION_BYTES,
                });
            }
            full_transaction_bytes = attempted;
            tx.input.full_transaction = Some(bytes);
        }
    }

    Ok(CoreCanonicalBlockInput {
        height,
        block_hash,
        prev_block_hash,
        branch_id: BranchId::for_height(params, BlockHeight::from_u32(height)),
        transactions: validated.into_iter().map(|tx| tx.input).collect(),
    })
}

/// Prepares the complete block first and delegates the sole state mutation to
/// the atomic core runtime.
pub fn apply_compact_block<P, R, S>(
    params: &P,
    runtime: &mut R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
) -> Result<R::BlockOutput, CompactBlockApplyError<S::Error, R::ApplyError>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
{
    let input = prepare_canonical_block(params, runtime, compact_block, full_tx_source)
        .map_err(CompactBlockApplyError::Prepare)?;
    runtime
        .apply_canonical_block(&input)
        .map_err(CompactBlockApplyError::Runtime)
}

/// Applies a CompactBlock with the same selective extended-effect policy as
/// [`prepare_canonical_block_with_transaction_selector`].
pub fn apply_compact_block_with_transaction_selector<P, R, S, F>(
    params: &P,
    runtime: &mut R,
    compact_block: &CompactBlock,
    full_tx_source: &mut S,
    select_full_transaction: F,
) -> Result<R::BlockOutput, CompactBlockApplyError<S::Error, R::ApplyError>>
where
    P: Parameters,
    R: CanonicalRuntime,
    S: FullTransactionSource,
    F: FnMut(&CanonicalCompactTransactionSummary<'_>) -> bool,
{
    let input = prepare_canonical_block_with_transaction_selector(
        params,
        runtime,
        compact_block,
        full_tx_source,
        select_full_transaction,
    )
    .map_err(CompactBlockApplyError::Prepare)?;
    runtime
        .apply_canonical_block(&input)
        .map_err(CompactBlockApplyError::Runtime)
}

fn network_matches(network: NetworkType, parameters: &ValidatedCoreRuntimeParameters) -> bool {
    matches!(
        (network, parameters.parameters().zcash_network),
        (NetworkType::Main, ZcashNetwork::Main)
            | (NetworkType::Test, ZcashNetwork::Test)
            | (NetworkType::Regtest, ZcashNetwork::Regtest)
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use coppice_core::{
        application::{ApplicationEnvelopeV1, ApplicationId, ApplicationKey},
        carrier,
        identity::{CoreRuntimeParameters, ZcashNetwork},
        replay::{
            CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration, CoreReplayError,
            FullTransactionAcquisition, IronwoodFrontier,
        },
        runtime::{ApplicationMessageStatus, CoreRuntime},
        transport,
    };
    use orchard::{
        Proof,
        builder::{Builder, BundleType},
        bundle::{Authorized as OrchardAuthorized, BundleVersion},
        keys::IncomingViewingKey,
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
        primitives::redpallas::{Binding, SigningKey, SpendAuth},
        value::NoteValue,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOrchardAction, CompactTx,
    };
    use zcash_note_encryption::Domain;
    use zcash_primitives::transaction::{Authorized, TransactionData};
    use zcash_protocol::{
        consensus::BlockHeight, local_consensus::LocalNetwork, value::ZatBalance,
    };

    use super::*;

    fn params() -> LocalNetwork {
        let active = Some(BlockHeight::from_u32(1));
        LocalNetwork {
            overwinter: active,
            sapling: active,
            blossom: active,
            heartwood: active,
            canopy: active,
            nu5: active,
            nu6: active,
            nu6_1: active,
            nu6_2: active,
            nu6_3: active,
        }
    }

    fn runtime() -> CoreRuntime {
        let parameters = CoreRuntimeParameters {
            runtime_protocol_id: b"coppice.runtime".to_vec(),
            runtime_protocol_version: 1,
            zcash_network_domain: b"coppice-runtime-regtest-v1".to_vec(),
            zcash_network: ZcashNetwork::Regtest,
            runtime_activation_height: 10,
            carrier_protocol_id: b"CPV1".to_vec(),
            rendezvous_ivk: hex::decode(
                "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            rendezvous_receiver: hex::decode(
                "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }
        .validate()
        .unwrap();
        let configuration = CoreReplayConfiguration::new(10, 16).unwrap();
        let replay = CoreReplay::new(
            configuration,
            CoreReplayActivationCheckpoint {
                height: 9,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        CoreRuntime::new(parameters, replay).unwrap()
    }

    fn rendezvous_action(recipient: orchard::Address) -> CompactOrchardAction {
        let nf = Nullifier::from_bytes(&[0; 32]).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = (0u8..=u8::MAX)
            .find_map(|byte| Option::from(RandomSeed::from_bytes([byte; 32], &rho)))
            .unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(0),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [0; 512]);
        let ciphertext = encryptor.encrypt_note_plaintext();
        CompactOrchardAction {
            nullifier: nf.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment())
                .to_bytes()
                .to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0.to_vec(),
            ciphertext: ciphertext[..52].to_vec(),
        }
    }

    fn real_rendezvous_action() -> CompactOrchardAction {
        let receiver: [u8; 43] = hex::decode(
            "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
        )
        .unwrap()
        .try_into()
        .unwrap();
        rendezvous_action(orchard::Address::from_raw_address_bytes(&receiver).unwrap())
    }

    fn alternate_rendezvous_action() -> CompactOrchardAction {
        let ivk: [u8; 64] = hex::decode(
            "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let key = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&ivk)).unwrap();
        rendezvous_action(key.address_at(1u32))
    }

    fn alternate_receiver() -> orchard::Address {
        let ivk: [u8; 64] = hex::decode(
            "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let key = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&ivk)).unwrap();
        key.address_at(1u32)
    }

    fn configured_receiver() -> orchard::Address {
        let receiver: [u8; 43] = hex::decode(
            "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
        )
        .unwrap()
        .try_into()
        .unwrap();
        orchard::Address::from_raw_address_bytes(&receiver).unwrap()
    }

    fn noncandidate_action() -> CompactOrchardAction {
        let mut action = real_rendezvous_action();
        action.ciphertext[0] ^= 1;
        action
    }

    fn compact_tx(index: u64, id: u8, actions: Vec<CompactOrchardAction>) -> CompactTx {
        CompactTx {
            index,
            txid: vec![id; 32],
            ironwood_actions: actions,
            ..Default::default()
        }
    }

    fn block(runtime: &CoreRuntime, transactions: Vec<CompactTx>) -> CompactBlock {
        CompactBlock {
            height: u64::from(runtime.tip().height + 1),
            hash: vec![7; 32],
            prev_hash: runtime.tip().block_hash.to_vec(),
            vtx: transactions,
            ..Default::default()
        }
    }

    fn empty_transaction() -> (Vec<u8>, [u8; 32]) {
        let transaction = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(10),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let txid = transaction.txid().into();
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).unwrap();
        (bytes, txid)
    }

    struct FullIronwoodFixture {
        bytes: Vec<u8>,
        txid: [u8; 32],
        compact: CompactOrchardAction,
        nullifier: [u8; 32],
        commitment: [u8; 32],
        value_commitment: [u8; 32],
        randomized_key: [u8; 32],
        value_balance: i64,
    }

    fn full_ironwood_transaction(
        receiver: orchard::Address,
        memo: [u8; 512],
        seed: u8,
    ) -> FullIronwoodFixture {
        let version = BundleVersion::ironwood_v3();
        let mut builder = Builder::new(
            BundleType::UNPADDED,
            version,
            version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(None, receiver, NoteValue::from_raw(5), memo)
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
        let count = unauthorized.actions().len();
        let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
        let binding_key =
            SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
        let proof = Proof::new(vec![0; Proof::expected_proof_size(count)]);
        let bundle = unauthorized.map_authorization(
            &mut rng,
            |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceAcquisitionTestSpend"),
            |rng, _| {
                OrchardAuthorized::from_parts(
                    proof,
                    binding_key.sign(&mut *rng, b"CoppiceAcquisitionTestBinding"),
                )
            },
        );
        let transaction = TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            BlockHeight::from_u32(10),
            None,
            None,
            None,
            Some(bundle),
        )
        .freeze()
        .unwrap();
        let action = transaction
            .ironwood_bundle()
            .unwrap()
            .actions()
            .iter()
            .next()
            .unwrap();
        let compact = CompactOrchardAction {
            nullifier: action.nullifier().to_bytes().to_vec(),
            cmx: action.cmx().to_bytes().to_vec(),
            ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
            ciphertext: action.encrypted_note().enc_ciphertext[..52].to_vec(),
        };
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).unwrap();
        FullIronwoodFixture {
            bytes,
            txid: transaction.txid().into(),
            compact,
            nullifier: action.nullifier().to_bytes(),
            commitment: action.cmx().to_bytes(),
            value_commitment: action.cv_net().to_bytes(),
            randomized_key: action.rk().into(),
            value_balance: i64::from(*transaction.ironwood_bundle().unwrap().value_balance()),
        }
    }

    #[derive(Default)]
    struct Source {
        calls: Vec<[u8; 32]>,
        values: BTreeMap<[u8; 32], Result<Option<Vec<u8>>, &'static str>>,
    }

    impl FullTransactionSource for Source {
        type Error = &'static str;

        fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.calls.push(txid);
            self.values.remove(&txid).unwrap_or(Ok(None))
        }
    }

    #[test]
    fn exact_receiver_detection_is_application_independent() {
        let runtime = runtime();
        let hit = CompactAction::try_from(&real_rendezvous_action()).unwrap();
        assert!(carrier::compact_action_is_rendezvous(
            &hit,
            runtime.rendezvous()
        ));
        let miss = CompactAction::try_from(&alternate_rendezvous_action()).unwrap();
        assert!(!carrier::compact_action_is_rendezvous(
            &miss,
            runtime.rendezvous()
        ));
    }

    #[test]
    fn alternate_receiver_does_not_fetch_or_become_a_carrier() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(0, 1, vec![alternate_rendezvous_action()])],
        );
        let mut source = Source::default();
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(
            prepared.transactions[0].full_transaction_acquisition,
            FullTransactionAcquisition::None
        );
        assert!(source.calls.is_empty());
    }

    #[test]
    fn malformed_container_fields_are_panic_free_and_do_not_fetch() {
        let runtime = runtime();
        let mut source = Source::default();

        let mut cases = vec![];
        let mut invalid_height = block(&runtime, vec![]);
        invalid_height.height = u64::from(u32::MAX) + 1;
        cases.push(invalid_height);
        for length in [31, 33] {
            let mut invalid_hash = block(&runtime, vec![]);
            invalid_hash.hash = vec![0; length];
            cases.push(invalid_hash);
        }
        let mut invalid_prev = block(&runtime, vec![]);
        invalid_prev.prev_hash = vec![0; 31];
        cases.push(invalid_prev);
        let mut invalid_index = block(&runtime, vec![compact_tx(0, 1, vec![])]);
        invalid_index.vtx[0].index = u64::from(u32::MAX) + 1;
        cases.push(invalid_index);
        for length in [31, 33] {
            let mut invalid_txid = block(&runtime, vec![compact_tx(0, 1, vec![])]);
            invalid_txid.vtx[0].txid = vec![0; length];
            cases.push(invalid_txid);
        }

        for malformed in cases {
            assert!(prepare_canonical_block(&params(), &runtime, &malformed, &mut source).is_err());
        }
        assert!(source.calls.is_empty());
    }

    #[test]
    fn every_compact_action_field_is_checked_before_fetch() {
        let runtime = runtime();
        let valid = real_rendezvous_action();
        let mut malformed = Vec::new();
        for length in [31, 33] {
            let mut action = valid.clone();
            action.nullifier = vec![0; length];
            malformed.push(action);
        }
        let mut action = valid.clone();
        action.nullifier = vec![0xff; 32];
        malformed.push(action);
        for length in [31, 33] {
            let mut action = valid.clone();
            action.cmx = vec![0; length];
            malformed.push(action);
        }
        let mut action = valid.clone();
        action.cmx = vec![0xff; 32];
        malformed.push(action);
        let mut action = valid.clone();
        action.ephemeral_key = vec![0; 31];
        malformed.push(action);
        for length in [51, 53] {
            let mut action = valid.clone();
            action.ciphertext = vec![0; length];
            malformed.push(action);
        }

        let mut source = Source::default();
        for action in malformed {
            let input = block(&runtime, vec![compact_tx(2, 1, vec![action])]);
            assert!(matches!(
                prepare_canonical_block(&params(), &runtime, &input, &mut source),
                Err(CompactBlockAdapterError::InvalidIronwoodCompactAction { .. })
            ));
        }
        assert!(source.calls.is_empty());
    }

    #[test]
    fn full_compact_validation_precedes_fetch() {
        let runtime = runtime();
        let candidate = real_rendezvous_action();
        let malformed = CompactOrchardAction {
            nullifier: vec![0; 31],
            ..candidate.clone()
        };
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![candidate]),
                compact_tx(7, 2, vec![malformed]),
            ],
        );
        let mut source = Source::default();
        assert!(prepare_canonical_block(&params(), &runtime, &input, &mut source).is_err());
        assert!(source.calls.is_empty());
    }

    #[test]
    fn sparse_transaction_order_is_accepted_and_noncanonical_order_is_rejected() {
        let runtime = runtime();
        let mut source = Source::default();
        for indices in [[2, 11, 7], [2, 2, 11]] {
            let input = block(
                &runtime,
                indices
                    .into_iter()
                    .enumerate()
                    .map(|(id, index)| compact_tx(index, id as u8, vec![]))
                    .collect(),
            );
            assert!(matches!(
                prepare_canonical_block(&params(), &runtime, &input, &mut source),
                Err(CompactBlockAdapterError::NonCanonicalTxOrder)
            ));
        }

        let sparse = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![]),
                compact_tx(7, 2, vec![]),
                compact_tx(11, 3, vec![]),
            ],
        );
        let prepared = prepare_canonical_block(&params(), &runtime, &sparse, &mut source).unwrap();
        assert_eq!(
            prepared
                .transactions
                .iter()
                .map(|tx| tx.tx_index)
                .collect::<Vec<_>>(),
            vec![2, 7, 11]
        );
    }

    #[test]
    fn carrier_candidates_fetch_full_transactions_independently_of_selector() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(7, 4, vec![real_rendezvous_action()])],
        );
        let mut source = Source::default();
        source.values.insert([4; 32], Ok(Some(vec![4])));
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(source.calls, vec![[4; 32]]);
        assert_eq!(
            prepared.transactions[0].full_transaction_acquisition,
            FullTransactionAcquisition::Carrier
        );
        assert_eq!(prepared.transactions[0].full_transaction, Some(vec![4]));
    }

    #[test]
    fn carrier_fetches_are_once_each_in_canonical_order() {
        let runtime = runtime();
        let candidate = real_rendezvous_action();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![candidate.clone(), candidate.clone()]),
                compact_tx(7, 2, vec![noncandidate_action()]),
                compact_tx(11, 3, vec![candidate]),
            ],
        );
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![1])));
        source.values.insert([3; 32], Ok(Some(vec![3])));
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(source.calls, vec![[1; 32], [3; 32]]);
        assert_eq!(
            prepared.transactions[0].full_transaction_acquisition,
            FullTransactionAcquisition::Carrier
        );
        assert_eq!(
            prepared.transactions[1].full_transaction_acquisition,
            FullTransactionAcquisition::None
        );
        assert_eq!(prepared.transactions[1].full_transaction, None);
    }

    #[test]
    fn zero_and_three_candidate_fetch_counts_are_exact() {
        let runtime = runtime();
        let no_hits = block(
            &runtime,
            vec![compact_tx(2, 1, vec![noncandidate_action()])],
        );
        let mut source = Source::default();
        prepare_canonical_block(&params(), &runtime, &no_hits, &mut source).unwrap();
        assert!(source.calls.is_empty());

        let hit = real_rendezvous_action();
        let three = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![hit.clone()]),
                compact_tx(7, 2, vec![hit.clone()]),
                compact_tx(11, 3, vec![hit]),
            ],
        );
        for id in 1..=3 {
            source.values.insert([id; 32], Ok(Some(vec![id])));
        }
        prepare_canonical_block(&params(), &runtime, &three, &mut source).unwrap();
        assert_eq!(source.calls, vec![[1; 32], [2; 32], [3; 32]]);
    }

    #[test]
    fn selected_full_transaction_bytes_have_per_transaction_limit() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(7, 4, vec![real_rendezvous_action()])],
        );
        let mut source = Source::default();
        source
            .values
            .insert([4; 32], Ok(Some(vec![0; MAX_FULL_TRANSACTION_BYTES + 1])));
        assert!(matches!(
            prepare_canonical_block(&params(), &runtime, &input, &mut source),
            Err(CompactBlockAdapterError::FullTransactionTooLarge {
                txid,
                len,
                limit: MAX_FULL_TRANSACTION_BYTES,
                ..
            }) if txid == [4; 32] && len == MAX_FULL_TRANSACTION_BYTES + 1
        ));
    }

    #[test]
    fn selector_receives_compact_summary_and_requests_extended_effects() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(7, 4, vec![noncandidate_action()])],
        );
        let mut source = Source::default();
        source.values.insert([4; 32], Ok(Some(vec![4])));
        let prepared = prepare_canonical_block_with_transaction_selector(
            &params(),
            &runtime,
            &input,
            &mut source,
            |summary| {
                assert_eq!(summary.tx_index, 7);
                assert_eq!(summary.txid, [4; 32]);
                assert_eq!(summary.action_count, 1);
                assert_eq!(summary.ironwood_nullifiers.len(), 1);
                assert_eq!(summary.ironwood_commitments.len(), 1);
                assert!(!summary.rendezvous_candidate);
                true
            },
        )
        .unwrap();
        assert_eq!(source.calls, vec![[4; 32]]);
        assert_eq!(
            prepared.transactions[0].full_transaction_acquisition,
            FullTransactionAcquisition::ExtendedEffects
        );
        assert_eq!(prepared.transactions[0].full_transaction, Some(vec![4]));
    }

    #[test]
    fn extended_effect_fetch_does_not_become_a_carrier_candidate() {
        let mut runtime = runtime();
        let (bytes, txid) = empty_transaction();
        let mut compact = compact_tx(7, 4, vec![]);
        compact.txid = txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source.values.insert(txid, Ok(Some(bytes)));
        let applied = apply_compact_block_with_transaction_selector(
            &params(),
            &mut runtime,
            &input,
            &mut source,
            |_| true,
        )
        .unwrap();
        let transaction = &applied.core().transactions()[0];
        assert_eq!(
            transaction.full_transaction_acquisition(),
            FullTransactionAcquisition::ExtendedEffects
        );
        assert!(!transaction.is_carrier_candidate());
        assert_eq!(
            applied.transactions()[0].message(),
            &ApplicationMessageStatus::NotCandidate
        );
    }

    #[test]
    fn extended_effects_authenticate_full_ironwood_effects_without_carrier_routing() {
        let mut runtime = runtime();
        let fixture = full_ironwood_transaction(alternate_receiver(), [0; 512], 4);
        let mut compact = compact_tx(7, 4, vec![fixture.compact.clone()]);
        compact.txid = fixture.txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source
            .values
            .insert(fixture.txid, Ok(Some(fixture.bytes.clone())));

        let applied = apply_compact_block_with_transaction_selector(
            &params(),
            &mut runtime,
            &input,
            &mut source,
            |_| true,
        )
        .unwrap();
        assert_eq!(source.calls, vec![fixture.txid]);
        let transaction = &applied.core().transactions()[0];
        assert_eq!(
            transaction.full_transaction_acquisition(),
            FullTransactionAcquisition::ExtendedEffects
        );
        assert!(!transaction.is_carrier_candidate());
        assert_eq!(
            transaction.ironwood_effects().nullifiers(),
            &[fixture.nullifier]
        );
        assert_eq!(
            transaction.ironwood_effects().commitments(),
            &[fixture.commitment]
        );
        let extended = transaction.ironwood_effects().extended().unwrap();
        assert_eq!(extended.actions.len(), 1);
        assert_eq!(extended.actions[0].nullifier, fixture.nullifier);
        assert_eq!(extended.actions[0].commitment, fixture.commitment);
        assert_eq!(
            extended.actions[0].value_commitment,
            fixture.value_commitment
        );
        assert_eq!(extended.actions[0].randomized_key, fixture.randomized_key);
        assert_eq!(extended.value_balance, fixture.value_balance);
        assert!(extended.flags.spends_enabled);
        assert!(extended.flags.outputs_enabled);
        assert!(extended.flags.cross_address_enabled);
        assert_eq!(
            applied.transactions()[0].message(),
            &ApplicationMessageStatus::NotCandidate
        );
    }

    #[test]
    fn carrier_acquisition_routes_once_without_exposing_extended_effects() {
        let mut runtime = runtime();
        let key = ApplicationKey::new(ApplicationId::from_bytes([7; 32]), 1);
        let envelope = ApplicationEnvelopeV1::new(key, vec![1]).unwrap().encode();
        let frame = transport::encode_frames(runtime.runtime_id().to_bytes(), &envelope)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let fixture = full_ironwood_transaction(configured_receiver(), frame, 5);
        let mut compact = compact_tx(7, 5, vec![fixture.compact.clone()]);
        compact.txid = fixture.txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source
            .values
            .insert(fixture.txid, Ok(Some(fixture.bytes.clone())));

        let applied = apply_compact_block(&params(), &mut runtime, &input, &mut source).unwrap();
        assert_eq!(source.calls, vec![fixture.txid]);
        let transaction = &applied.core().transactions()[0];
        assert_eq!(
            transaction.full_transaction_acquisition(),
            FullTransactionAcquisition::Carrier
        );
        assert!(transaction.is_carrier_candidate());
        assert!(
            transaction
                .full_transaction_status()
                .validated_full_transaction()
                .is_some()
        );
        assert!(transaction.ironwood_effects().extended().is_none());
        assert!(matches!(
            applied.transactions()[0].message(),
            ApplicationMessageStatus::Message(message) if message.key() == key
        ));
    }

    #[test]
    fn carrier_and_extended_effects_fetch_once_route_once_and_expose_effects() {
        let mut runtime = runtime();
        let key = ApplicationKey::new(ApplicationId::from_bytes([8; 32]), 1);
        let envelope = ApplicationEnvelopeV1::new(key, vec![2]).unwrap().encode();
        let frame = transport::encode_frames(runtime.runtime_id().to_bytes(), &envelope)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let fixture = full_ironwood_transaction(configured_receiver(), frame, 6);
        let mut compact = compact_tx(7, 6, vec![fixture.compact.clone()]);
        compact.txid = fixture.txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source.values.insert(fixture.txid, Ok(Some(fixture.bytes)));

        let applied = apply_compact_block_with_transaction_selector(
            &params(),
            &mut runtime,
            &input,
            &mut source,
            |_| true,
        )
        .unwrap();
        assert_eq!(source.calls, vec![fixture.txid]);
        let transaction = &applied.core().transactions()[0];
        assert_eq!(
            transaction.full_transaction_acquisition(),
            FullTransactionAcquisition::CarrierAndExtendedEffects
        );
        assert!(transaction.is_carrier_candidate());
        assert!(transaction.ironwood_effects().extended().is_some());
        assert!(matches!(
            applied.transactions()[0].message(),
            ApplicationMessageStatus::Message(message) if message.key() == key
        ));
    }

    #[test]
    fn cumulative_full_transaction_budget_is_bounded() {
        let runtime = runtime();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![real_rendezvous_action()]),
                compact_tx(7, 2, vec![real_rendezvous_action()]),
            ],
        );
        let each = MAX_FULL_TRANSACTION_BYTES / 2 + 1;
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![0; each])));
        source.values.insert([2; 32], Ok(Some(vec![0; each])));
        assert!(matches!(
            prepare_canonical_block(&params(), &runtime, &input, &mut source),
            Err(CompactBlockAdapterError::FullTransactionBudgetExceeded {
                txid,
                attempted,
                limit: MAX_FULL_TRANSACTION_BYTES,
                ..
            }) if txid == [2; 32] && attempted == each * 2
        ));
        assert_eq!(source.calls, vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn preflight_and_late_source_failure_do_not_apply() {
        let mut runtime = runtime();
        let mut wrong_predecessor = block(
            &runtime,
            vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
        );
        wrong_predecessor.prev_hash = vec![8; 32];
        let mut source = Source::default();
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &wrong_predecessor, &mut source),
            Err(CompactBlockApplyError::Prepare(
                CompactBlockAdapterError::PredecessorMismatch
            ))
        ));
        assert!(source.calls.is_empty());

        let hit = real_rendezvous_action();
        let input = block(
            &runtime,
            vec![
                compact_tx(2, 1, vec![hit.clone()]),
                compact_tx(7, 2, vec![hit]),
            ],
        );
        source.values.insert([1; 32], Ok(Some(vec![1])));
        source.values.insert([2; 32], Err("late transport"));
        let before_tip = runtime.tip();
        let before_root = runtime.ironwood_frontier().root();
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &input, &mut source),
            Err(CompactBlockApplyError::Prepare(
                CompactBlockAdapterError::FullTransactionSource("late transport")
            ))
        ));
        assert_eq!(source.calls, vec![[1; 32], [2; 32]]);
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
    }

    #[test]
    fn missing_or_failed_fetch_never_advances_runtime() {
        for value in [Ok(None), Err("transport")] {
            let mut runtime = runtime();
            let before_tip = runtime.tip();
            let before_root = runtime.ironwood_frontier().root();
            let before_checkpoints = runtime.ironwood_checkpoints().clone();
            let input = block(
                &runtime,
                vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
            );
            let mut source = Source::default();
            source.values.insert([1; 32], value);
            assert!(apply_compact_block(&params(), &mut runtime, &input, &mut source).is_err());
            assert_eq!(runtime.tip(), before_tip);
            assert_eq!(runtime.ironwood_frontier().root(), before_root);
            assert_eq!(runtime.ironwood_checkpoints(), &before_checkpoints);
        }
    }

    #[test]
    fn noncarrier_compact_effects_apply_without_fetch() {
        let mut runtime = runtime();
        let action = noncandidate_action();
        let expected: CompactAction = (&action).try_into().unwrap();
        let input = block(&runtime, vec![compact_tx(7, 1, vec![action])]);
        let mut source = Source::default();
        let prepared = prepare_canonical_block(&params(), &runtime, &input, &mut source).unwrap();
        assert_eq!(
            prepared.transactions[0].ironwood_nullifiers,
            vec![expected.nullifier().to_bytes()]
        );
        let applied = apply_compact_block(&params(), &mut runtime, &input, &mut source).unwrap();
        assert!(source.calls.is_empty());
        assert_eq!(applied.ironwood_checkpoint().tree_size, 1);
    }

    #[test]
    fn branch_id_is_parameter_derived() {
        let runtime = runtime();
        let input = block(&runtime, vec![]);
        let mut before_nu6_3 = params();
        before_nu6_3.nu6_3 = None;
        let mut source = Source::default();
        let prepared =
            prepare_canonical_block(&before_nu6_3, &runtime, &input, &mut source).unwrap();
        assert_eq!(prepared.branch_id, BranchId::Nu6_2);
        assert_ne!(prepared.branch_id, BranchId::Nu6_3);
    }

    #[test]
    fn malformed_fetched_transaction_is_core_fatal_and_atomic() {
        let mut runtime = runtime();
        let input = block(
            &runtime,
            vec![compact_tx(2, 1, vec![real_rendezvous_action()])],
        );
        let before_tip = runtime.tip();
        let before_root = runtime.ironwood_frontier().root();
        let mut source = Source::default();
        source.values.insert([1; 32], Ok(Some(vec![0; 4])));
        assert!(matches!(
            apply_compact_block(&params(), &mut runtime, &input, &mut source),
            Err(CompactBlockApplyError::Runtime(
                CoreReplayError::InvalidFullTransaction
            ))
        ));
        assert_eq!(runtime.tip(), before_tip);
        assert_eq!(runtime.ironwood_frontier().root(), before_root);
    }

    #[test]
    fn txid_mismatch_from_selected_full_transaction_is_core_fatal() {
        let runtime = runtime();
        let (bytes, actual_txid) = empty_transaction();
        let mut wrong_txid = actual_txid;
        wrong_txid[0] ^= 1;
        let mut compact = compact_tx(7, 4, vec![]);
        compact.txid = wrong_txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source.values.insert(wrong_txid, Ok(Some(bytes)));
        assert!(matches!(
            apply_compact_block_with_transaction_selector(
                &params(),
                &mut runtime.clone(),
                &input,
                &mut source,
                |_| true,
            ),
            Err(CompactBlockApplyError::Runtime(
                CoreReplayError::TxidMismatch
            ))
        ));
    }

    #[test]
    fn compact_full_effect_mismatch_is_core_fatal() {
        let runtime = runtime();
        let (bytes, actual_txid) = empty_transaction();
        let mut compact = compact_tx(7, 4, vec![noncandidate_action()]);
        compact.txid = actual_txid.to_vec();
        let input = block(&runtime, vec![compact]);
        let mut source = Source::default();
        source.values.insert(actual_txid, Ok(Some(bytes)));
        assert!(matches!(
            apply_compact_block_with_transaction_selector(
                &params(),
                &mut runtime.clone(),
                &input,
                &mut source,
                |_| true,
            ),
            Err(CompactBlockApplyError::Runtime(
                CoreReplayError::IronwoodEffectsMismatch
            ))
        ));
    }

    #[test]
    fn compact_nullifier_and_commitment_mismatches_are_independently_core_fatal() {
        let runtime = runtime();
        let fixture = full_ironwood_transaction(alternate_receiver(), [0; 512], 9);

        let mut nullifier_mismatch = fixture.compact.clone();
        nullifier_mismatch.nullifier = vec![0; 32];
        let mut commitment_mismatch = fixture.compact.clone();
        commitment_mismatch.cmx = alternate_rendezvous_action().cmx;

        for action in [nullifier_mismatch, commitment_mismatch] {
            let mut compact = compact_tx(7, 9, vec![action]);
            compact.txid = fixture.txid.to_vec();
            let input = block(&runtime, vec![compact]);
            let mut source = Source::default();
            source
                .values
                .insert(fixture.txid, Ok(Some(fixture.bytes.clone())));
            assert!(matches!(
                apply_compact_block_with_transaction_selector(
                    &params(),
                    &mut runtime.clone(),
                    &input,
                    &mut source,
                    |_| true,
                ),
                Err(CompactBlockApplyError::Runtime(
                    CoreReplayError::IronwoodEffectsMismatch
                ))
            ));
        }
    }
}
