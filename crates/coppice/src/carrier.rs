//! Real (but self-contained) Ironwood carrier construction for the POC.
use crate::{
    config::Rendezvous,
    envelope::{self, Operation},
};
use incrementalmerkletree::Retention;
use orchard::{
    keys::{FullViewingKey, IncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note_encryption::IronwoodDomain,
    tree::MerkleHashOrchard,
};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, signer::Signer,
    spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::{try_compact_note_decryption, try_note_decryption};
use zcash_primitives::transaction::{
    Transaction, TxId,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};

#[derive(Debug)]
pub enum Error {
    NotFound,
    Envelope,
    Build,
    Pczt,
}
pub struct BuiltCoppiceTx {
    pub tx: Transaction,
    pub txid: TxId,
    pub frame_count: usize,
    /// Canonical nullifier of the real fixture note spent by this transaction.
    pub input_nullifier: [u8; 32],
}
fn network() -> zcash_protocol::local_consensus::LocalNetwork {
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: Some(BlockHeight::from_u32(10)),
        #[cfg(zcash_unstable = "nu7")]
        nu7: None,
    }
}
/// Returns the deployment's public incoming capability. It contains no spending authority.
pub fn bulletin_ivk(rendezvous: Rendezvous) -> Result<IncomingViewingKey, Error> {
    Option::from(IncomingViewingKey::from_bytes(&rendezvous.orchard_ivk)).ok_or(Error::Build)
}
pub fn bulletin_address(rendezvous: Rendezvous) -> Result<orchard::Address, Error> {
    Option::from(orchard::Address::from_raw_address_bytes(
        &rendezvous.orchard_receiver,
    ))
    .ok_or(Error::Build)
}
/// Builds a real V6 Ironwood transaction. The input note is a POC fixture; it is cryptographically
/// valid and spends through the normal PCZT flow, but is not a funded chain/regtest wallet note.
pub fn build_coppice_transaction(op: &Operation) -> Result<BuiltCoppiceTx, Error> {
    build_coppice_transaction_for(op, crate::config::TESTNET_V0.rendezvous)
}

pub fn build_coppice_transaction_for(
    op: &Operation,
    rendezvous: Rendezvous,
) -> Result<BuiltCoppiceTx, Error> {
    let payload = envelope::encode_operation(op).map_err(|_| Error::Envelope)?;
    build_coppice_payload_for(&payload, rendezvous)
}

/// Constructs a valid carrier around arbitrary logical bytes for adversarial scanner fixtures.
pub fn build_coppice_payload(payload: &[u8]) -> Result<BuiltCoppiceTx, Error> {
    build_coppice_payload_for(payload, crate::config::TESTNET_V0.rendezvous)
}

pub fn build_coppice_payload_for(
    payload: &[u8],
    rendezvous: Rendezvous,
) -> Result<BuiltCoppiceTx, Error> {
    let frames = envelope::frames(payload, 0, 400).map_err(|_| Error::Envelope)?;
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"CoppiceCarrierNoteV0");
    seed_hasher.update(payload);
    let seed: [u8; 32] = seed_hasher.finalize().into();
    let mut fixture_rng = ChaCha20Rng::from_seed(seed);
    let mut memos = Vec::new();
    for frame in &frames {
        let mut memo = [0u8; 512];
        memo[..frame.len()].copy_from_slice(frame);
        memos.push(memo);
    }
    let source =
        Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).ok_or(Error::Build)?;
    let ask = SpendAuthorizingKey::from(&source);
    let fvk = FullViewingKey::from(&source);
    let ivk = fvk.to_ivk(Scope::External);
    let recipient = fvk.address_at(0u32, Scope::External);
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut ob = orchard::builder::Builder::new(
        orchard::builder::BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .map_err(|_| Error::Build)?;
    ob.add_output(
        None,
        recipient,
        orchard::value::NoteValue::from_raw(1_000_000),
        MemoBytes::empty().into_bytes(),
    )
    .map_err(|_| Error::Build)?;
    let (bundle, meta) = ob
        .build::<i64>(&mut fixture_rng)
        .map_err(|_| Error::Build)?
        .ok_or(Error::Build)?;
    let action = bundle
        .actions()
        .get(meta.output_action_index(0).ok_or(Error::Build)?)
        .ok_or(Error::Build)?;
    let domain = IronwoodDomain::for_action(action);
    let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action).ok_or(Error::Build)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    tree.append(leaf, Retention::Marked)
        .map_err(|_| Error::Build)?;
    tree.checkpoint(9_999_999).map_err(|_| Error::Build)?;
    let path: orchard::tree::MerklePath = tree
        .witness_at_checkpoint_depth(0.into(), 0)
        .map_err(|_| Error::Build)?
        .ok_or(Error::Build)?
        .into();
    let anchor = path.root(cmx);
    let mut b = Builder::new(
        network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::UNPADDED,
            ironwood_padding: BundlePadding::UNPADDED,
        },
    );
    b.add_ironwood_spend::<zip317::FeeRule>(fvk, note, path)
        .map_err(|_| Error::Build)?;
    // Zero-valued shielded outputs are consensus-valid and accepted by the current
    // public builder. The fixture therefore gives bulletin notes no economic value.
    const BULLETIN_VALUE: u64 = 0;
    for memo in &memos {
        b.add_ironwood_output::<zip317::FeeRule>(
            None,
            bulletin_address(rendezvous)?,
            Zatoshis::const_from_u64(BULLETIN_VALUE),
            MemoBytes::from_bytes(memo).map_err(|_| Error::Envelope)?,
        )
        .map_err(|_| Error::Build)?;
    }
    // One change output makes the ZIP-317 fee explicit. The resulting bundle has
    // max(1 spend, frame_count + 1 outputs) logical actions, with a two-action grace.
    let logical_actions = (frames.len() + 1).max(2) as u64;
    let fee = logical_actions * 5_000;
    b.add_ironwood_output::<zip317::FeeRule>(
        None,
        recipient,
        Zatoshis::const_from_u64(1_000_000 - fee),
        MemoBytes::empty(),
    )
    .map_err(|_| Error::Build)?;
    let result = b
        .build_for_pczt(&mut fixture_rng, &zip317::FeeRule::standard())
        .map_err(|e| {
            eprintln!("ironwood builder: {e:?}");
            Error::Build
        })?;
    let spend_index = result
        .ironwood_meta
        .spend_action_index(0)
        .ok_or(Error::Build)?;
    let created = Creator::build_from_parts(result.pczt_parts).ok_or(Error::Pczt)?;
    let base = IoFinalizer::new(created)
        .finalize_io()
        .map_err(|_| Error::Pczt)?;
    let input_nullifier = *base
        .ironwood()
        .actions()
        .get(spend_index)
        .ok_or(Error::Pczt)?
        .spend()
        .nullifier();
    let p = Prover::new(base)
        .create_ironwood_proof(&orchard::circuit::ProvingKey::build(
            orchard::circuit::OrchardCircuitVersion::PostNu6_3,
        ))
        .map_err(|_| Error::Pczt)?
        .finish();
    let mut signer = Signer::new(p).map_err(|_| Error::Pczt)?;
    signer
        .sign_ironwood(spend_index, &ask)
        .map_err(|_| Error::Pczt)?;
    let p = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .map_err(|_| Error::Pczt)?;
    let tx = TransactionExtractor::new(p)
        .extract()
        .map_err(|_| Error::Pczt)?;
    let txid = tx.txid();
    Ok(BuiltCoppiceTx {
        tx,
        txid,
        frame_count: frames.len(),
        input_nullifier,
    })
}

/// Detects a rendez-vous output from compact Ironwood data without fetching the full transaction.
pub fn compact_action_is_bulletin(
    action: &orchard::note_encryption::CompactAction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let domain = IronwoodDomain::for_compact_action(action);
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    Ok(try_compact_note_decryption(&domain, &ivk, action).is_some())
}

pub fn transaction_has_bulletin_output(
    tx: &Transaction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let Some(bundle) = tx.ironwood_bundle() else {
        return Ok(false);
    };
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    Ok(bundle.actions().iter().any(|action| {
        let domain = IronwoodDomain::for_action(action);
        try_note_decryption(&domain, &ivk, action).is_some()
    }))
}
pub fn decode_bulletin(tx: &Transaction) -> Result<Operation, Error> {
    decode_bulletin_for(tx, crate::config::TESTNET_V0.rendezvous)
}

pub fn decode_bulletin_for(tx: &Transaction, rendezvous: Rendezvous) -> Result<Operation, Error> {
    let b = tx.ironwood_bundle().ok_or(Error::NotFound)?;
    let ivk = bulletin_ivk(rendezvous)?.prepare();
    let mut frames = Vec::new();
    let mut saw_coppice = false;
    for action in b.actions() {
        let domain = IronwoodDomain::for_action(action);
        if let Some((_, _, memo)) = try_note_decryption(&domain, &ivk, action) {
            if memo.starts_with(crate::DOMAIN) {
                saw_coppice = true;
                frames.push(envelope::frame_from_memo(&memo).map_err(|_| Error::Envelope)?);
            }
        }
    }
    if !saw_coppice {
        return Err(Error::NotFound);
    }
    let p = envelope::reconstruct(frames).map_err(|_| Error::Envelope)?;
    envelope::decode_operation(&p).map_err(|_| Error::Envelope)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_carrier_round_trip_and_effects() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Reveal {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA_A".to_vec(),
            secret: [9; 32],
        };
        let rendezvous = crate::config::REGTEST_V0.rendezvous;
        let built = build_coppice_transaction_for(&op, rendezvous).unwrap();
        assert!(
            built
                .tx
                .ironwood_bundle()
                .unwrap()
                .actions()
                .iter()
                .any(|action| compact_action_is_bulletin(
                    &orchard::note_encryption::CompactAction::from(action),
                    rendezvous,
                )
                .unwrap())
        );
        let mut bytes = Vec::new();
        built.tx.write(&mut bytes).unwrap();
        let parsed =
            Transaction::read(bytes.as_slice(), zcash_protocol::consensus::BranchId::Nu6_3)
                .unwrap();
        assert_eq!(parsed.txid(), built.txid);
        assert_eq!(decode_bulletin_for(&parsed, rendezvous).unwrap(), op);
        assert!(matches!(
            decode_bulletin_for(&parsed, crate::config::TESTNET_V0.rendezvous),
            Err(Error::NotFound)
        ));
        let effects = crate::ironwood::extract_ironwood_effects(&parsed);
        assert!(!effects.commitments.is_empty());
        assert_eq!(effects.commitments.len(), effects.nullifiers.len());
    }
    #[test]
    fn real_multiframe_carrier_round_trip() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Reveal {
            name: "frames".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: vec![0x55; 900],
            secret: [9; 32],
        };
        let built = build_coppice_transaction(&op).unwrap();
        let mut bytes = Vec::new();
        built.tx.write(&mut bytes).unwrap();
        println!(
            "multiframe payload={} frames={} actions={} bytes={} proofs=1 signing=1",
            crate::envelope::encode_operation(&op).unwrap().len(),
            built.frame_count,
            built.tx.ironwood_bundle().unwrap().actions().len(),
            bytes.len()
        );
        assert!(built.frame_count >= 2);
        assert!(built.tx.ironwood_bundle().unwrap().actions().len() >= built.frame_count);
        assert_eq!(decode_bulletin(&built.tx).unwrap(), op);
    }
}
