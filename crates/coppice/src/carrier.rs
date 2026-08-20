//! Real (but self-contained) Ironwood carrier construction for the POC.
use crate::{
    DEFAULT_TAG_BITS,
    envelope::{self, Operation},
};
use incrementalmerkletree::Retention;
use orchard::{
    keys::{FullViewingKey, IncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note_encryption::IronwoodDomain,
    tree::MerkleHashOrchard,
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor,
        signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
    },
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    Transaction, TxId,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};

#[derive(Debug)]
pub enum Error {
    Envelope,
    Build,
    Pczt,
    Grind,
}
pub struct BuiltCoppiceTx {
    pub tx: Transaction,
    pub txid: TxId,
    pub attempts: u64,
    pub frame_count: usize,
    pub grind_elapsed: std::time::Duration,
    pub grind_profile: GrindProfile,
    /// Canonical nullifier of the real fixture note spent by this transaction.
    pub input_nullifier: [u8; 32],
}
pub struct GroundPczt {
    pub pczt: Pczt,
    pub txid: TxId,
    pub attempts: u64,
    pub frame_count: usize,
}
pub struct GroundPcztBytes {
    pub bytes: Vec<u8>,
    pub txid: TxId,
    pub attempts: u64,
    pub frame_count: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct GrindProfile {
    pub pczt_clone: std::time::Duration,
    pub redaction: std::time::Duration,
    pub io_finalizer: std::time::Duration,
    pub txid_digest: std::time::Duration,
    pub memo_update: std::time::Duration,
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
/// Deterministic, test-only public bulletin IVK. Its notes carry no authority.
pub fn bulletin_ivk() -> IncomingViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([0x42; 32]).unwrap()).to_ivk(Scope::External)
}
pub fn bulletin_address() -> orchard::Address {
    FullViewingKey::from(&SpendingKey::from_bytes([0x42; 32]).unwrap())
        .address_at(0u32, Scope::External)
}
fn effects_id(p: Pczt) -> Result<TxId, Error> {
    let e = p.into_effects().map_err(|_| Error::Pczt)?;
    Ok(to_txid(
        e.version(),
        e.consensus_branch_id(),
        &e.digest(TxIdDigester),
    ))
}
fn candidate(
    base: &Pczt,
    indexes: &[usize],
    memos: &[[u8; 512]],
    profile: &mut GrindProfile,
) -> Result<Pczt, Error> {
    let start = std::time::Instant::now();
    let base = base.clone();
    profile.pczt_clone += start.elapsed();
    let start = std::time::Instant::now();
    let p = Redactor::new(base)
        .redact_ironwood_with(|mut r| {
            for (index, memo) in indexes.iter().zip(memos) {
                r.redact_action(*index, |mut a| {
                    a.replace_enc_ciphertext_with_memo_plaintext(*memo)
                })
            }
        })
        .finish();
    profile.redaction += start.elapsed();
    let start = std::time::Instant::now();
    let result = IoFinalizer::new(p).finalize_io().map_err(|_| Error::Pczt);
    profile.io_finalizer += start.elapsed();
    result
}
/// Builds a real V6 Ironwood transaction. The input note is a POC fixture; it is cryptographically
/// valid and spends through the normal PCZT flow, but is not a funded chain/regtest wallet note.
pub fn build_coppice_transaction(op: &Operation, tag_bits: u8) -> Result<BuiltCoppiceTx, Error> {
    let payload = envelope::encode_operation(op).map_err(|_| Error::Envelope)?;
    build_coppice_payload(&payload, tag_bits)
}

/// Adds Coppice memo frames to pre-authorization Ironwood bulletin outputs in an existing PCZT.
/// The returned PCZT is still unproved and unsigned.
pub fn grind_existing_pczt(base: Pczt, op: &Operation, tag_bits: u8) -> Result<GroundPczt, Error> {
    if tag_bits == 0 || tag_bits > 16 {
        return Err(Error::Grind);
    }
    let payload = envelope::encode_operation(op).map_err(|_| Error::Envelope)?;
    let frames = envelope::frames(&payload, 0, 400).map_err(|_| Error::Envelope)?;
    let recipient = bulletin_address().to_raw_address_bytes();
    let indexes = base
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            (action.output().recipient().as_ref() == Some(&recipient)).then_some(index)
        })
        .collect::<Vec<_>>();
    if indexes.len() != frames.len() {
        return Err(Error::Build);
    }
    let mut memos = frames
        .iter()
        .map(|frame| {
            let mut memo = [0u8; 512];
            memo[..frame.len()].copy_from_slice(frame);
            memo
        })
        .collect::<Vec<_>>();
    let mut profile = GrindProfile::default();
    for nonce in 0u64..=u16::MAX as u64 {
        for memo in &mut memos {
            memo[52..60].copy_from_slice(&nonce.to_be_bytes());
        }
        let pczt = candidate(&base, &indexes, &memos, &mut profile)?;
        let txid = effects_id(pczt)?;
        let raw: [u8; 32] = txid.into();
        if crate::txid_matches_tag(&raw, 0, tag_bits as usize) {
            let pczt = candidate(&base, &indexes, &memos, &mut GrindProfile::default())?;
            return Ok(GroundPczt {
                pczt,
                txid,
                attempts: nonce + 1,
                frame_count: frames.len(),
            });
        }
    }
    Err(Error::Grind)
}

/// Serialization boundary for wallets whose librustzcash PCZT crate is older
/// than the POC's effecting-data helper API. PCZT wire semantics are unchanged.
pub fn grind_serialized_pczt(
    encoded: &[u8],
    op: &Operation,
    tag_bits: u8,
) -> Result<GroundPcztBytes, Error> {
    let base = Pczt::parse(encoded).map_err(|_| Error::Pczt)?;
    let ground = grind_existing_pczt(base, op, tag_bits)?;
    Ok(GroundPcztBytes {
        bytes: ground.pczt.serialize().map_err(|_| Error::Pczt)?,
        txid: ground.txid,
        attempts: ground.attempts,
        frame_count: ground.frame_count,
    })
}

/// Constructs a valid carrier around arbitrary logical bytes for adversarial scanner fixtures.
pub fn build_coppice_payload(payload: &[u8], tag_bits: u8) -> Result<BuiltCoppiceTx, Error> {
    if tag_bits == 0 || tag_bits > 16 {
        return Err(Error::Grind);
    }
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
    for _ in &frames {
        b.add_ironwood_output::<zip317::FeeRule>(
            None,
            bulletin_address(),
            Zatoshis::const_from_u64(BULLETIN_VALUE),
            MemoBytes::empty(),
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
    let output_indexes = (0..frames.len())
        .map(|i| {
            result
                .ironwood_meta
                .output_action_index(i)
                .ok_or(Error::Build)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let spend_index = result
        .ironwood_meta
        .spend_action_index(0)
        .ok_or(Error::Build)?;
    let base = Creator::build_from_parts(result.pczt_parts).ok_or(Error::Pczt)?;
    let input_nullifier = *base
        .ironwood()
        .actions()
        .get(spend_index)
        .ok_or(Error::Pczt)?
        .spend()
        .nullifier();
    let tag = 0u16;
    let mut chosen = None;
    let mut grind_profile = GrindProfile::default();
    let grind_start = std::time::Instant::now();
    let mut candidate_memos = memos;
    for n in 0u64..65536 {
        let start = std::time::Instant::now();
        for m in &mut candidate_memos {
            m[52..60].copy_from_slice(&n.to_be_bytes());
        }
        grind_profile.memo_update += start.elapsed();
        let p = candidate(&base, &output_indexes, &candidate_memos, &mut grind_profile)?;
        let start = std::time::Instant::now();
        let id = effects_id(p)?;
        grind_profile.txid_digest += start.elapsed();
        let raw: [u8; 32] = id.into();
        if crate::txid_matches_tag(&raw, tag, tag_bits as usize) {
            chosen = Some((n + 1, n, id));
            break;
        }
    }
    let (attempts, winning_nonce, txid) = chosen.ok_or(Error::Grind)?;
    for m in &mut candidate_memos {
        m[52..60].copy_from_slice(&winning_nonce.to_be_bytes());
    }
    // Reconstruct the single winning effect bundle after the search. This avoids cloning every
    // finalized PCZT merely to retain the rare winner.
    let p = candidate(
        &base,
        &output_indexes,
        &candidate_memos,
        &mut GrindProfile::default(),
    )?;
    let grind_elapsed = grind_start.elapsed();
    let p = Prover::new(p)
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
    if tx.txid() != txid {
        return Err(Error::Pczt);
    }
    Ok(BuiltCoppiceTx {
        tx,
        txid,
        attempts,
        frame_count: frames.len(),
        grind_elapsed,
        grind_profile,
        input_nullifier,
    })
}
pub fn decode_bulletin(tx: &Transaction) -> Result<Operation, Error> {
    let b = tx.ironwood_bundle().ok_or(Error::Envelope)?;
    let mut frames = Vec::new();
    for action in b.actions() {
        let domain = IronwoodDomain::for_action(action);
        if let Some((_, _, memo)) = try_note_decryption(&domain, &bulletin_ivk().prepare(), action)
        {
            if let Ok(frame) = envelope::frame_from_memo(&memo) {
                frames.push(frame);
            }
        }
    }
    let p = envelope::reconstruct(frames).map_err(|_| Error::Envelope)?;
    envelope::decode_operation(&p).map_err(|_| Error::Envelope)
}
pub fn default_tag_bits() -> u8 {
    DEFAULT_TAG_BITS as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_carrier_round_trip_and_effects() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Register {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA_A".to_vec(),
        };
        let built = build_coppice_transaction(&op, 8).unwrap();
        assert!(crate::is_coppice_candidate(&built.txid, 8));
        let mut bytes = Vec::new();
        built.tx.write(&mut bytes).unwrap();
        let parsed =
            Transaction::read(bytes.as_slice(), zcash_protocol::consensus::BranchId::Nu6_3)
                .unwrap();
        assert_eq!(parsed.txid(), built.txid);
        assert_eq!(decode_bulletin(&parsed).unwrap(), op);
        let effects = crate::ironwood::extract_ironwood_effects(&parsed);
        assert!(!effects.commitments.is_empty());
        assert_eq!(effects.commitments.len(), effects.nullifiers.len());
    }
    #[test]
    fn real_multiframe_carrier_round_trip() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Register {
            name: "frames".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: vec![0x55; 900],
        };
        let built = build_coppice_transaction(&op, 12).unwrap();
        let mut bytes = Vec::new();
        built.tx.write(&mut bytes).unwrap();
        println!(
            "multiframe payload={} frames={} actions={} bytes={} attempts={} rate={:.0}/s proofs-in-loop=0 signatures-in-loop=0 proofs-after=1 signing-after=1",
            crate::envelope::encode_operation(&op).unwrap().len(),
            built.frame_count,
            built.tx.ironwood_bundle().unwrap().actions().len(),
            bytes.len(),
            built.attempts,
            built.attempts as f64 / built.grind_elapsed.as_secs_f64()
        );
        assert!(built.frame_count >= 2);
        assert!(built.tx.ironwood_bundle().unwrap().actions().len() >= built.frame_count);
        assert_eq!(decode_bulletin(&built.tx).unwrap(), op);
    }
}
