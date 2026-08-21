//! This regression exercises the actual PCZT effecting-data -> proof -> authorization lifecycle.
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
use rand_core::OsRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use std::time::Instant;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};

fn params() -> zcash_protocol::local_consensus::LocalNetwork {
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

fn base() -> (Pczt, SpendAuthorizingKey, IncomingViewingKey) {
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let ask = SpendAuthorizingKey::from(&sk);
    let fvk = FullViewingKey::from(&sk);
    let ivk = fvk.to_ivk(Scope::External);
    let recipient = fvk.address_at(0u32, Scope::External);
    let ovk = fvk.to_ovk(Scope::External);
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut ob = orchard::builder::Builder::new(
        orchard::builder::BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    ob.add_output(
        None,
        recipient,
        orchard::value::NoteValue::from_raw(1_000_000),
        MemoBytes::empty().into_bytes(),
    )
    .unwrap();
    let (bundle, meta) = ob.build::<i64>(&mut OsRng).unwrap().unwrap();
    let action = bundle
        .actions()
        .get(meta.output_action_index(0).unwrap())
        .unwrap();
    let domain = IronwoodDomain::for_action(action);
    let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action).unwrap();
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    tree.append(leaf, Retention::Marked).unwrap();
    tree.checkpoint(9_999_999).unwrap();
    let path: orchard::tree::MerklePath = tree
        .witness_at_checkpoint_depth(0.into(), 0)
        .unwrap()
        .unwrap()
        .into();
    let anchor = path.root(cmx);
    let mut b = Builder::new(
        params(),
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
        .unwrap();
    b.add_ironwood_output::<zip317::FeeRule>(
        Some(ovk),
        recipient,
        Zatoshis::const_from_u64(990_000),
        MemoBytes::empty(),
    )
    .unwrap();
    let result = b
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    (
        Creator::build_from_parts(result.pczt_parts).unwrap(),
        ask,
        ivk,
    )
}
fn candidate(base: Pczt, nonce: u64) -> Pczt {
    let mut memo = [0u8; 512];
    memo[..8].copy_from_slice(&nonce.to_be_bytes());
    let p = Redactor::new(base)
        .redact_ironwood_with(|mut r| {
            r.redact_actions(|mut a| a.replace_enc_ciphertext_with_memo_plaintext(memo))
        })
        .finish();
    IoFinalizer::new(p).finalize_io().unwrap()
}
fn txid(p: Pczt) -> zcash_primitives::transaction::TxId {
    let effects = p.into_effects().unwrap();
    to_txid(
        effects.version(),
        effects.consensus_branch_id(),
        &effects.digest(TxIdDigester),
    )
}

#[test]
fn preauthorization_memo_grind_keeps_action_statement_fixed() {
    let (base, ask, ivk) = base();
    let a = candidate(base.clone(), 1);
    let b = candidate(base, 2);
    let aa = &a.ironwood().actions()[0];
    let bb = &b.ironwood().actions()[0];
    assert_eq!(aa.cv_net(), bb.cv_net());
    assert_eq!(aa.spend().nullifier(), bb.spend().nullifier());
    assert_eq!(aa.spend().rk(), bb.spend().rk());
    assert_eq!(aa.output().cmx(), bb.output().cmx());
    assert_eq!(aa.output().ephemeral_key(), bb.output().ephemeral_key());
    assert_eq!(aa.output().out_ciphertext(), bb.output().out_ciphertext());
    assert_eq!(a.ironwood().anchor(), b.ironwood().anchor());
    assert_ne!(aa.output().enc_ciphertext(), bb.output().enc_ciphertext());
    let ea = aa
        .output()
        .enc_ciphertext()
        .clone()
        .into_encrypted()
        .unwrap();
    let eb = bb
        .output()
        .enc_ciphertext()
        .clone()
        .into_encrypted()
        .unwrap();
    assert_eq!(&ea[..52], &eb[..52]);
    let ta = txid(a.clone());
    let tb = txid(b.clone());
    assert_ne!(ta, tb);
    let start = Instant::now();
    let mut winner = None;
    for n in 0u64..32768 {
        let p = candidate(b.clone(), n);
        let id = txid(p.clone());
        let raw: [u8; 32] = id.into();
        if raw[0] == 0 && raw[1] >> 4 == 0 {
            winner = Some((n + 1, p, id));
            break;
        }
    }
    let (attempts, p, winning) = winner.expect("12-bit grind exceeded 32k attempts");
    println!(
        "preauth 12-bit attempts={attempts} elapsed={:?} rate={:.0}/s proofs-in-loop=0 signatures-in-loop=0",
        start.elapsed(),
        attempts as f64 / start.elapsed().as_secs_f64()
    );
    // Wallet integrations carry the grounded PCZT across a serialization
    // boundary before independent prove/sign roles consume it.
    let p = Pczt::parse(&p.serialize().unwrap()).unwrap();
    let p = Prover::new(p)
        .create_ironwood_proof(&orchard::circuit::ProvingKey::build(
            orchard::circuit::OrchardCircuitVersion::PostNu6_3,
        ))
        .unwrap()
        .finish();
    let mut signer = Signer::new(p).unwrap();
    signer.sign_ironwood(0, &ask).unwrap();
    let p = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .unwrap();
    let final_tx = TransactionExtractor::new(p).extract().unwrap();
    assert_eq!(final_tx.txid(), winning);
    let mut bytes = Vec::new();
    final_tx.write(&mut bytes).unwrap();
    let reparsed = zcash_primitives::transaction::Transaction::read(
        bytes.as_slice(),
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .unwrap();
    assert_eq!(reparsed.txid(), winning);
    let action = &reparsed.ironwood_bundle().unwrap().actions()[0];
    let domain = IronwoodDomain::for_action(action);
    let (_, _, memo) = try_note_decryption(&domain, &ivk.prepare(), action).unwrap();
    assert_eq!(&memo[..8], &(attempts - 1).to_be_bytes());
}
