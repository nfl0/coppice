//! First non-recursive private BondCircuit POC, composed from the Orchard Action constraints.
use crate::{
    constants,
    spent::{domain_field, native_hash, spent_tag},
};
use halo2_proofs::{
    plonk::{SingleVerifier, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use incrementalmerkletree::Retention;
use orchard::{
    Note, NoteVersion,
    builder::SpendInfo,
    circuit::{OrchardCircuitVersion, bond::BondCircuit},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{RandomSeed, Rho},
    note_encryption::IronwoodDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor},
};
use pasta_curves::{group::ff::PrimeField, pallas, vesta};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use std::time::{Duration, Instant};
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::memo::MemoBytes;

pub const BOND_K: u32 = 12;
pub const FIXTURE_VALUE: u64 = 1_000_000;
pub const FIXTURE_MINIMUM: u64 = 500_000;

#[derive(Clone, Debug)]
pub struct BondMeasurement {
    pub proof: Vec<u8>,
    pub proving_time: Duration,
    pub verification_time: Duration,
    pub public_input_bytes: usize,
    pub k: u32,
    pub bond_tag: [u8; 32],
    pub anchor: [u8; 32],
    /// Linux high-water resident set size for this process, when available.
    pub peak_memory_kib: Option<u64>,
}

fn peak_memory_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn protocol_binding() -> pallas::Base {
    native_hash(
        constants::BOND_PROTOCOL_DOMAIN,
        domain_field(constants::POC_NETWORK_ID).expect("short network domain"),
    )
    .expect("short protocol domain")
}
fn binding_32(domain: &[u8], bytes: [u8; 32]) -> pallas::Base {
    let lo = pallas::Base::from_u128(u128::from_le_bytes(bytes[..16].try_into().expect("length")));
    let hi = pallas::Base::from_u128(u128::from_le_bytes(bytes[16..].try_into().expect("length")));
    let pair = halo2_gadgets::poseidon::primitives::Hash::<
        _,
        halo2_gadgets::poseidon::primitives::P128Pow5T3,
        halo2_gadgets::poseidon::primitives::ConstantLength<2>,
        3,
        2,
    >::init()
    .hash([lo, hi]);
    native_hash(domain, pair).expect("fixed short domain")
}
pub fn context_binding(name: &str) -> pallas::Base {
    binding_32(constants::BOND_CONTEXT_DOMAIN, crate::owner::name_id(name))
}
pub fn owner_binding(owner_pk: [u8; 32]) -> pallas::Base {
    binding_32(constants::BOND_OWNER_DOMAIN, owner_pk)
}

fn fixture(
    value: u64,
    minimum: u64,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    name: &str,
    owner_pk: [u8; 32],
) -> Option<(BondCircuit, Vec<pallas::Base>, [u8; 32])> {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32]))?;
    let ask = SpendAuthorizingKey::from(&sk);
    let fvk = FullViewingKey::from(&sk);
    let ivk = fvk.to_ivk(Scope::External);
    let recipient = fvk.address_at(0u32, Scope::External);
    let version = orchard::bundle::BundleVersion::ironwood_v3();
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .ok()?;
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(value),
            MemoBytes::empty().into_bytes(),
        )
        .ok()?;
    let mut rng = ChaCha20Rng::from_seed([44; 32]);
    let (bundle, meta) = builder.build::<i64>(&mut rng).ok()??;
    let action = bundle.actions().get(meta.output_action_index(0)?)?;
    let (note, _, _) =
        try_note_decryption(&IronwoodDomain::for_action(action), &ivk.prepare(), action)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Marked)
        .ok()?;
    tree.checkpoint(1).ok()?;
    let mut path: MerklePath = tree.witness_at_checkpoint_depth(0.into(), 0).ok()??.into();
    let anchor = path.root(cmx);
    if corrupt_path {
        let mut auth = path.auth_path();
        auth[0] = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
            &pallas::Base::from(9).to_repr(),
        ))?;
        path = MerklePath::from_parts(path.position(), auth);
    }
    let nf = note.nullifier(&fvk);
    let rho = Rho::from_nf_old(nf);
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([55; 32], &rho))?;
    let output = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(0),
        rho,
        rseed,
        NoteVersion::V3,
    ))?;
    let spend = SpendInfo::new(fvk, note, path)?;
    let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(
        pallas::Scalar::from(3).to_repr(),
    ))?;
    let actual_ask = ask_override.unwrap_or(ask);
    let protocol = protocol_binding();
    let context = context_binding(name);
    let owner = owner_binding(owner_pk);
    let circuit = BondCircuit::from_action_context(
        spend,
        output,
        pallas::Scalar::from(5),
        rcv,
        actual_ask,
        minimum,
        protocol,
        context,
        owner,
        crate::spent::bond_tag_domain_field(),
        OrchardCircuitVersion::PostNu6_3,
    )?;
    let nf_bytes = nf.to_bytes();
    let tag_bytes = spent_tag(&nf_bytes).ok()?;
    let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(tag_bytes))?;
    let anchor_field = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor.to_bytes()))?;
    let instance = vec![
        anchor_field,
        pallas::Base::from(minimum),
        protocol,
        context,
        owner,
        tag,
        pallas::Base::zero(),
        pallas::Base::one(),
        pallas::Base::one(),
        pallas::Base::zero(),
    ];
    Some((circuit, instance, nf_bytes))
}

fn prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    circuit: BondCircuit,
    instance: &[pallas::Base],
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    let columns: [&[pallas::Base]; 1] = [instance];
    let instances: [&[&[pallas::Base]]; 1] = [&columns];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
    create_proof(params, pk, &[circuit], &instances, OsRng, &mut transcript)?;
    Ok(transcript.finalize())
}
fn verify(
    params: &Params<vesta::Affine>,
    vk: &halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
    proof: &[u8],
    instance: &[pallas::Base],
) -> bool {
    let columns: [&[pallas::Base]; 1] = [instance];
    let instances: [&[&[pallas::Base]]; 1] = [&columns];
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
    verify_proof(params, vk, strategy, &instances, &mut transcript).is_ok()
}

pub fn run_bond_poc_for_registration(
    name: &str,
    owner_pk: [u8; 32],
) -> Result<BondMeasurement, String> {
    let (circuit, instance, _) =
        fixture(FIXTURE_VALUE, FIXTURE_MINIMUM, false, None, name, owner_pk).ok_or("fixture")?;
    let params = Params::<vesta::Affine>::new(BOND_K);
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|e| format!("pk: {e:?}"))?;
    let start = Instant::now();
    let proof = prove(&params, &pk, circuit, &instance).map_err(|e| format!("prove: {e:?}"))?;
    let proving_time = start.elapsed();
    let start = Instant::now();
    if !verify(&params, pk.get_vk(), &proof, &instance) {
        return Err("verify".into());
    }
    let verification_time = start.elapsed();
    Ok(BondMeasurement {
        proof,
        proving_time,
        verification_time,
        public_input_bytes: instance.len() * 32,
        k: BOND_K,
        bond_tag: instance[5].to_repr(),
        anchor: instance[0].to_repr(),
        peak_memory_kib: peak_memory_kib(),
    })
}

pub fn run_bond_poc() -> Result<BondMeasurement, String> {
    let key = crate::owner::OwnerSigningKey::try_from([1; 32]).map_err(|_| "owner key")?;
    run_bond_poc_for_registration("bonded", crate::owner::owner_key_bytes(&(&key).into()))
}

pub fn verify_registration_bond(
    name: &str,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    anchor: [u8; 32],
    proof: &[u8],
) -> bool {
    let Some(tag) = Option::<pallas::Base>::from(pallas::Base::from_repr(bond_tag)) else {
        return false;
    };
    let Some(anchor) = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor)) else {
        return false;
    };
    let Some((key_circuit, _, _)) =
        fixture(FIXTURE_VALUE, FIXTURE_MINIMUM, false, None, name, owner_pk)
    else {
        return false;
    };
    let params = Params::<vesta::Affine>::new(BOND_K);
    let Ok(vk) = keygen_vk(&params, &key_circuit) else {
        return false;
    };
    let instance = vec![
        anchor,
        pallas::Base::from(FIXTURE_MINIMUM),
        protocol_binding(),
        context_binding(name),
        owner_binding(owner_pk),
        tag,
        pallas::Base::zero(),
        pallas::Base::one(),
        pallas::Base::one(),
        pallas::Base::zero(),
    ];
    verify(&params, &vk, proof, &instance)
}

#[cfg(test)]
pub(crate) fn test_registration_bond(name: &str) -> &'static BondMeasurement {
    use std::sync::OnceLock;
    static ALICE: OnceLock<BondMeasurement> = OnceLock::new();
    static BOB: OnceLock<BondMeasurement> = OnceLock::new();
    let owner = crate::owner::owner_key_bytes(
        &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
    );
    match name {
        "alice" => ALICE.get_or_init(|| run_bond_poc_for_registration(name, owner).unwrap()),
        "bob" => BOB.get_or_init(|| run_bond_poc_for_registration(name, owner).unwrap()),
        _ => panic!("unsupported shared test bond"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_bond_circuit_positive_and_negative() {
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let (good, instance, _) =
            fixture(FIXTURE_VALUE, FIXTURE_MINIMUM, false, None, "bonded", owner).unwrap();
        let params = Params::<vesta::Affine>::new(BOND_K);
        let vk = keygen_vk(&params, &good).unwrap();
        let pk = keygen_pk(&params, vk, &good).unwrap();
        let proof = prove(&params, &pk, good.clone(), &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &proof, &instance));
        for i in [0usize, 1, 2, 3, 4, 5] {
            let mut bad = instance.clone();
            bad[i] += pallas::Base::one();
            assert!(!verify(&params, pk.get_vk(), &proof, &bad));
        }
        let (low, low_instance, _) =
            fixture(499_999, FIXTURE_MINIMUM, false, None, "bonded", owner).unwrap();
        let low_proof = prove(&params, &pk, low, &low_instance).unwrap();
        assert!(!verify(&params, pk.get_vk(), &low_proof, &low_instance));
        let (wrong_path, wrong_instance, _) =
            fixture(FIXTURE_VALUE, FIXTURE_MINIMUM, true, None, "bonded", owner).unwrap();
        let wrong_proof = prove(&params, &pk, wrong_path, &wrong_instance).unwrap();
        assert!(!verify(&params, pk.get_vk(), &wrong_proof, &wrong_instance));
        let wrong_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap();
        assert!(
            fixture(
                FIXTURE_VALUE,
                FIXTURE_MINIMUM,
                false,
                Some(SpendAuthorizingKey::from(&wrong_sk)),
                "bonded",
                owner,
            )
            .is_none()
        );
    }
}
