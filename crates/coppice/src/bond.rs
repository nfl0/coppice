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
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use std::time::{Duration, Instant};
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::memo::MemoBytes;

use orchard::circuit::coppice_bond::CoppiceBondCircuit;

pub const BOND_K: u32 = 12;
/// Minimum parameter size for the dedicated parallel-Merkle Coppice bond circuit.
pub const COPPICE_BOND_K: u32 = 11;
/// Exercises the inclusive `value >= B` boundary at exactly 1 ZEC.
pub const FIXTURE_VALUE: u64 = constants::MINIMUM_BOND_VALUE;
pub const FIXTURE_MINIMUM: u64 = constants::MINIMUM_BOND_VALUE;

/// Private wallet material needed to prove a registration bond. Wallets obtain
/// the note and Merkle path from their ordinary Ironwood wallet state.
pub struct RegistrationBondWitness {
    pub note: Note,
    pub full_viewing_key: FullViewingKey,
    pub spend_authorizing_key: SpendAuthorizingKey,
    pub merkle_path: MerklePath,
}

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
        domain_field(constants::NETWORK_ID).expect("short network domain"),
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
pub fn context_binding(name: &str, address: &[u8]) -> pallas::Base {
    let mut preimage = constants::BOND_REGISTRATION_DOMAIN.to_vec();
    preimage.extend_from_slice(&crate::owner::name_id(name));
    preimage.extend_from_slice(&(address.len() as u32).to_be_bytes());
    preimage.extend_from_slice(address);
    binding_32(
        constants::BOND_CONTEXT_DOMAIN,
        Sha256::digest(preimage).into(),
    )
}
pub fn owner_binding(owner_pk: [u8; 32]) -> pallas::Base {
    binding_32(constants::BOND_OWNER_DOMAIN, owner_pk)
}

fn circuit_for_witness(
    witness: RegistrationBondWitness,
    minimum: u64,
    name: &str,
    owner_pk: [u8; 32],
    address: &[u8],
) -> Option<(BondCircuit, Vec<pallas::Base>, [u8; 32])> {
    let RegistrationBondWitness {
        note,
        full_viewing_key,
        spend_authorizing_key,
        merkle_path,
    } = witness;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let anchor = merkle_path.root(cmx);
    let nf = note.nullifier(&full_viewing_key);
    let rho = Rho::from_nf_old(nf);
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([55; 32], &rho))?;
    let output = Option::<Note>::from(Note::from_parts(
        note.recipient(),
        NoteValue::ZERO,
        rho,
        rseed,
        NoteVersion::V3,
    ))?;
    let spend = SpendInfo::new(full_viewing_key, note, merkle_path)?;
    let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(
        pallas::Scalar::from(3).to_repr(),
    ))?;
    let protocol = protocol_binding();
    let context = context_binding(name, address);
    let owner = owner_binding(owner_pk);
    let circuit = BondCircuit::from_action_context(
        spend,
        output,
        pallas::Scalar::from(5),
        rcv,
        spend_authorizing_key,
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
    Some((
        circuit,
        vec![
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
        ],
        nf_bytes,
    ))
}

fn fixture(
    value: u64,
    minimum: u64,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    name: &str,
    note_seed: &[u8],
    owner_pk: [u8; 32],
    address: &[u8],
) -> Option<(BondCircuit, Vec<pallas::Base>, [u8; 32])> {
    let witness = fixture_witness(value, corrupt_path, ask_override, note_seed, 0)?;
    circuit_for_witness(witness, minimum, name, owner_pk, address)
}

fn fixture_witness(
    value: u64,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    note_seed: &[u8],
    position: u32,
) -> Option<RegistrationBondWitness> {
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
    let mut fixture_seed = Sha256::new();
    fixture_seed.update(b"CoppiceBondFixtureV1");
    fixture_seed.update(note_seed);
    let mut rng = ChaCha20Rng::from_seed(fixture_seed.finalize().into());
    let (bundle, meta) = builder.build::<i64>(&mut rng).ok()??;
    let action = bundle.actions().get(meta.output_action_index(0)?)?;
    let (note, _, _) =
        try_note_decryption(&IronwoodDomain::for_action(action), &ivk.prepare(), action)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    for _ in 0..position {
        tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Ephemeral)
            .ok()?;
    }
    tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Marked)
        .ok()?;
    tree.checkpoint(1).ok()?;
    let mut path: MerklePath = tree
        .witness_at_checkpoint_depth(u64::from(position).into(), 0)
        .ok()??
        .into();
    if corrupt_path {
        let mut auth = path.auth_path();
        auth[0] = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
            &pallas::Base::from(9).to_repr(),
        ))?;
        path = MerklePath::from_parts(path.position(), auth);
    }
    let actual_ask = ask_override.unwrap_or(ask);
    Some(RegistrationBondWitness {
        note,
        full_viewing_key: fvk,
        spend_authorizing_key: actual_ask,
        merkle_path: path,
    })
}

fn minimal_fixture(
    value: u64,
    minimum: u64,
    position: u32,
    position_floor: u32,
    corrupt_path: bool,
    ask_override: Option<SpendAuthorizingKey>,
    name: &str,
    note_seed: &[u8],
    owner_pk: [u8; 32],
    address: &[u8],
) -> Option<(CoppiceBondCircuit, Vec<pallas::Base>, [u8; 32])> {
    let RegistrationBondWitness {
        note,
        full_viewing_key,
        spend_authorizing_key,
        merkle_path,
    } = fixture_witness(value, corrupt_path, ask_override, note_seed, position)?;
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
    let anchor = merkle_path.root(cmx);
    let nf = note.nullifier(&full_viewing_key);
    let spend = SpendInfo::new(full_viewing_key, note, merkle_path)?;
    let protocol = protocol_binding();
    let context = context_binding(name, address);
    let owner = owner_binding(owner_pk);
    let circuit = CoppiceBondCircuit::from_spend(
        spend,
        spend_authorizing_key,
        minimum,
        protocol,
        context,
        owner,
        position_floor,
        crate::spent::bond_tag_domain_field(),
    )?;
    let nf_bytes = nf.to_bytes();
    let tag_bytes = spent_tag(&nf_bytes).ok()?;
    let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(tag_bytes))?;
    let anchor_field = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor.to_bytes()))?;
    Some((
        circuit,
        vec![
            anchor_field,
            pallas::Base::from(minimum),
            pallas::Base::from(u64::from(position_floor)),
            protocol,
            context,
            owner,
            tag,
        ],
        nf_bytes,
    ))
}

#[derive(Serialize)]
struct PublicInputVector {
    name: &'static str,
    value: String,
}

#[derive(Serialize)]
struct FailedPublicInputMutation {
    index: usize,
    name: &'static str,
    mutated_value: String,
    accepted: bool,
}

#[derive(Serialize)]
struct BondProofVector {
    source_git_commit: String,
    halo2_proofs: &'static str,
    params: &'static str,
    commitment_scheme: &'static str,
    transcript: &'static str,
    proof_rng: &'static str,
    public_inputs: Vec<PublicInputVector>,
    verifier_artifact_format: &'static str,
    verifier_artifact: String,
    #[serde(rename = "BOND_VK_ID")]
    bond_vk_id: String,
    accepted_proof: String,
    proof_length: usize,
    accepted: bool,
    failed_public_input_mutations: Vec<FailedPublicInputMutation>,
    floor_equality_pass: bool,
    floor_minus_one_fail: bool,
}

#[derive(Serialize)]
struct OwnerKeyVector {
    source: &'static str,
    pallas_scalar: String,
    redpallas_spendauth_verification_key: String,
}

#[derive(Serialize)]
struct BondTagVector {
    version: &'static str,
    canonical_nullifier: String,
    poseidon_bond_tag: String,
}

/// Generates the dedicated bond proof fixture and the two native vectors.
///
/// `source_git_commit` is explicit so the generated artifact can identify the
/// source commit without creating a commit-hash cycle when the vectors themselves
/// are committed afterward.
pub fn generate_coppice_bond_vectors(
    source_git_commit: &str,
    canonical_nullifier: [u8; 32],
) -> Result<(String, String, String), String> {
    const PROOF_RNG_SEED: [u8; 32] = [42; 32];
    const FIXTURE_POSITION: u32 = 1;
    const PUBLIC_INPUT_NAMES: [&str; 7] = [
        "anchor",
        "minimum_value",
        "position_floor",
        "protocol_binding",
        "context_binding",
        "owner_binding",
        "bond_tag",
    ];

    let owner = crate::owner::owner_key_bytes(
        &(&crate::owner::OwnerSigningKey::try_from([1; 32]).map_err(|_| "owner key")?).into(),
    );
    let (circuit, instance, _) = minimal_fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        FIXTURE_POSITION,
        FIXTURE_POSITION,
        false,
        None,
        "bonded",
        b"minimal-bond",
        owner,
        b"UA_BOND",
    )
    .ok_or("bond fixture")?;
    let params = Params::<vesta::Affine>::new(COPPICE_BOND_K);
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|e| format!("pk: {e:?}"))?;
    let proof = prove_with_rng(
        &params,
        &pk,
        circuit,
        &instance,
        ChaCha20Rng::from_seed(PROOF_RNG_SEED),
    )
    .map_err(|e| format!("proof: {e:?}"))?;
    let accepted = verify(&params, pk.get_vk(), &proof, &instance);
    if !accepted {
        return Err("generated proof rejected".into());
    }

    let failed_public_input_mutations = PUBLIC_INPUT_NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let mut mutated = instance.clone();
            mutated[index] += pallas::Base::one();
            FailedPublicInputMutation {
                index,
                name,
                mutated_value: hex::encode(mutated[index].to_repr()),
                accepted: verify(&params, pk.get_vk(), &proof, &mutated),
            }
        })
        .collect::<Vec<_>>();
    if failed_public_input_mutations
        .iter()
        .any(|mutation| mutation.accepted)
    {
        return Err("public input mutation accepted".into());
    }

    let failing_floor = FIXTURE_POSITION + 1;
    let (below_floor, below_floor_instance, _) = minimal_fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        FIXTURE_POSITION,
        failing_floor,
        false,
        None,
        "bonded",
        b"minimal-bond",
        owner,
        b"UA_BOND",
    )
    .ok_or("below-floor fixture")?;
    let below_floor_proof = prove_with_rng(
        &params,
        &pk,
        below_floor,
        &below_floor_instance,
        ChaCha20Rng::from_seed(PROOF_RNG_SEED),
    )
    .map_err(|e| format!("below-floor proof: {e:?}"))?;
    let floor_minus_one_fail = !verify(
        &params,
        pk.get_vk(),
        &below_floor_proof,
        &below_floor_instance,
    );
    if !floor_minus_one_fail {
        return Err("position below floor accepted".into());
    }

    let verifier_artifact = format!("{:?}", pk.get_vk().pinned()).into_bytes();
    let bond_vk_id = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"CoppiceBondV1")
        .hash(&verifier_artifact);
    let bond = BondProofVector {
        source_git_commit: source_git_commit.to_owned(),
        halo2_proofs: "0.3.2",
        params: "Params::<vesta::Affine>::new(11)",
        commitment_scheme: "Halo2 IPA/Vesta",
        transcript: "Blake2bWrite/Blake2bRead with Challenge255",
        proof_rng: "ChaCha20Rng::from_seed([42; 32])",
        public_inputs: PUBLIC_INPUT_NAMES
            .iter()
            .zip(&instance)
            .map(|(name, value)| PublicInputVector {
                name,
                value: hex::encode(value.to_repr()),
            })
            .collect(),
        verifier_artifact_format: "UTF-8 Debug bytes of halo2_proofs::plonk::VerifyingKey::pinned()",
        verifier_artifact: hex::encode(verifier_artifact),
        bond_vk_id: hex::encode(bond_vk_id.as_bytes()),
        accepted_proof: hex::encode(&proof),
        proof_length: proof.len(),
        accepted,
        failed_public_input_mutations,
        floor_equality_pass: accepted,
        floor_minus_one_fail,
    };
    if bond.proof_length != 4_960 {
        return Err(format!("unexpected proof length: {}", bond.proof_length));
    }

    let owner_key =
        crate::owner::OwnerSigningKey::try_from([1; 32]).map_err(|_| "native owner key")?;
    let owner_vector = OwnerKeyVector {
        source: "reference-v0 owner partial vector",
        pallas_scalar: hex::encode(<[u8; 32]>::from(&owner_key)),
        redpallas_spendauth_verification_key: hex::encode(crate::owner::owner_key_bytes(
            &(&owner_key).into(),
        )),
    };
    let bond_tag = spent_tag(&canonical_nullifier).map_err(|_| "canonical nullifier")?;
    let tag_vector = BondTagVector {
        version: "Coppice bond tag v1 Poseidon P128Pow5T3 ConstantLength<2>",
        canonical_nullifier: hex::encode(canonical_nullifier),
        poseidon_bond_tag: hex::encode(bond_tag),
    };

    fn json<T: Serialize>(value: &T) -> Result<String, String> {
        serde_json::to_string_pretty(value)
            .map(|json| json + "\n")
            .map_err(|e| e.to_string())
    }
    Ok((json(&bond)?, json(&owner_vector)?, json(&tag_vector)?))
}

fn prove<C: halo2_proofs::plonk::Circuit<pallas::Base>>(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    circuit: C,
    instance: &[pallas::Base],
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    prove_with_rng(params, pk, circuit, instance, OsRng)
}

fn prove_with_rng<C: halo2_proofs::plonk::Circuit<pallas::Base>, R: RngCore + CryptoRng>(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    circuit: C,
    instance: &[pallas::Base],
    rng: R,
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    let columns: [&[pallas::Base]; 1] = [instance];
    let instances: [&[&[pallas::Base]]; 1] = [&columns];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
    create_proof(params, pk, &[circuit], &instances, rng, &mut transcript)?;
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
    address: &[u8],
) -> Result<BondMeasurement, String> {
    run_bond_poc_for_registration_with_seed(name, owner_pk, address, name.as_bytes())
}

fn run_bond_poc_for_registration_with_seed(
    name: &str,
    owner_pk: [u8; 32],
    address: &[u8],
    note_seed: &[u8],
) -> Result<BondMeasurement, String> {
    let (circuit, instance, _) = fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        false,
        None,
        name,
        note_seed,
        owner_pk,
        address,
    )
    .ok_or("fixture")?;
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

/// Proves a registration bond from a real wallet-owned Ironwood note.
pub fn prove_registration_bond(
    witness: RegistrationBondWitness,
    name: &str,
    owner_pk: [u8; 32],
    address: &[u8],
) -> Result<BondMeasurement, String> {
    let (circuit, instance, _) =
        circuit_for_witness(witness, FIXTURE_MINIMUM, name, owner_pk, address)
            .ok_or("bond witness")?;
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
    run_bond_poc_for_registration(
        "bonded",
        crate::owner::owner_key_bytes(&(&key).into()),
        b"UA_BOND",
    )
}

pub fn verify_registration_bond(
    name: &str,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    anchor: [u8; 32],
    proof: &[u8],
    address: &[u8],
) -> bool {
    let Some(tag) = Option::<pallas::Base>::from(pallas::Base::from_repr(bond_tag)) else {
        return false;
    };
    let Some(anchor) = Option::<pallas::Base>::from(pallas::Base::from_repr(anchor)) else {
        return false;
    };
    let Some((key_circuit, _, _)) = fixture(
        FIXTURE_VALUE,
        FIXTURE_MINIMUM,
        false,
        None,
        name,
        name.as_bytes(),
        owner_pk,
        address,
    ) else {
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
        context_binding(name, address),
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
pub(crate) fn test_registration_bond(name: &str, address: &[u8]) -> &'static BondMeasurement {
    use std::sync::OnceLock;
    static ALICE_A: OnceLock<BondMeasurement> = OnceLock::new();
    static ALICE_NEW: OnceLock<BondMeasurement> = OnceLock::new();
    static BOB_B: OnceLock<BondMeasurement> = OnceLock::new();
    static BOB_C: OnceLock<BondMeasurement> = OnceLock::new();
    let owner = crate::owner::owner_key_bytes(
        &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
    );
    match (name, address) {
        ("alice", b"UA_A") => {
            ALICE_A.get_or_init(|| run_bond_poc_for_registration(name, owner, address).unwrap())
        }
        ("alice", b"UA_NEW") => {
            ALICE_NEW.get_or_init(|| run_bond_poc_for_registration(name, owner, address).unwrap())
        }
        ("bob", b"UA_B") => {
            BOB_B.get_or_init(|| run_bond_poc_for_registration(name, owner, address).unwrap())
        }
        ("bob", b"UA_C") => {
            BOB_C.get_or_init(|| run_bond_poc_for_registration(name, owner, address).unwrap())
        }
        _ => panic!("unsupported shared test bond"),
    }
}

#[cfg(test)]
pub(crate) fn test_registration_bond_with_owner_and_seed(
    name: &str,
    owner_pk: [u8; 32],
    address: &[u8],
    note_seed: &[u8],
) -> BondMeasurement {
    run_bond_poc_for_registration_with_seed(name, owner_pk, address, note_seed).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::plonk::ConstraintSystem;
    #[test]
    fn real_bond_circuit_positive_and_negative() {
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        let (good, instance, _) = fixture(
            FIXTURE_VALUE,
            FIXTURE_MINIMUM,
            false,
            None,
            "bonded",
            b"bonded",
            owner,
            b"UA_BOND",
        )
        .unwrap();
        let params = Params::<vesta::Affine>::new(BOND_K);
        let vk = keygen_vk(&params, &good).unwrap();
        let pk = keygen_pk(&params, vk, &good).unwrap();
        let proof = prove(&params, &pk, good.clone(), &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &proof, &instance));
        let measurement = run_bond_poc_for_registration("bonded", owner, b"UA_BOND").unwrap();
        assert!(verify_registration_bond(
            "bonded",
            owner,
            measurement.bond_tag,
            measurement.anchor,
            &measurement.proof,
            b"UA_BOND",
        ));
        assert!(!verify_registration_bond(
            "bonded",
            owner,
            measurement.bond_tag,
            measurement.anchor,
            &measurement.proof,
            b"UA_CHANGED",
        ));
        for i in [0usize, 1, 2, 3, 4, 5] {
            let mut bad = instance.clone();
            bad[i] += pallas::Base::one();
            assert!(!verify(&params, pk.get_vk(), &proof, &bad));
        }
        let (low, low_instance, _) = fixture(
            FIXTURE_MINIMUM - 1,
            FIXTURE_MINIMUM,
            false,
            None,
            "bonded",
            b"bonded",
            owner,
            b"UA_BOND",
        )
        .unwrap();
        let low_proof = prove(&params, &pk, low, &low_instance).unwrap();
        assert!(!verify(&params, pk.get_vk(), &low_proof, &low_instance));
        let (wrong_path, mut wrong_instance, _) = fixture(
            FIXTURE_VALUE,
            FIXTURE_MINIMUM,
            true,
            None,
            "bonded",
            b"bonded",
            owner,
            b"UA_BOND",
        )
        .unwrap();
        let wrong_proof = prove(&params, &pk, wrong_path, &wrong_instance).unwrap();
        // A path authenticates to the root it computes. Verification must bind
        // that proof to the independently accepted root, not the attacker's.
        wrong_instance[0] = instance[0];
        assert!(!verify(&params, pk.get_vk(), &wrong_proof, &wrong_instance));
        let wrong_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap();
        assert!(
            fixture(
                FIXTURE_VALUE,
                FIXTURE_MINIMUM,
                false,
                Some(SpendAuthorizingKey::from(&wrong_sk)),
                "bonded",
                b"bonded",
                owner,
                b"UA_BOND",
            )
            .is_none()
        );
    }

    const MINIMAL_TEST_POSITION: u32 = 1;

    fn minimal_good(
        value: u64,
        floor: u32,
        corrupt_path: bool,
        ask_override: Option<SpendAuthorizingKey>,
    ) -> Option<(CoppiceBondCircuit, Vec<pallas::Base>, [u8; 32])> {
        let owner = crate::owner::owner_key_bytes(
            &(&crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap()).into(),
        );
        minimal_fixture(
            value,
            FIXTURE_MINIMUM,
            MINIMAL_TEST_POSITION,
            floor,
            corrupt_path,
            ask_override,
            "bonded",
            b"minimal-bond",
            owner,
            b"UA_BOND",
        )
    }

    fn circuit_stats<C: halo2_proofs::plonk::Circuit<pallas::Base>>() -> [usize; 7] {
        let mut cs = ConstraintSystem::<pallas::Base>::default();
        C::configure(&mut cs);
        let pinned = format!("{:?}", cs.pinned());
        let count = |field: &str| {
            pinned
                .split_once(field)
                .and_then(|(_, rest)| rest.split_once(','))
                .and_then(|(value, _)| value.trim().parse::<usize>().ok())
                .unwrap()
        };
        let permutation = pinned
            .split_once("permutation: Argument { columns: [")
            .and_then(|(_, rest)| rest.split_once("] }, lookups:"))
            .unwrap()
            .0;
        let permutation_columns = permutation.matches("Column {").count();
        let lookups = pinned
            .split_once("lookups: [")
            .and_then(|(_, rest)| rest.split_once("], constants:"))
            .unwrap()
            .0
            .matches("Argument { input_expressions")
            .count();
        let degree = cs.degree();
        [
            count("num_advice_columns:"),
            count("num_fixed_columns:"),
            count("num_instance_columns:"),
            lookups,
            permutation_columns,
            permutation_columns.div_ceil(degree - 2),
            degree,
        ]
    }

    #[test]
    fn minimal_bond_relation_positive_and_negative() {
        let (good, instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, false, None).unwrap();
        let params = Params::<vesta::Affine>::new(11);
        let vk = keygen_vk(&params, &good).unwrap();
        let pk = keygen_pk(&params, vk, &good).unwrap();
        let proof = prove(&params, &pk, good, &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &proof, &instance));

        let (wrong_path, mut wrong_path_instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, true, None).unwrap();
        let wrong_path_proof = prove(&params, &pk, wrong_path, &wrong_path_instance).unwrap();
        wrong_path_instance[0] = instance[0];
        assert!(!verify(
            &params,
            pk.get_vk(),
            &wrong_path_proof,
            &wrong_path_instance
        ));

        let wrong_sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap();
        assert!(
            minimal_good(
                FIXTURE_VALUE,
                MINIMAL_TEST_POSITION,
                false,
                Some(SpendAuthorizingKey::from(&wrong_sk)),
            )
            .is_none()
        );

        let (low, low_instance, _) =
            minimal_good(FIXTURE_MINIMUM - 1, MINIMAL_TEST_POSITION, false, None).unwrap();
        let low_proof = prove(&params, &pk, low, &low_instance).unwrap();
        assert!(!verify(&params, pk.get_vk(), &low_proof, &low_instance));

        for input in [3usize, 4, 5, 6] {
            let mut wrong = instance.clone();
            wrong[input] += pallas::Base::one();
            assert!(!verify(&params, pk.get_vk(), &proof, &wrong));
        }

        // Inclusive boundary: position == floor.
        assert_eq!(
            instance[2],
            pallas::Base::from(u64::from(MINIMAL_TEST_POSITION))
        );

        // position == floor - 1 must fail.
        let failing_floor = MINIMAL_TEST_POSITION + 1;
        let (below_floor, below_floor_instance, _) =
            minimal_good(FIXTURE_VALUE, failing_floor, false, None).unwrap();
        let below_floor_proof = prove(&params, &pk, below_floor, &below_floor_instance).unwrap();
        assert!(!verify(
            &params,
            pk.get_vk(),
            &below_floor_proof,
            &below_floor_instance
        ));
    }

    #[test]
    fn dedicated_bond_vectors_regenerate_byte_for_byte() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bond_path = root.join("test-vectors/coppice_bond_v1.json");
        let owner_path = root.join("test-vectors/owner_keys.json");
        let tag_path = root.join("test-vectors/bond_tags.json");
        let expected_bond = std::fs::read_to_string(bond_path).expect("bond vector");
        let expected_owner = std::fs::read_to_string(owner_path).expect("owner vector");
        let expected_tag = std::fs::read_to_string(tag_path).expect("tag vector");
        let bond: serde_json::Value = serde_json::from_str(&expected_bond).unwrap();
        let tag: serde_json::Value = serde_json::from_str(&expected_tag).unwrap();
        let source = bond["source_git_commit"].as_str().unwrap();
        let canonical_nullifier: [u8; 32] =
            hex::decode(tag["canonical_nullifier"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let (bond, owner, tag) =
            generate_coppice_bond_vectors(source, canonical_nullifier).unwrap();
        assert_eq!(bond, expected_bond);
        assert_eq!(owner, expected_owner);
        assert_eq!(tag, expected_tag);
    }

    #[test]
    #[ignore = "manual optimized benchmark"]
    fn minimal_bond_benchmark() {
        const RUNS: usize = 10;
        let (circuit, instance, _) =
            minimal_good(FIXTURE_VALUE, MINIMAL_TEST_POSITION, false, None).unwrap();
        for k in 9..=11 {
            let params = Params::<vesta::Affine>::new(k);
            let result = keygen_vk(&params, &circuit).and_then(|vk| {
                let pk = keygen_pk(&params, vk, &circuit)?;
                let proof = prove(&params, &pk, circuit.clone(), &instance)?;
                if verify(&params, pk.get_vk(), &proof, &instance) {
                    Ok(())
                } else {
                    Err(halo2_proofs::plonk::Error::ConstraintSystemFailure)
                }
            });
            println!("minimum-k-probe k={k} prove-verify={:?}", result.is_ok());
        }

        let k = 11;
        let params = Params::<vesta::Affine>::new(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();
        let warmup = prove(&params, &pk, circuit.clone(), &instance).unwrap();
        assert!(verify(&params, pk.get_vk(), &warmup, &instance));

        let mut proof = Vec::new();
        let mut proving = Duration::ZERO;
        let mut verifying = Duration::ZERO;
        for _ in 0..RUNS {
            let start = Instant::now();
            proof = prove(&params, &pk, circuit.clone(), &instance).unwrap();
            proving += start.elapsed();
            let start = Instant::now();
            assert!(verify(&params, pk.get_vk(), &proof, &instance));
            verifying += start.elapsed();
        }
        let [
            advice,
            fixed,
            instance_columns,
            lookups,
            permutation_columns,
            permutation_sets,
            degree,
        ] = circuit_stats::<CoppiceBondCircuit>();
        println!(
            "columns advice={} fixed={} instance={} lookups={} permutation-columns={} permutation-product-sets={} degree={}",
            advice, fixed, instance_columns, lookups, permutation_columns, permutation_sets, degree,
        );
        let baseline = circuit_stats::<BondCircuit>();
        println!("baseline-constraint-system={baseline:?}");
        println!("proof-bytes={}", proof.len());
        println!("prove-mean-us={}", proving.as_micros() / RUNS as u128);
        println!("verify-mean-us={}", verifying.as_micros() / RUNS as u128);
        println!("peak-rss-kib={:?}", peak_memory_kib());
    }
}
