use coppice::{
    bond, carrier,
    envelope::Operation,
    owner::{OwnerSigningKey, owner_key_bytes, sign_operation},
    replay::{ChainContext, ReplayState, process_serialized_transaction},
    state::{NameRecord, Status},
};
use sha2::{Digest, Sha256};

fn owner() -> ([u8; 32], OwnerSigningKey) {
    let key = OwnerSigningKey::try_from([1; 32]).expect("fixed POC key");
    (owner_key_bytes(&(&key).into()), key)
}

fn serialized(tx: &zcash_primitives::transaction::Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("write transaction");
    bytes
}

fn carrier_demo() {
    let (owner_pk, _) = owner();
    let operation = Operation::Reveal {
        name: "frames".into(),
        owner_pk,
        bond_tag: [1; 32],
        bond_anchor: [0; 32],
        bond_proof: Vec::new(),
        address: vec![0x55; 900],
        secret: [9; 32],
    };
    let built = carrier::build_coppice_transaction(&operation).expect("carrier");
    let raw = serialized(&built.tx);
    let parsed = zcash_primitives::transaction::Transaction::read(
        raw.as_slice(),
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .expect("parse transaction");
    let decoded = carrier::decode_bulletin(&parsed).expect("decrypt bulletin");
    println!(
        "txid: {}\nactions: {}\nbytes: {}\nframes: {}\nround trip: {}",
        built.txid,
        parsed.ironwood_bundle().map_or(0, |b| b.actions().len()),
        raw.len(),
        built.frame_count,
        decoded == operation,
    );
}

fn replay_demo() {
    let (owner_pk, key) = owner();
    let bond = bond::run_bond_poc_for_registration("alice", owner_pk, b"UA_A").expect("bond proof");
    let secret = [7; 32];
    let commitment = coppice::state::registration_commitment(
        "alice",
        owner_pk,
        bond.bond_tag,
        bond.anchor,
        b"UA_A",
        secret,
    );
    let reveal = Operation::Reveal {
        name: "alice".into(),
        owner_pk,
        bond_tag: bond.bond_tag,
        bond_anchor: bond.anchor,
        bond_proof: bond.proof,
        address: b"UA_A".to_vec(),
        secret,
    };
    let initial = NameRecord {
        owner_pk,
        bond_tag: bond.bond_tag,
        sequence: 0,
        address: b"UA_A".to_vec(),
        status: Status::Active,
    };
    let mut update = Operation::Update {
        name: "alice".into(),
        sequence: 1,
        address: b"UA_B".to_vec(),
        signature: Vec::new(),
    };
    let update_signature = sign_operation(&key, &update, &initial).expect("sign update");
    if let Operation::Update { signature, .. } = &mut update {
        *signature = update_signature;
    }
    let updated = NameRecord {
        address: b"UA_B".to_vec(),
        sequence: 1,
        ..initial
    };
    let mut release = Operation::Release {
        name: "alice".into(),
        sequence: 2,
        signature: Vec::new(),
    };
    let release_signature = sign_operation(&key, &release, &updated).expect("sign release");
    if let Operation::Release { signature, .. } = &mut release {
        *signature = release_signature;
    }
    let mut state = ReplayState::new();
    state.accept_bond_anchor(bond.anchor);
    for (index, operation) in [Operation::Commit { commitment }, reveal, update, release]
        .iter()
        .enumerate()
    {
        let built = carrier::build_coppice_transaction(operation).expect("carrier");
        let result = process_serialized_transaction(
            &mut state,
            100 + index as u32,
            0,
            &serialized(&built.tx),
        )
        .expect("replay");
        println!("height={} outcome={:?}", 100 + index, result.outcome);
    }
    let context = ChainContext {
        height: 103,
        fixture_block_id: Sha256::digest(b"CoppiceStandaloneFixtureV0").into(),
    };
    println!(
        "NameTreeRoot {}\nSpentTagTreeRoot {}\nCoppiceStateRoot {}\nalice {:?}",
        hex::encode(state.names.state_root()),
        hex::encode(state.spent.root()),
        hex::encode(state.state_commitment(&context)),
        state.names.names["alice"].status,
    );
}

fn bond_demo() {
    let measurement = bond::run_bond_poc().expect("bond proof");
    println!(
        "proof bytes: {}\nprove: {:?}\nverify: {:?}\nbond tag: {}\nanchor: {}",
        measurement.proof.len(),
        measurement.proving_time,
        measurement.verification_time,
        hex::encode(measurement.bond_tag),
        hex::encode(measurement.anchor),
    );
}

fn vectors(write: bool) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/reference-v0.json");
    let existing = std::fs::read_to_string(&path).expect("read vectors");
    let value: serde_json::Value = serde_json::from_str(&existing).expect("parse vectors");
    let nullifier: [u8; 32] = hex::decode(
        value["ironwood_nullifier"]
            .as_str()
            .expect("nullifier vector"),
    )
    .expect("hex nullifier")
    .try_into()
    .expect("32-byte nullifier");
    let generated = coppice::vectors::generate(nullifier);
    if write {
        std::fs::write(&path, generated).expect("write vectors");
        println!("{}", path.display());
    } else {
        print!("{generated}");
    }
}

fn write_bond_vectors(source_git_commit: &str) {
    assert!(
        source_git_commit.len() == 40
            && source_git_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "source commit must be a 40-character hexadecimal SHA"
    );
    let head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("run git rev-parse");
    assert!(head.status.success(), "git rev-parse HEAD failed");
    assert_eq!(
        source_git_commit,
        String::from_utf8(head.stdout)
            .expect("ASCII git SHA")
            .trim(),
        "source commit must equal the checked-out HEAD"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let reference = std::fs::read_to_string(root.join("test-vectors/reference-v0.json"))
        .expect("read reference vectors");
    let reference: serde_json::Value =
        serde_json::from_str(&reference).expect("parse reference vectors");
    let canonical_nullifier: [u8; 32] = hex::decode(
        reference["ironwood_nullifier"]
            .as_str()
            .expect("canonical nullifier"),
    )
    .expect("hex nullifier")
    .try_into()
    .expect("32-byte nullifier");
    let (bond, owner_keys, bond_tags) =
        bond::generate_coppice_bond_vectors(source_git_commit, canonical_nullifier)
            .expect("generate bond vectors");
    let vectors = root.join("test-vectors");
    for (name, contents) in [
        ("coppice_bond_v1.json", bond),
        ("owner_keys.json", owner_keys),
        ("bond_tags.json", bond_tags),
    ] {
        let path = vectors.join(name);
        std::fs::write(&path, contents).expect("write vector");
        println!("{}", path.display());
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("carrier-demo") => carrier_demo(),
        Some("replay-demo") => replay_demo(),
        Some("bond-demo") => bond_demo(),
        Some("print-test-vectors") => vectors(false),
        Some("write-test-vectors") => vectors(true),
        Some("write-bond-vectors") => write_bond_vectors(
            args.get(2)
                .expect("usage: write-bond-vectors <source-git-commit>"),
        ),
        _ => eprintln!(
            "usage: carrier-demo | replay-demo | bond-demo | print-test-vectors | write-bond-vectors <source-git-commit>"
        ),
    }
}
