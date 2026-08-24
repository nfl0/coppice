use coppice::{
    config::{DeploymentParameters, Rendezvous},
    envelope::Operation,
    names_application::{encode_names_v1_envelope, names_v1_core_runtime_parameters},
    names_runtime::{NamesRuntime, NamesTransactionOutcome},
};
use coppice_core::{
    application::{
        ApplicationDescriptor, ApplicationEnvelopeV1, ApplicationKey, ApplicationTip,
        CoppiceApplication, derive_application_id,
    },
    replay::{
        CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplay,
        CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::{ApplicationMessageStatus, CoreRuntime, RuntimeBlockContext},
    transport,
};
use orchard::{
    Proof,
    builder::{Builder, BundleType},
    bundle::{Authorized as OrchardAuthorized, BundleVersion},
    primitives::redpallas::{Binding, SigningKey, SpendAuth},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType},
    value::ZatBalance,
};

const ACTIVATION_HEIGHT: u32 = 100;
const ACTIVATION_HASH: [u8; 32] = [9; 32];

fn deployment() -> DeploymentParameters {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
    let input = &fixture["input"];
    DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: ACTIVATION_HEIGHT,
        minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    }
}

fn checkpoint() -> CoreReplayActivationCheckpoint {
    CoreReplayActivationCheckpoint {
        height: ACTIVATION_HEIGHT - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    }
}

fn candidate_transaction(
    deployment: &DeploymentParameters,
    runtime_id: [u8; 32],
    envelope: &[u8],
    tx_index: u32,
    seed: u8,
) -> CoreCanonicalTransactionInput {
    let frames = transport::encode_frames(runtime_id, envelope).unwrap();
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    let receiver = coppice::carrier::bulletin_address(deployment.rendezvous).unwrap();
    for frame in frames {
        builder
            .add_output(None, receiver, NoteValue::ZERO, frame)
            .unwrap();
    }
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let count = unauthorized.actions().len();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(count)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceRuntimeTestSpend"),
        |rng, _| {
            OrchardAuthorized::from_parts(
                proof,
                binding_key.sign(&mut *rng, b"CoppiceRuntimeTestBinding"),
            )
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(ACTIVATION_HEIGHT),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let bundle = transaction.ironwood_bundle().unwrap();
    let nullifiers = bundle
        .actions()
        .iter()
        .map(|action| action.nullifier().to_bytes())
        .collect();
    let commitments = bundle
        .actions()
        .iter()
        .map(|action| action.cmx().to_bytes())
        .collect();
    let mut bytes = Vec::new();
    transaction.write(&mut bytes).unwrap();
    CoreCanonicalTransactionInput {
        tx_index,
        txid: transaction.txid().into(),
        ironwood_nullifiers: nullifiers,
        ironwood_commitments: commitments,
        full_tx_required: true,
        candidate_full_tx: Some(bytes),
    }
}

fn block(
    tip: coppice_core::replay::CoreReplayTip,
    height: u32,
    transactions: Vec<CoreCanonicalTransactionInput>,
) -> CoreCanonicalBlockInput {
    CoreCanonicalBlockInput {
        height,
        block_hash: [height as u8; 32],
        prev_block_hash: tip.block_hash,
        branch_id: BranchId::Nu6_3,
        transactions,
    }
}

#[derive(Clone)]
struct TinyApplication {
    descriptor: ApplicationDescriptor,
    tip: ApplicationTip,
    value: u8,
    history: Vec<(ApplicationTip, u8)>,
}

impl CoppiceApplication for TinyApplication {
    type BlockOutput = u8;
    type ApplyError = ();
    type RewindError = ();

    fn descriptor(&self) -> ApplicationDescriptor {
        self.descriptor
    }

    fn tip(&self) -> ApplicationTip {
        self.tip
    }

    fn state_root(&self) -> [u8; 32] {
        [self.value; 32]
    }

    fn apply_block(&mut self, block: &RuntimeBlockContext) -> Result<u8, ()> {
        let core = block.core();
        if self.tip.height.checked_add(1) != Some(core.height())
            || self.tip.block_hash != core.prev_block_hash()
        {
            return Err(());
        }
        self.history.push((self.tip, self.value));
        for transaction in block.transactions() {
            if let ApplicationMessageStatus::Message(message) = transaction.message()
                && message.key() == self.descriptor.key
            {
                let [increment] = message.payload() else {
                    return Err(());
                };
                self.value = self.value.checked_add(*increment).ok_or(())?;
            }
        }
        self.tip = ApplicationTip {
            height: core.height(),
            block_hash: core.block_hash(),
        };
        Ok(self.value)
    }

    fn rewind_to(&mut self, height: u32) -> Result<(), ()> {
        while self.tip.height > height {
            let (tip, value) = self.history.pop().ok_or(())?;
            self.tip = tip;
            self.value = value;
        }
        Ok(())
    }
}

#[test]
fn core_routes_a_non_names_application_without_understanding_its_state() {
    let deployment = deployment();
    let parameters = names_v1_core_runtime_parameters(&deployment).unwrap();
    let replay = CoreReplay::new(
        CoreReplayConfiguration::new(ACTIVATION_HEIGHT, 8).unwrap(),
        checkpoint(),
    )
    .unwrap();
    let mut core = CoreRuntime::new(parameters, replay).unwrap();
    let key = ApplicationKey::new(derive_application_id(b"test.only.counter").unwrap(), 1);
    let envelope = ApplicationEnvelopeV1::new(key, vec![7]).unwrap().encode();
    let transaction =
        candidate_transaction(&deployment, core.runtime_id().to_bytes(), &envelope, 0, 3);
    let input = block(core.tip(), ACTIVATION_HEIGHT, vec![transaction]);
    let context = core.apply_block(&input).unwrap();
    assert!(matches!(
        context.transactions()[0].message(),
        ApplicationMessageStatus::Message(message) if message.key() == key
    ));
    let mut application = TinyApplication {
        descriptor: ApplicationDescriptor {
            key,
            activation_height: ACTIVATION_HEIGHT,
        },
        tip: ApplicationTip {
            height: ACTIVATION_HEIGHT - 1,
            block_hash: ACTIVATION_HASH,
        },
        value: 0,
        history: vec![],
    };
    assert_eq!(application.apply_block(&context), Ok(7));
    assert_eq!(application.state_root(), [7; 32]);
    assert_eq!(core.tip().height, application.tip().height);
}

#[test]
fn names_runtime_routes_envelopes_and_restores_split_state_atomically() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    let operation = Operation::Commit {
        commitment: [0x44; 32],
    };
    let envelope = encode_names_v1_envelope(&operation).unwrap();
    let transaction = candidate_transaction(
        &deployment,
        runtime.core().runtime_id().to_bytes(),
        &envelope,
        0,
        5,
    );
    let first = block(runtime.core().tip(), ACTIVATION_HEIGHT, vec![transaction]);
    let applied = runtime.apply_block(&first).unwrap();
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![NamesTransactionOutcome::Applied]
    );
    assert!(runtime.names().state().pending.contains_key(&[0x44; 32]));

    for height in (ACTIVATION_HEIGHT + 1)..=(ACTIVATION_HEIGHT + 4) {
        let input = block(runtime.core().tip(), height, vec![]);
        runtime.apply_block(&input).unwrap();
    }
    let snapshot = runtime.save_snapshot().unwrap();
    let mut restored = NamesRuntime::load_snapshot(deployment.clone(), &snapshot).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(
        restored.core().ironwood_frontier(),
        runtime.core().ironwood_frontier()
    );
    assert_eq!(restored.names().state(), runtime.names().state());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    runtime.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    restored.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(restored.names().state(), runtime.names().state());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    let replacement = block(runtime.core().tip(), ACTIVATION_HEIGHT + 2, vec![]);
    runtime.apply_block(&replacement).unwrap();
    restored.apply_block(&replacement).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    let mut tampered: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    tampered["application_state_root"][0] = serde_json::json!(255);
    assert!(matches!(
        NamesRuntime::load_snapshot(deployment, &serde_json::to_vec(&tampered).unwrap()),
        Err(coppice::names_runtime::NamesRuntimeSnapshotError::TipMismatch)
            | Err(coppice::names_runtime::NamesRuntimeSnapshotError::RootMismatch)
    ));
}
