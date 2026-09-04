//! Explicit opt-in live qualification against a disposable Zakura Regtest.
//!
//! `scripts/rpc-qualification.sh` supplies the endpoint and creates the
//! initial short chain. This test owns no Zakura internals and exercises the
//! same public HTTP adapter used by a server deployment.

use std::{cell::RefCell, rc::Rc};

use coppice_core::{
    identity::{CoreRuntimeParameters, ZcashNetwork},
    replay::{CoreReplay, CoreReplayConfiguration},
    runtime::CoreRuntime,
};
use coppice_librustzcash::{
    CanonicalBlockSource, CanonicalTip, FullTransactionSource, ReconcileKind,
    reconcile_canonical_chain,
};
use coppice_zcash_rpc::{
    HttpTransport, HttpTransportError, RpcAdapterConfig, RpcCanonicalBlockSource, RpcError,
    RpcTransport, ZcashRpcClient, ZcashRpcConfig,
};
use serde_json::{Value, json};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType},
    local_consensus::LocalNetwork,
};

type Source = RpcCanonicalBlockSource<LocalNetwork, HttpTransport>;
type SourceError = RpcError<HttpTransportError>;

fn parameters() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    let two = Some(BlockHeight::from_u32(2));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: two,
        nu6: two,
        nu6_1: two,
        nu6_2: two,
        nu6_3: two,
    }
}

fn runtime_parameters() -> coppice_core::identity::ValidatedCoreRuntimeParameters {
    CoreRuntimeParameters {
        zcash_network_domain: b"coppice-runtime-regtest".to_vec(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: 10,
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
    .unwrap()
}

#[derive(Clone)]
struct SharedSource(Rc<RefCell<Source>>);

impl CanonicalBlockSource for SharedSource {
    type Error = SourceError;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        self.0.borrow_mut().canonical_tip()
    }

    fn compact_block(
        &mut self,
        height: u32,
    ) -> Result<Option<zcash_client_backend::proto::compact_formats::CompactBlock>, Self::Error>
    {
        self.0.borrow_mut().compact_block(height)
    }
}

impl FullTransactionSource for SharedSource {
    type Error = SourceError;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.borrow_mut().full_transaction(txid)
    }
}

fn display_hash(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}

fn raw_rpc(endpoint: &str, id: u64, method: &str, params: Value) -> Value {
    let mut transport = HttpTransport::new(ZcashRpcConfig::new(endpoint)).unwrap();
    let request = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": id, "method": method, "params": params,
    }))
    .unwrap();
    let response: Value = serde_json::from_slice(&transport.send(&request).unwrap()).unwrap();
    assert!(response["error"].is_null(), "{method}: {response}");
    response["result"].clone()
}

fn make_source(endpoint: &str) -> SharedSource {
    let transport = HttpTransport::new(ZcashRpcConfig::new(endpoint)).unwrap();
    SharedSource(Rc::new(RefCell::new(RpcCanonicalBlockSource::new(
        parameters(),
        ZcashRpcClient::new(transport),
        RpcAdapterConfig::new(NetworkType::Regtest, 9),
    ))))
}

fn fresh_runtime(source: &SharedSource) -> CoreRuntime {
    let checkpoint = source.0.borrow_mut().activation_checkpoint(10).unwrap();
    let configuration = CoreReplayConfiguration::new(10, 16).unwrap();
    let replay = CoreReplay::new(configuration, checkpoint).unwrap();
    CoreRuntime::new(runtime_parameters(), replay).unwrap()
}

#[tokio::test]
#[ignore = "requires scripts/rpc-qualification.sh and a disposable Zaino sidecar"]
async fn zakura_rpc_compact_facts_match_zaino() {
    let endpoint = std::env::var("COPPICE_RPC_LIVE_ENDPOINT").unwrap();
    let zaino = std::env::var("COPPICE_ZAINO_GRPC_ENDPOINT").unwrap();
    let mut rpc = make_source(&endpoint);
    let tip = rpc.canonical_tip().unwrap();
    let mut client = zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::connect(zaino)
        .await
        .unwrap();

    for height in 10..=tip.height {
        let from_rpc = rpc.compact_block(height).unwrap().unwrap();
        let from_zaino = client
            .get_block(zcash_client_backend::proto::service::BlockId {
                height: u64::from(height),
                hash: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(from_rpc.height, from_zaino.height, "height {height}");
        assert_eq!(from_rpc.hash, from_zaino.hash, "hash {height}");
        assert_eq!(
            from_rpc.prev_hash, from_zaino.prev_hash,
            "prev hash {height}"
        );
        assert_eq!(
            from_rpc.vtx, from_zaino.vtx,
            "compact transactions {height}"
        );
    }
    println!(
        "RPC/Zaino CompactBlock equality through height {}",
        tip.height
    );
}

#[test]
#[ignore = "requires scripts/rpc-qualification.sh and a disposable Zakura Regtest"]
fn zakura_rpc_checkpoint_reconciliation_restart_and_reorg() {
    let endpoint = std::env::var("COPPICE_RPC_LIVE_ENDPOINT").unwrap();
    let mut source = make_source(&endpoint);
    let mut full_source = source.clone();
    let mut runtime = fresh_runtime(&source);

    let first =
        reconcile_canonical_chain(&parameters(), &mut runtime, &mut source, &mut full_source)
            .unwrap();
    assert_eq!(first.kind, ReconcileKind::Forward);
    assert!(first.blocks_applied >= 3);
    let branch_a_tip = runtime.tip();
    let snapshot = runtime.save_snapshot().unwrap();

    let old_hash = display_hash(branch_a_tip.block_hash);
    raw_rpc(&endpoint, 1, "invalidateblock", json!([old_hash]));
    raw_rpc(&endpoint, 2, "generate", json!([1]));

    let reorg =
        reconcile_canonical_chain(&parameters(), &mut runtime, &mut source, &mut full_source)
            .unwrap();
    assert_eq!(reorg.kind, ReconcileKind::Reorg);
    assert_eq!(reorg.blocks_rewound, 1);
    assert_eq!(reorg.blocks_applied, 1);
    assert_ne!(runtime.tip().block_hash, branch_a_tip.block_hash);

    let configuration = CoreReplayConfiguration::new(10, 16).unwrap();
    let mut restarted =
        CoreRuntime::load_snapshot(runtime_parameters(), configuration, &snapshot).unwrap();
    let restart_outcome =
        reconcile_canonical_chain(&parameters(), &mut restarted, &mut source, &mut full_source)
            .unwrap();
    assert_eq!(restart_outcome.kind, ReconcileKind::Reorg);
    assert_eq!(restarted.tip(), runtime.tip());
    assert_eq!(restarted.ironwood_frontier(), runtime.ironwood_frontier());

    let mut fresh_source = make_source(&endpoint);
    let mut fresh_full_source = fresh_source.clone();
    let mut fresh = fresh_runtime(&fresh_source);
    let fresh_outcome = reconcile_canonical_chain(
        &parameters(),
        &mut fresh,
        &mut fresh_source,
        &mut fresh_full_source,
    )
    .unwrap();
    assert_eq!(fresh_outcome.final_tip, runtime.tip());
    assert_eq!(fresh.ironwood_frontier(), runtime.ironwood_frontier());
    assert_eq!(fresh.ironwood_checkpoints(), runtime.ironwood_checkpoints());

    println!(
        "checkpoint=9 tip_before={} tip_after={} common={} rewound={} applied={} root={}",
        hex::encode(branch_a_tip.block_hash),
        hex::encode(runtime.tip().block_hash),
        reorg.common_ancestor.unwrap().height,
        reorg.blocks_rewound,
        reorg.blocks_applied,
        hex::encode(runtime.ironwood_frontier().root().to_bytes()),
    );
}
