//! Small operator-facing probe used by the reproducible native RPC harness.

use coppice_librustzcash::CanonicalBlockSource;
use coppice_zcash_rpc::{
    HttpTransport, RpcAdapterConfig, RpcCanonicalBlockSource, ZcashRpcClient, ZcashRpcConfig,
};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

fn regtest_parameters() -> LocalNetwork {
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

fn main() -> Result<(), String> {
    let endpoint = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: rpc-probe HTTP_ENDPOINT ACTIVATION_HEIGHT".to_owned())?;
    let activation = std::env::args()
        .nth(2)
        .ok_or_else(|| "usage: rpc-probe HTTP_ENDPOINT ACTIVATION_HEIGHT".to_owned())?
        .parse()
        .map_err(|error| format!("invalid activation height: {error}"))?;
    let transport = HttpTransport::new(ZcashRpcConfig::new(endpoint))
        .map_err(|error| format!("HTTP transport: {error:?}"))?;
    let mut source = RpcCanonicalBlockSource::new(
        regtest_parameters(),
        ZcashRpcClient::new(transport),
        RpcAdapterConfig::new(zcash_protocol::consensus::NetworkType::Regtest, activation),
    );
    let tip = source
        .canonical_tip()
        .map_err(|error| format!("canonical tip: {error:?}"))?;
    let checkpoint = source
        .activation_checkpoint(activation)
        .map_err(|error| format!("activation checkpoint: {error:?}"))?;
    let block = source
        .compact_block(activation)
        .map_err(|error| format!("activation block: {error:?}"))?
        .ok_or_else(|| "activation block unavailable".to_owned())?;
    println!(
        "tip={} {}\ncheckpoint={} {} root={} size={}\nblock={} {} prev={} txs={}",
        tip.height,
        hex::encode(tip.block_hash),
        checkpoint.height,
        hex::encode(checkpoint.block_hash),
        hex::encode(checkpoint.ironwood_frontier.root().to_bytes()),
        checkpoint.ironwood_tree_size,
        block.height,
        hex::encode(&block.hash),
        hex::encode(&block.prev_hash),
        block.vtx.len(),
    );
    Ok(())
}
