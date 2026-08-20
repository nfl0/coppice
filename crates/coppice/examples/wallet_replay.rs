use coppice::{config::TESTNET_V0, incremental::IncrementalWallet};
use incrementalmerkletree::frontier::CommitmentTree;

fn main() {
    // A real wallet supplies the authenticated Ironwood frontier immediately
    // before activation, then calls process_compact_block_with_chain for every
    // subsequent canonical block.
    let frontier = CommitmentTree::empty();
    let wallet = IncrementalWallet::testnet_v0([0; 32], frontier);
    println!(
        "Coppice Testnet V0 starts at {}; next={}",
        TESTNET_V0.activation_height,
        wallet.next_height()
    );
}
