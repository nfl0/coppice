# Native Zcash JSON-RPC host integration

`coppice-zcash-rpc` is Coppice's primary/reference server integration. It is
designed against normal zcashd-compatible JSON-RPC with Zakura as the reference
compatibility and qualification target; it does not link to, call, or otherwise
depend on Zakura internals.

```text
Zakura or compatible Zcash full node
  -> standard JSON-RPC
  -> coppice-zcash-rpc
  -> CoppiceRuntime<Apps>
```

Zaino/lightwalletd remains a supported compact/light-client transport through
`coppice-librustzcash`. Both hosts reconstruct the same in-memory CompactBlock
facts and then use the already-qualified canonical ingestion path. Core knows
nothing about RPC, HTTP, Zakura, Zaino, or protobuf.

## Required RPC contract

The adapter needs the normal methods below. Result fields are treated as
untrusted encoding, even though the node remains the canonical fork-choice
authority.

| Method | Required semantics |
| --- | --- |
| `getblockchaininfo` | `chain`, `blocks`, `bestblockhash`, `pruned`, and, when pruned, `pruneheight`. |
| `getblockcount` | Current canonical tip height. |
| `getbestblockhash` | Current canonical tip hash. |
| `getblockhash(height)` | Canonical hash at a height. |
| `getblock(hash, 1)` | Object with exact `hash`, `height`, `previousblockhash`, and ordered `tx` id array. |
| `getrawtransaction(txid, 0, blockhash)` | Exact serialized transaction hex for the named block. The block hash is required so no global `txindex` is needed. |
| `z_gettreestate(hash)` | For activation bootstrap: exact `height`, `hash`, and Ironwood `commitments.finalState` / `finalRoot`. |
| `sendrawtransaction(hex)` | Optional publication helper for an already-authorized transaction. |

The node must use conventional display-order hexadecimal transaction and block
identifiers. The adapter converts identifiers exactly once at the JSON-RPC
boundary into librustzcash/CompactBlock internal order. Commitment-tree roots
are not identifiers and retain their RPC byte order. zcashd-compatible
Regtest reports the historical BIP70 `chain: "test"` label; the adapter accepts
that label when configured with Regtest consensus parameters. It only needs
HTTP; operators may place TLS termination in front of the local adapter
endpoint.

Zakura at qualification revision `f892b9074002a04a678ef2365ec7658795796572`
supports `getblock` verbosity 0/1/2, block-scoped `getrawtransaction`, and
Ironwood tree state in `z_gettreestate`. The adapter deliberately uses
verbosity 1 plus per-transaction raw RPC: that preserves the node's canonical
transaction order, validates raw bytes independently, and avoids trusting
node-decoded Ironwood effects. It does not require `txindex`.

## Canonicality and mutable node state

At the start of reconciliation the adapter obtains `getblockchaininfo`,
`getblockcount`, and `getbestblockhash`; disagreement fails rather than
creating a mixed snapshot. For each requested height it resolves the canonical
hash, verifies that `getblock` echoes that hash and height, obtains each raw
transaction scoped to that hash, parses it under the canonical branch ID,
checks its txid, and finally rechecks `getblockhash(height)`. The existing
reconciler then validates predecessor linkage, freezes the observed tip,
discovers a retained common ancestor, rewinds, and replays. A change at any
point is an explicit error for the caller to retry; the adapter never performs
its own fork choice.

Raw bytes are retained only in a single-block cache. The shared CompactBlock
adapter asks the frozen runtime whether each transaction is `None`, `Carrier`,
`ExtendedEffects`, or `CarrierAndExtendedEffects`; cached bytes are passed to
Core only for the selected mode. Core still parses the bytes, validates txid,
nullifiers, commitments, limits, and compact/full agreement. Transport access
to all block bytes does not grant applications additional observation rights.

## Pruning and activation bootstrap

`RpcAdapterConfig::required_history_from` is the earliest block body required
to activate or rebuild the hosted runtime. If `getblockchaininfo` reports a
larger `pruneheight`, the adapter returns `RequiredHistoryPruned`; it never
silently starts from partial history. Operators need a node retaining block
bodies through the earliest Coppice activation/rebuild checkpoint they intend
to service, not necessarily a forever archive.

For a fresh runtime, call `activation_checkpoint(activation_height)`. It
requests `z_gettreestate` at `activation_height - 1`, decodes the normal
librustzcash commitment-tree serialization, and cross-checks the returned
height, block hash, serialized tree, and final root before constructing the
unchanged `CoreReplayActivationCheckpoint`. If tree state is unavailable (for
example due to pruning), bootstrap fails explicitly; Core's authenticated
checkpoint requirement is not weakened.

## Native Zcash RPC qualification

The focused native qualification is separate from the frozen runtime/Names
Phases 1-7 evidence. Run it from this repository with pinned binaries built
from the adjacent checkouts:

```sh
./scripts/rpc-qualification.sh
```

The script launches an isolated archive-mode Zakura Regtest, generates a short
Ironwood chain, obtains the activation checkpoint through JSON-RPC, reconciles
the public Core runtime, snapshots/restarts it, performs a one-block real
Zakura `invalidateblock`/`generate` reorg, compares the replacement state to a
fresh replay, and then starts Zaino solely for a per-height `CompactBlock`
differential. The primary sequence uses only Zakura RPC; Zaino is not started
until the differential phase.

The first successful run used Zakura
`f892b9074002a04a678ef2365ec7658795796572`, Zaino
`b819583a1a6663a01cb7681ac5b5fc2a174596a0`, and native adapter base
`a86823f3e39ee06dd19e502772e02aa45deb93dc`. It recorded checkpoint height 9,
internal block hash `f4ddaea0bb155a7a08676e6a8369af77eb037fe2b8e159b0bb291d1912c414c9`,
Ironwood root `635e83b2277f91db040925459362c7d371b9e5a2efe0f251f049cca6d13e741f`,
and tree size 8. The live reorg had common ancestor 11, rewound/applied one
block, and ended at Ironwood root
`9fc5d1c1cf5d05d20377a5207422d3ee8758b2443a6fb8f86b6cbc586f03300d`.
RPC-derived and Zaino-derived CompactBlocks were exactly equal for every block
from activation through height 12.

## Security and operational notes

Malformed JSON success values, incorrect JSON-RPC ids, RPC errors, invalid or
wrong-length hashes, invalid hex, missing transactions, oversized responses,
wrong block hash/height, changed height mappings, and unavailable tree state
are hard errors. The adapter limits the built-in HTTP response and each raw
transaction to the consensus block bound. `ZcashRpcConfig::timeout` bounds
connect, read, and write activity (15 seconds by default). It intentionally
does not add a retry policy: a host can retry a complete reconciliation after a
transient failure or reorg.

`submit_raw_transaction` only hex-encodes and submits pre-authorized bytes.
It has no wallet, key, coin-selection, or node-wallet integration.

## Reproduction outline

Use the pinned Zakura source revision and a regtest node with normal RPC
credentials, then run the crate tests and the generic workspace checks:

```sh
git -C ../zakura rev-parse HEAD # f892b9074002a04a678ef2365ec7658795796572
cargo test -p coppice-zcash-rpc --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The previous frozen runtime/Names Phases 1–7 qualification is separate
historical evidence. Native RPC qualification must be recorded as a distinct
run and must not be represented as a rerun of that baseline.
