# Coppice Core implementation guide

This guide describes the generic crates behind the Core protocol. It is not a
replacement for [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md).

```text
crates/coppice-core
    identities, CPV1/CA01, Core replay, Ironwood effects, publishing,
    application lifecycle, persistence metadata, and compositor
crates/coppice-librustzcash
    hostile CompactBlock adaptation, selective full acquisition, and
    host-authoritative canonical reconciliation
crates/coppice
    small public facade and application-authoring testkit
```

`CoreRuntime` is application-blind. `CoppiceRuntime<A>` stages one Core clone
and one clone of the statically hosted application set, applies a block once,
and publishes only after every application succeeds and its tip matches Core.
The tuple implementation is deliberately static: it gives deterministic
ordering without a registry or cross-application mutable calls.

The adapter validates every CompactBlock structurally before its first fetch.
`CanonicalCompactTransactionSummary` exposes compact nullifiers, commitments,
transaction index, txid, action count, and Core-owned rendezvous
classification. The `CanonicalRuntime` acquisition method passes a restricted
application view to each active application and unions their
`ExtendedEffects` requests with carrier candidacy. `FullTransactionAcquisition`
keeps carrier routing and extended-effect observation independent. Bytes are
parsed and cross-checked by Core before any routing or extended effects are
exposed.

`CanonicalBlockSource` and `FrozenCanonicalBlockSource` keep fork choice with
the host. Reconciliation discovers a retained hash-matching ancestor, rewinds
the generic runtime, replays the replacement suffix, and invokes a progress
callback only after durable state boundaries. A host that needs application
policy can layer it above this adapter without importing Names.

Applications persist an `ApplicationSnapshot` with an opaque application-owned
payload. The common envelope validates format, descriptor, activation, tip,
state root, and rewind-boundary metadata before the application decodes its
payload. A composed snapshot codec carrying Core plus heterogeneous application
payloads is intentionally still a follow-up API; callers may persist the Core
snapshot and each validated application snapshot separately for now.

The public `coppice::testkit::CanonicalHistoryBuilder` supplies synthetic
canonical blocks, compact-only transactions, forks, and empty blocks for
application tests without wallet-private data.
