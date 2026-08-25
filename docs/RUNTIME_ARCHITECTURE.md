# Coppice runtime architecture

Zcash is the sole canonical-chain and fork-choice authority. Coppice validates
a host-selected Ironwood history and supplies deterministic native application
state machines; it neither creates a second consensus layer nor chooses forks.

```text
host CompactBlocks
  -> coppice-librustzcash (compact validation and one runtime acquisition query)
  -> coppice-core::CoreRuntime (canonical replay once)
  -> CoppiceRuntime<(ApplicationA, ApplicationB, ...)>
  -> isolated application roots, snapshots, and undo journals
```

`CoreRuntime` is application-blind. It validates height, predecessor, ordered
transaction positions, compact/full transaction consistency, and Ironwood
frontier updates. Carrier candidates are detected through the configured
receiver, not IVK decryption alone. CPV1 is reconstructed only from exact
rendezvous actions and CA01 is decoded once by Core.

`CoppiceRuntime` statically composes one or more `CoppiceApplication`s. It
does not sort host data or callbacks: tuple order is the declared deterministic
composition order. It stages a cloned Core and cloned application collection,
commits only after all applications succeed, and checks that all tips agree. It
takes the maximum application rewind requirement and rejects a Core
configuration whose retention is smaller. Rewinds follow the same staged,
tip-consistent boundary.

Each active application gets `ApplicationTransactionContext` values carrying a
canonical Core transaction and, independently, an optional payload addressed
to its exact `ApplicationKey`. It never receives another application's CA01
payload. Before its activation it receives block position only; Core effects
and all application payloads are unavailable.

The payload is the application protocol boundary. It may contain an
application-specific zero-knowledge proof or any other deterministic
authorization data, but Core does not parse or verify it. An application that
needs full public Ironwood action data requests `ExtendedEffects` through its
read-only acquisition hook; the compositor unions that request with Core's
carrier candidacy and performs one authenticated fetch. Proof verification,
proof replay rules, and the meaning of `cv`, `rk`, `cmx`, `nf`, flags, or value
balance remain application decisions.

`PersistedCoppiceApplication` provides common snapshot metadata: format,
descriptor, tip, root, oldest rewind point, and opaque application-owned bytes.
Applications retain exclusive control of state encoding and validation. Hosts
must persist a successful apply or rewind as one atomic boundary and rebuild
from the authenticated activation checkpoint when the common ancestor falls
outside retained history.

Canonical observations never contain wallet-private data. Compact contexts
always include nullifiers and commitments. The adapter asks the composed
runtime for one `FullTransactionAcquisition` value per transaction. Core
carrier candidacy is unioned with each active application's read-only
`ExtendedEffects` request, so a host does not branch on application types and
multiple applications share one fetch. Before activation an application
contributes no request. Core parses and cross-checks selected transactions,
then exposes typed value commitments, randomized keys, bundle flags, and
signed bundle value balance. Proofs, signatures, ciphertexts, private note
data, viewing keys, memos, recipients, values, ownership, and mempool facts
are not application state input.

The generic publisher prepares `ApplicationKey + payload` as CA01 inside CPV1
and can verify a constructed transaction using the same exact-receiver Core
inspection path. Wallet-specific fees, input selection, authorisation, and
application policy live above it.

For proof binding, an application can use its own descriptor's
`ApplicationId`/version, the already-public `CoreRuntimeId` captured from the
validated Core parameters, the canonical transaction position and identity,
the relevant ordered Ironwood effects, an operation discriminator, and its
own public fields. The application must freeze the exact subset and encoding
required by its protocol; Core intentionally does not impose a universal proof
domain or verification-key registry.

Coppice Names is an external consumer in `../coppice-names/`; it is not a
runtime subsystem.
