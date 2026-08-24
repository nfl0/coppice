# Coppice runtime architecture

This document records the production crate and state boundaries after the
general-runtime refactor. Protocol bytes remain governed by
`PROTOCOL_SPEC.md` and the normative vectors.

## Authority and dependencies

```text
Zcash wallet/host (sole fork choice)
        |
        | canonical CompactBlocks + candidate full transactions
        v
coppice-librustzcash
        |
        | CoreCanonicalBlockInput
        v
coppice-core::CoreRuntime
        |  owns CoreReplay, CPV1 and CA01 routing
        |  depends on no application crate
        v
coppice::NamesRuntime
        |  composes CoreRuntime + NamesApplication atomically
        v
wallet-facing Names workflows and protection policy
```

There is no second consensus layer. The host supplies an already selected
canonical chain. Core validates continuity, ordering, candidate/full
consistency, and Ironwood effects, but never chooses a competing block.

## Stable identities

- `CoreRuntimeId` binds only generic runtime/network/activation/carrier and
  rendezvous context.
- `ApplicationId + u16 version` selects an application from CA01.
- `NamesDeploymentId` is the frozen historical Names deployment hash used only
  by Names commitments, owner derivation and authorization, bond statements,
  and Names state roots.

The Rust APIs use distinct wrapper types wherever two identities could
otherwise be accidentally interchanged. Wallet carrier preparation accepts a
`CoreRuntimeId`; Names cryptography continues to accept the historical
32-byte deployment value.

## State ownership

```text
Core state
  canonical tip
  Ironwood frontier
  authenticated Ironwood checkpoints
  bounded canonical rewind journal

Names application state
  name records and active-bond index
  pending commitments
  recent-spent tags
  Names state root
  bounded Names undo journal
```

`CoreRuntime` decrypts public rendezvous frames and emits immutable transaction
contexts containing canonical height/hash/index/txid, ordered validated
nullifiers and commitments, candidate validation status, and optional routed
application message. It does not interpret an application payload.

`NamesApplication` consumes those contexts. Canonical nullifiers may terminate
Names bonds before a routed operation in the same transaction. The application
owns every Names transition, root, and undo entry.

## Apply and rewind composition

For apply, `NamesRuntime` clones/stages Core, applies and routes the complete
block, then applies Names against the immutable emitted context. It publishes
both staged layers only after both succeed. Fatal Core or application errors
therefore leave both layers unchanged; protocol-level Names rejections remain
committed no-ops after canonical effects and end-of-block processing.

For rewind, `NamesRuntime` first proves the requested Core rewind on a staged
clone, then rewinds Names, and finally commits the staged Core. Both layers
must retain the requested height and must resolve it to the same block hash.
The Core retention value is generic configuration. Names v1 supplies its
current required horizon when constructing the composed runtime; Core does not
import or calculate Names policy.

Deep reorgs outside the retained horizon are not guessed or locally selected.
The adapter reports that a rebuild is required, and the host reconstructs from
the configured activation checkpoint along its canonical chain.

## Persistence

`CoreReplay`, `CoreRuntime`, and `NamesApplication` serialize independently
versioned state. `NamesRuntime::save_snapshot` writes one composite manifest
that contains opaque Core and application snapshots plus:

- `CoreRuntimeId`;
- Names application ID and version;
- shared canonical tip;
- current Ironwood root/tree size; and
- current Names state root.

Loading validates each layer independently and then validates the manifest and
every retained Names root against the corresponding retained Core checkpoint.
The host must replace the manifest atomically. A snapshot from the old
monolithic development format is unsupported and is rebuilt from activation.
Incremental durability is one successful block or rewind boundary at a time;
reconciliation callbacks expose exactly those boundaries.

## Public crate surfaces

### `coppice-core`

- validated `CoreRuntimeParameters -> ValidatedCoreRuntimeParameters ->
  CoreRuntimeId`;
- `ApplicationId`, `ApplicationKey`, `ApplicationEnvelopeV1`, and
  `CoppiceApplication`;
- CPV1 limits and strict transport encoding/reconstruction;
- `CoreReplay` canonical input/context/checkpoint/rewind APIs;
- `CoreRuntime` routing, read-only transaction inspection, and Core snapshots.

Core must remain application-blind. In particular it must not gain Names,
bonds, owner keys, `.zec`, COMMIT/REVEAL, Unified Address, or application
retention concepts.

### `coppice`

- frozen Names protocol primitives and vectors;
- Names identity/core compatibility helpers;
- `NamesApplication` and the production `NamesRuntime` composition;
- Names snapshot, state, root, outcome, and rewind APIs.

### `coppice-librustzcash`

- hostile-input-safe CompactBlock adaptation;
- rendezvous candidate detection and candidate-only full transaction fetching;
- host-authoritative reconciliation and rebuild signaling;
- wallet-local bond inventory, witness/proof construction, pending intents,
  owner workflows, locks, and spend protection;
- normal librustzcash proposal/construction for Core-bound, Names-routed
  carriers.

Wallet policy is deliberately outside Core. A wallet may expose Coppice as
enabled, guard-only, or off. Off bypasses reconciliation/protection and never
changes how ordinary Zcash consensus or wallet scanning works. Names UI and
policy remain above the generic runtime API.

## Isolation rules

- Applications do not share mutable state or roots.
- An unknown `(ApplicationId, version)` is structurally valid and ignored by
  Names; it is never reinterpreted as Names.
- A malformed CA01 envelope is a deterministic routed rejection, not a fallback
  parser signal.
- Core native effects may drive an application's transition only through the
  immutable canonical context.
- No application can affect Core ordering, fork choice, or another
  application's state.
- The runtime has no WASM, arbitrary contracts, gas, or application-defined
  consensus.
