# Coppice Core Runtime Protocol Specification

**Status:** normative Core v1 specification; pre-release runtime API
**Scope:** generic Zcash/Ironwood deterministic application hosting

This document is the normative authority for Coppice Core. Coppice Names is an
external application and its protocol specification is subordinate to this
document for Core identity, transport, routing, canonical replay, and host
reconciliation. Names-specific operations, commitments, bonds, state roots,
and vectors are authoritative only in the `coppice-names` repository.

## 1. Runtime boundary

Coppice Core consumes a host-selected canonical Zcash chain. Zcash remains the
fork-choice and consensus authority. Core is not a blockchain, a second
consensus layer, a contract VM, or a remote application registry.

Core is application-blind. Applications are native deterministic state
machines hosted by `CoppiceRuntime`; they do not call one another or share
mutable state. A single canonical scan may feed one application or a static
composition of isolated applications.

The generic runtime is intentionally Ironwood-only. Sapling, pre-Ironwood
Orchard, transparent, wallet-private, mempool, and local-node observations are
not canonical application inputs.

## 2. Core identity and rendezvous

The Core protocol identity is `coppice.runtime`, version `1`. A validated
`CoreRuntimeParameters` contains, in canonical order:

```text
runtime_protocol_id     : length_u16 || bytes
runtime_protocol_version: u16
zcash_network_domain    : length_u16 || bytes
zcash_network_code      : u8 (Main=1, Test=2, Regtest=3)
runtime_activation      : u32
carrier_protocol_id     : length_u16 || bytes
rendezvous_ivk          : length_u16 || 64 bytes
rendezvous_receiver     : length_u16 || 43 bytes
```

`CoreRuntimeId` is unkeyed BLAKE2b-256 over that preimage with the exact
16-byte personalization `CoppiceRuntime1\0`. Raw parameters must first be
structurally validated, parsed as an Ironwood IVK/address pair, and checked
for the exact receiver/IVK relationship. Application IDs and application
activation heights are not in this preimage.

The qualification identity vector is retained at
`test-vectors/core_runtime_id.json`. Its regtest context uses activation 10,
carrier `CPV1`, and the exact rendezvous bytes recorded by that vector.

The configured receiver is part of the rendezvous invariant. Successful
compact decryption under the IVK is insufficient when it yields another
diversified receiver; candidate detection requires byte-for-byte equality with
the configured receiver.

## 3. CPV1 transport and CA01 envelopes

Core owns the generic CPV1 framing and CA01 application envelope. CPV1 uses:

```text
protocol magic                         CPV1
frame size                             512 bytes
maximum frames                         32
start header / payload capacity        74 / 438 bytes
continuation header / payload capacity 7 / 505 bytes
maximum authenticated payload          16,093 bytes
```

Frames are reconstructed by index, require one start frame, reject duplicate,
missing, out-of-range, malformed, and nonzero-padding bytes, and authenticate
the runtime ID and payload digest before routing. The configured exact
rendezvous is checked before any frame is considered.

The CA01 envelope is:

```text
CA01 || application_id[32] || application_version_u16_be || payload
```

`ApplicationId` is BLAKE2b-256 with personalization `CoppiceAppIdV1\0\0`
over the application's exact nonempty identity bytes. Core performs no text
normalization. The envelope and payload are bounded by CPV1's maximum payload.
Unknown application IDs, versions, and malformed envelopes are isolated
routed/application outcomes; they do not alter another application's state.

## 4. Application lifecycle and routing isolation

An application declares an `ApplicationDescriptor` containing an
`ApplicationKey` (ID plus version) and an activation height no earlier than
Core activation. `RuntimeBlockContext::for_application` (and the compositor's
equivalent context) delivers:

* the canonical position for every processed block;
* validated Core effects and messages only after that application's activation;
* at most the CA01 payload whose exact key matches that descriptor.

Before activation, effects and routed messages are unavailable. A message
routed to another application, an unknown route, a malformed envelope, or a
transport error is never passed as that application's payload. Applications do
not inspect a global envelope list to enforce their own key isolation.

`CoppiceRuntime<A>` applies Core once, derives one isolated context per hosted
application, stages Core and every application on clones, and publishes the
staged pair only after all applications succeed and their tips match Core.
Duplicate application keys are rejected at construction. Applications remain
independently activated; the composed host derives the maximum rewind
retention required by its members.

## 5. Canonical Ironwood observation

For each canonical transaction Core accepts compact Ironwood nullifiers and
note commitments (`cmx`) in canonical action order. These public effects are
available without fetching full transactions.

An adapter may request a full transaction selectively using a
`CanonicalCompactTransactionSummary` containing:

```text
tx_index, txid,
ironwood_nullifiers, ironwood_commitments,
action_count, rendezvous_candidate
```

This is a host policy decision, not application code embedded in Core. The
two independent acquisition reasons are represented by
`FullTransactionAcquisition`:

```text
None
Carrier
ExtendedEffects
CarrierAndExtendedEffects
```

Carrier detection always requires the full transaction. Extended-effect
selection fetches only the requested transactions and never turns a
non-carrier into a carrier. A `Carrier` acquisition authenticates bytes for
routing but does not expose typed extended effects; those effects are exposed
only for `ExtendedEffects` or `CarrierAndExtendedEffects`. Every supplied
transaction is untrusted until Core parses it under the canonical branch,
verifies its txid, and compares its Ironwood nullifiers and commitments with
compact data.

After that validation, an application may observe typed public extended
effects:

```text
CanonicalIronwoodActionEffects {
    nullifier,
    commitment,
    value_commitment,
    randomized_key,
}

CanonicalIronwoodBundleEffects {
    actions,
    value_balance,
    flags: spends_enabled / outputs_enabled / cross_address_enabled,
}
```

Private note plaintexts, wallet ownership, viewing keys, recipients, values,
memos, proof bytes, signatures, ciphertexts, and local observations are not
canonical Core inputs. A `Carrier` acquisition authenticates a full
transaction for carrier routing but does not expose typed extended effects.
Those effects are present only when acquisition is `ExtendedEffects` or
`CarrierAndExtendedEffects`, and the selected full transaction is authenticated.

## 6. Canonical replay and error boundaries

The host supplies a strictly sequential `CoreCanonicalBlockInput` with the
height, block hash, predecessor hash, consensus branch ID, transaction IDs,
ordered compact effects, and any acquired full bytes. Core verifies the next
height, predecessor, increasing transaction indexes, bounded bytes, full
transaction parse, txid, and compact/full effect equality before committing.

Core stages frontier, checkpoints, transaction contexts, and the tip. A fatal
canonical-input error leaves all state unchanged. Examples include malformed
compact effects, missing required bytes, unexpected bytes, oversized bytes,
invalid full transactions, txid mismatch, and compact/full effect mismatch.
Application rejection and unknown/malformed routing outcomes are deterministic
application results and do not permit Core to reinterpret canonical bytes.

The authenticated Ironwood frontier and checkpoints are advanced in canonical
transaction order. Core exposes nullifiers, commitments, typed extended
effects, prior checkpoints, and the post-block checkpoint only after the whole
block commits.

## 7. Persistence, rewind, and reconciliation

Core replay snapshots carry a format version, runtime identity, tip,
Ironwood frontier/checkpoints, and bounded undo history. Applications use the
generic `ApplicationSnapshot` / `PersistedCoppiceApplication` contract: the
application owns its payload, while Core validates format, descriptor,
activation, tip, state root, and rewind-boundary metadata before payload
loading.

`CoppiceRuntime` requires every application tip to equal Core's tip and every
application's retained history to intersect Core's retained history. The safe
common retention is the maximum application requirement; an application that
needs more history than Core retains cannot be composed.

Fork choice remains host-authoritative. The generic librustzcash adapter's
`CanonicalBlockSource` obtains the host tip and compact blocks, discovers a
retained common ancestor by comparing block hashes, rewinds Core and all
applications atomically, and replays the replacement suffix. It persists only
after a successful rewind or block commit. If no retained common ancestor
exists, reconciliation fails with `NoRetainedCommonAncestor`; it never invents
a fork or silently resets state.

## 8. Generic publication

The Core publisher accepts an `ApplicationKey` and payload bytes, constructs
the exact CA01 envelope, frames it as CPV1 using the configured Core runtime
ID, and targets the exact Core rendezvous. It exposes the same transport
inspection used by replay routing so an external builder can verify the
constructed transaction before broadcast. Bond selection, owner authorization,
pending registrations, and other policy belong to the consuming application.

## 9. Authority and vectors

This file and the generic Rust APIs are the Core authority. Generic vectors
under `coppice/test-vectors/` cover Core identity and replay/rewind properties.
Names-specific frozen envelopes, carrier frames, operation bytes, bond proofs,
and state-root vectors live under `coppice-names/test-vectors/`; their bytes
were copied without regeneration during extraction. The Names specification
references this Core specification rather than redefining Core wire or replay
semantics.
