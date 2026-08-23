# Coppice v1 Implementation Guide

**Audience:** implementation model / engineer  
**Normative protocol:** `PROTOCOL_SPEC.md`  
**Goal:** make implementation mechanical and minimize architectural invention.

## 1. Rules for the implementer

1. Read `PROTOCOL_SPEC.md` first.
2. Treat every protocol requirement ID (`P-*`) as authoritative.
3. Do not infer protocol behavior from legacy Coppice code when it conflicts
   with the new specification.
4. Reuse existing audited/working cryptographic code where explicitly called
   out below.
5. Do not redesign the proof system, carrier, reducer, wallet lock model, or
   operation set.
6. Do not add transfer, rebond, renewal, expiry, server authority, or new
   protocol operations.
7. Do not silently choose values for an item marked `FREEZE GATE`.
8. A task is complete only when its requirement-ID tests pass.

## 2. Repository starting point

The current repository is a single Rust workspace member:

```text
crates/coppice
```

and currently contains modules including:

```text
bond.rs
carrier.rs
config.rs
constants.rs
envelope.rs
incremental.rs
ironwood.rs
name_tree.rs
owner.rs
replay.rs
spent.rs
state.rs
vectors.rs
```

The workspace already pins `halo2_proofs = 0.3.2`, Pasta/Orchard dependencies,
and selects the Coppice Orchard fork through:

```toml
[patch.crates-io]
orchard = { path = "vendor/orchard" }
```

### Preserve, do not recreate

The implementation MUST preserve and build on:

```text
vendor/orchard
```

The existing Coppice Orchard patch already exposes/refactors the real Orchard
note-commitment, Merkle-membership, key, value, and nullifier constraints needed
for BondProof. Do not reimplement these cryptographic primitives.

The final BondProof implementation SHOULD replace the old Action-derived
production proof path with the measured dedicated parallel-Merkle
`CoppiceBondCircuit` only after F-001 in `PROTOCOL_SPEC.md` is completed.

Fixture/witness-generation code that already creates real Ironwood V3 notes and
Merkle paths SHOULD be factored and reused rather than recreated.

### Legacy code policy

Existing application protocol/state code may be deleted or rewritten freely if
that is simpler than adapting it. There is no requirement to preserve old
Coppice wire compatibility, database compatibility, or internal APIs.

The exception is cryptographic work explicitly marked for reuse above.

## 3. Recommended target structure

Do not create many crates merely for aesthetics. The cheapest acceptable first
implementation can remain one `coppice` crate with strong module boundaries:

```text
crates/coppice/src/
    protocol/
        hash.rs
        deployment.rs
        name.rs
        owner.rs
        operation.rs
        carrier.rs
        bond.rs
        tree.rs
        errors.rs

    reducer/
        state.rs
        apply.rs
        spent.rs
        reorg.rs
        snapshot.rs

    wallet/
        chain.rs
        witness.rs
        inventory.rs
        locks.rs
        register.rs
        resolve.rs

    lib.rs
```

A later split into `coppice-core` and `coppice-librustzcash` is optional. Do not
perform that split unless it reduces code rather than increasing it.

## 4. Implementation contract

The pure protocol/reducer layer MUST NOT depend on:

- wallet account IDs;
- wallet birthdays;
- output-lock database tables;
- UI state;
- RPC clients;
- filesystem paths.

It receives neutral canonical block effects and deterministic deployment
parameters and returns deterministic Coppice state.

The wallet layer is responsible for:

- obtaining canonical blocks/full transactions;
- historical Ironwood witnesses;
- owned-note enumeration;
- note-to-bond-tag matching;
- output locks;
- transaction construction;
- persistence integration;
- user-facing safety behavior.

## I-001 — Wallet-owned bond reconstruction

At a canonical tip:

```text
A = all bond_tags from NameRecords with status Active
B = all wallet-owned unspent Ironwood notes
```

For each owned note:

```text
nf  = note.nullifier(account_orchard_fvk)
tag = CoppiceBondTagV1(nf)
```

If:

```text
tag in A
```

the note is an owned live Coppice bond.

This mapping happens locally.

No remote query receives the note nullifier.

## I-002 — Viewing capability requirements

A full viewing key is sufficient to derive Ironwood note nullifiers.

A spending key is not required for bond classification.

Therefore:

- UFVK watch-only wallet: can classify owned bonds;
- spending wallet: can classify and manage/spend;
- UIVK-only wallet: cannot derive spentness/nullifier mapping and cannot provide full bond inventory.

The adapter MUST return an explicit capability error rather than guessing for UIVK-only accounts.

## I-003 — Output-lock owner and expiry

Use:

```rust
LockOwner::new(bond_tag)
```

for the corresponding active/pending Coppice bond.

The `bond_tag` is already domain-separated and is not secret.

For active and pending Coppice reservations, use the maximum representable
`BlockHeight` accepted by the backend as `lock_expiry_height` (for the current
librustzcash API this is `u32::MAX`). Reconciliation idempotently re-acquires
the same-owner lock. A future backend with a smaller explicit maximum MUST
expose that maximum through the adapter rather than silently shortening the
reservation.

A foreign subsystem lock MUST NOT be cleared by Coppice.

## I-004 — Reconstructible lock reconciliation

Desired wallet tags:

```text
desired_tags =
    active canonical bond tags owned by this wallet
    UNION
    local pending-registration bond tags
```

Enumerate wallet unspent Ironwood notes with a lock filter that includes already-locked outputs.

For each note derive its tag.

If tag is desired:

```text
ensure Coppice lock exists
```

If tag is not desired:

```text
remove only LockOwner(tag) if present
```

This makes reconciliation idempotent.

## I-005 — Mandatory pre-spend safety guard

When Coppice protection is active, an ordinary send MUST NOT be proposed until:

```text
host wallet canonical tip
==
Coppice reducer tip
```

including both:

```text
height
block_hash
```

Then bond reconciliation MUST succeed.

Only after that may the ordinary librustzcash proposal/input-selection path run.

If any step fails:

```text
ordinary send unavailable
```

Fail closed.

## I-006 — Generic lock clearing

If a wallet invokes generic output-lock recovery/clearing:

```text
clear locks
```

it MUST run Coppice reconciliation before another ordinary transaction proposal while protection mode is active.

The lock database is not authoritative.

## I-007 — Runtime feature modes

A Coppice-capable wallet SHOULD model three conceptual modes:

```text
Enabled
GuardOnly
Off
```

### Enabled

- full Coppice UI;
- global replay;
- resolve/register/update/release;
- bond inventory;
- lock reconciliation;
- pre-spend guard.

### GuardOnly

Used when the user hides/disables normal Coppice functionality while the wallet still owns active or pending bonds.

- replay continues;
- locks remain protected;
- ordinary spend guard remains;
- management UI may be minimal;
- user can re-enable or explicitly break bonds.

### Off

Equivalent to a Coppice-unaware wallet.

- no Coppice replay requirement;
- no Coppice lock reconciliation;
- no Coppice spend guard.

Automatic transition to Off is safe only when:

```text
no owned active bond
AND
no local pending bond
```

A force-Off action while bonds exist MUST show a clear warning.

## I-008 — Coppice-unaware wallet behavior

If the same seed is imported into a wallet with no Coppice support:

- the bonded Ironwood note appears as ordinary ZEC;
- the wallet may spend it;
- the resulting public nullifier is observed by Coppice-aware replayers;
- the active name becomes `BondSpent`.

This is intentional.

Coppice v1 does not cryptographically lock funds at consensus level.

## I-009 — Bond-note selection

For a new registration, wallet policy SHOULD choose:

> the smallest spendable eligible Ironwood note whose value is at least the minimum bond.

Do not automatically reserve a huge note merely because it is the oldest qualifying note.

Before confirmation show the user:

```text
minimum required: 1 ZEC
actual note reserved: X ZEC
```

## I-010 — Preparing a fresh bond note

Because v1 requires a fresh bond note, a wallet SHOULD support:

```text
Prepare Coppice bond
```

when no suitable recent note exists.

This is an ordinary self-transfer that creates a dedicated near-minimum Ironwood note.

After it is mined and witnessable, it can be selected for COMMIT.

This UX is strongly recommended because it:

- satisfies bond freshness;
- minimizes reserved value;
- avoids locking a large wallet note;
- reduces accidental spending ambiguity.

## I-011 — Registration wallet flow

Recommended flow:

```text
1. validate name + UA
2. choose/prepare recent Ironwood note
3. derive note nullifier and bond_tag
4. derive default owner key or obtain external owner pk
5. generate random registration secret
6. LOCK bond note
7. compute commitment
8. persist local pending intent
9. build/broadcast COMMIT carrier
10. wait for COMMIT to mine
11. sync to canonical COMMIT block
12. choose canonical anchor height >= COMMIT height
13. obtain note Merkle path at that anchor
14. derive deterministic freshness position floor
15. create BondProof
16. build/broadcast REVEAL
17. wait for REVEAL
18. canonical replay activates name
19. delete completed local pending metadata
20. reconciliation keeps the now-canonical active bond locked
```

Lock the bond before publishing COMMIT.

Do not spend CPU producing the expensive BondProof before COMMIT is mined unless an implementation deliberately precomputes reusable circuit material.

## I-012 — Pending local registration state

Pending state is wallet-local, not global protocol state.

Suggested shape:

```rust
pub struct PendingRegistration {
    pub wallet_account_id: [u8; 32],
    pub name: String,
    pub address: String,
    pub owner_pk: [u8; 32],
    pub bond_tag: [u8; 32],
    pub secret: [u8; 32],
    pub commitment: [u8; 32],

    pub commit_txid: Option<[u8; 32]>,
    pub commit_height: Option<u32>,
}
```

`wallet_account_id` is local wallet metadata derived from the canonical
Orchard full viewing key, not a wallet-database row identifier. It therefore
survives restart and same-seed/import restoration. A wallet-global pending
collection MUST filter pending bond tags by this account identity before
reconciling one account's notes; another account's pending bond is not a
missing note in the account currently being reconciled.

Do not rely on persisting the old `OutputRef`.

After restart:

```text
pending bond_tag
+
wallet unspent notes
+
UFVK
=
rediscover current output reference
```

## I-013 — Lost pending metadata

A COMMIT intentionally hides its preimage.

If all local pending metadata is lost before REVEAL, the wallet may not be able to recover:

- name;
- address;
- secret;
- intended owner context.

That registration attempt can be abandoned.

The COMMIT expires automatically.

No active name is lost.

Pending metadata backup across devices is outside v1.

## I-014 — Expired local registration handling

If a local pending COMMIT expires before successful REVEAL:

1. mark the local attempt expired;
2. remove its pending bond tag from the desired lock set;
3. reconcile;
4. the note becomes ordinarily spendable unless it backs another active name.

A retry MUST use a new registration secret and a new COMMIT.

It MAY use the same still-fresh unspent note if it remains within the freshness rule at the new COMMIT.

## I-015 — UPDATE wallet flow

```text
1. sync host + Coppice
2. require exact tip equality
3. resolve current Active record
4. derive/obtain owner signer
5. canonical-validate new UA
6. construct sequence+1 message
7. sign
8. construct UPDATE carrier
9. broadcast
10. wait for canonical replay
```

The bond remains locked throughout.

## I-016 — RELEASE wallet flow

```text
1. sync host + Coppice
2. require exact tip equality
3. resolve Active record
4. derive/obtain owner signer
5. sign sequence+1 RELEASE
6. construct/broadcast carrier
7. wait for canonical replay
8. record becomes Released
9. reconciliation removes bond reservation
```

The note remains unspent.

## I-017 — Explicit Break Bond

The controller of the ZEC note must always be able to reclaim it even if owner signing authority is unavailable.

A Coppice-aware wallet MAY expose:

```text
Break Bond
```

This deliberately constructs a Zcash transaction allowed to spend the specific output through its Coppice `LockOwner`.

No Coppice operation is required.

When mined:

```text
nullifier
-> bond_tag
-> active record becomes BondSpent
```

Never implement Break Bond by merely deleting the local lock.

## I-018 — Resolution and payment safety

A Coppice-aware wallet MUST prefer refusing payment over returning a questionable destination.

The send path MUST fail if:

- Coppice replay is behind;
- host and Coppice block hashes differ;
- NameTree proof verification fails;
- canonical UA validation fails;
- local reducer state fails validation.

Never silently degrade to an unchecked address.

## I-019 — Workspace structure

The target workspace SHOULD contain:

```text
coppice/
├── Cargo.toml
├── SYSTEM_DESIGN.md
├── README.md
├── PROTOCOL.md
├── REFERENCE.md
├── crates/
│   ├── coppice/
│   │   ├── protocol encoding
│   │   ├── cryptographic domains
│   │   ├── BondProof
│   │   ├── carrier framing
│   │   ├── deterministic reducer
│   │   ├── NameTree
│   │   ├── state commitment
│   │   ├── snapshot/rewind structures
│   │   └── public query APIs
│   │
│   └── coppice-librustzcash/
│       ├── CompactBlock conversion
│       ├── rendezvous compact detection
│       ├── candidate full-tx fetch orchestration
│       ├── shared-sync integration
│       ├── wallet-owned bond discovery
│       ├── output-lock reconciliation
│       ├── deterministic owner-key helper
│       └── feature-mode guard
│
├── test-vectors/
└── vendor/
    └── orchard/   # only the non-consensus circuit API patch if still required
```

No production dependency from `coppice` core to SQLite is required.

## I-020 — Core crate responsibilities

`coppice` owns:

- deployment parameter validation;
- deployment ID derivation;
- canonical name parsing;
- operation encoding/decoding;
- memo frame encoding/decoding;
- `bond_tag` derivation;
- BondProof creation/verification primitives;
- owner signature message construction/verification;
- name state transitions;
- recent-spend tracking;
- Ironwood frontier progression;
- deterministic state commitment;
- block reduction;
- bounded rewind information;
- resolution and live-bond queries.

`coppice` MUST NOT own:

- account wallet birthdays;
- wallet databases;
- Zaino/lightwalletd connections;
- wallet UI settings;
- transaction coin selection;
- user balance presentation;
- application seed storage.

## I-021 — librustzcash adapter responsibilities

`coppice-librustzcash` owns:

- adapting current librustzcash CompactBlocks to neutral Coppice block inputs;
- sharing the host's chain source and canonicality decisions;
- historical Coppice catch-up independent from account scan ranges;
- detecting compact Ironwood outputs decryptable by the public rendezvous incoming key;
- fetching required full transactions;
- converting wallet-owned unspent Ironwood notes into Coppice bond tags;
- output-lock reconciliation;
- ordinary-send safety guard;
- optional runtime feature mode;
- default owner-key derivation for software spending accounts;
- integration-level tests.

CompactBlock ingestion first validates the complete hostile protobuf structure,
then extracts every canonical Ironwood nullifier and commitment and performs
public rendezvous compact trial decryption. Only transactions with a rendezvous
hit require a raw full-transaction fetch. Those bytes and the compact effects
are passed to the reducer, which validates the transaction under the canonical
branch ID, its txid, and the exact compact/full Ironwood effects before applying
the block atomically. A compact hit does not imply a valid Coppice bulletin, and
a missing required full transaction prevents any reducer advance.

Canonical-chain reconciliation takes host-selected block identities as its sole
chain authority; Coppice performs no Zcash fork choice. It discovers the highest
common ancestor without mutation inside the reducer's retained history, invokes
`V1Reducer::rewind_to`, and replays replacement CompactBlocks exclusively through
`apply_compact_block`. Reorg depth is bounded by the frozen reducer undo history;
a deeper divergence requires rebuild. Replay starts no earlier than activation,
is resumable, and is block-atomic rather than one range transaction. Once a
known-stale suffix has been rewound, a later failure leaves the reducer at the
last successfully applied canonical block and never restores that stale suffix.
Historical replay holds only the currently validated CompactBlock, not the full
catch-up range. A pass targets the canonical tip observed at its start. Normal
extension beyond that tip does not invalidate success when the observed tip is
still canonical; a later invocation catches up the newly arrived suffix.

The Orchard/Ironwood builder may randomize Action positions. Wallet carrier
construction MUST NOT rely on output insertion order to preserve frame order.
It may add rendezvous outputs in any builder order; canonical v1 reconstruction
uses each memo's explicit `frame_index`.

Carrier transaction construction SHOULD map each prepared frame to one
zero-valued payment to the Orchard-only rendezvous Unified Address and use the
normal `propose_transfer` and `create_proposed_transactions` wallet path. The
proposal MUST route every payment to Ironwood, and the stored finished
transaction MUST be decrypted and reconstructed before it is handed to a
broadcaster.

`create_proposed_transactions` stores constructed transactions before Coppice
can perform that final inspection. A post-build invariant failure is therefore
an integration-recovery condition and MUST retain the affected txid; it is not
a claim that wallet state was rolled back or an ordinary request to retry.

It SHOULD depend on librustzcash public traits rather than directly on `zcash_client_sqlite` where practical.

Historical Ironwood witness retrieval is a required proving capability. Because
the current librustzcash historical-witness helper is backend-specific, the
adapter SHOULD define a small `IronwoodWitnessSource` abstraction and provide a
`WalletDb` implementation rather than pretending this operation already exists
in every generic wallet-storage trait.

## I-022 — Rewind storage

The core SHOULD keep a bounded per-block undo journal.

Suggested shape:

```rust
pub struct BlockUndo {
    pub height: u32,
    pub block_hash: [u8; 32],

    pub previous_ironwood_frontier: IronwoodFrontier,

    pub previous_name_records:
        Vec<(String, Option<NameRecord>)>,

    pub previous_commitments:
        Vec<([u8; 32], Option<ChainPosition>)>,

    pub recent_spent_changes:
        Vec<RecentSpentUndo>,

    pub checkpoint_changes:
        CheckpointUndo,
}
```

Record the old value only once per mutated key per block.

`active_bond_index` MAY simply be rebuilt after rewind.

## I-023 — Bounded reorg retention

Reorg retention is a local storage policy, not protocol semantics.

Recommended default:

```text
100 blocks or greater
```

If the host requests a rewind deeper than locally retained undo state:

```text
return NeedsRebuild
```

Then discard local Coppice state and replay from the activation checkpoint.

Correctness is more important than heroic deep-reorg local mutation.

## I-024 — Persistence snapshot

A persisted local snapshot SHOULD contain:

```rust
pub struct CoppiceSnapshotV1 {
    pub format_version: u32,
    pub deployment_id: [u8; 32],

    pub tip: ReplayTip,

    pub names: ...,
    pub commitments: ...,
    pub recent_spent: ...,

    pub ironwood_frontier: ...,
    pub ironwood_checkpoints: ...,

    pub rewind_journal: ...,

    pub state_root: [u8; 32],
}
```

`active_bond_index` should be reconstructed rather than trusted as independent persisted authority.

The reference reducer exposes a versioned local snapshot containing its current
authoritative state plus a bounded rewind journal. The default journal retains
one full current state and 100 per-block undo entries. Each undo entry stores
only previous values for registry keys changed by that block, together with the
previous compact Ironwood frontier and checkpoint-map changes; it does not copy
the complete registry state. Loading rejects a wrong deployment, non-contiguous
or oversized history, malformed canonical records, invalid tree/checkpoint
relationships, and current or historical state-root mismatches by walking the
journal backward. The active bond index is always rebuilt from authoritative
name records. Snapshot bytes remain wallet-local data; after loading, the host
must still compare the saved tip identity with its selected canonical chain
before enabling protected spends.

## I-025 — Snapshot validation and local trust model

On load:

1. check format version;
2. check deployment ID;
3. canonical-validate every name;
4. canonical-validate every owner key;
5. canonical-validate every stored UA;
6. validate status/terminal-height invariants;
7. rebuild active bond index;
8. reject duplicate active bond tags;
9. verify commitment ordering/positions;
10. verify RecentSpent retention bounds;
11. verify checkpoint ordering and frontier/root consistency;
12. recompute NameTree root;
13. recompute all state subroots;
14. recompute state root;
15. compare with stored state root;
16. compare local tip hash with the host wallet's canonical hash at that height.

Any failure means the snapshot is unusable.

These checks detect malformed or inconsistent local state; a self-computed state
root is not an authentication proof against an attacker who can coherently
rewrite the wallet database and the stored root. v1 therefore places local
wallet-storage integrity in the trust base. A higher-assurance application MAY
MAC snapshots with a wallet-held secret or re-fetch/replay canonical chain data.

The application can rebuild from activation.

## I-026 — Crash consistency

The host wallet DB and Coppice persistence may not share one database transaction.

Safety is obtained through idempotence and exact tip matching.

After restart:

```text
read host wallet tip
read Coppice tip

if tips differ:
    catch up or rewind Coppice

then:
    reconcile bond locks
```

Ordinary sends remain disabled while protection mode requires synchronization.

## I-027 — Initial catch-up

A wallet may have existed for years before Coppice is enabled.

Correct flow:

```text
user enables Coppice
        |
        v
obtain activation checkpoint
        |
        v
fetch canonical blocks from Coppice activation
        |
        v
run Coppice reducer to current canonical tip
        |
        v
enumerate this wallet's current unspent Ironwood notes
        |
        v
match note tags against Active name bond tags
        |
        v
reconstruct output locks
```

Do not rescan the user's viewing key from Coppice activation merely to build registry state.

Coppice catch-up is global chain processing.

Personal note discovery remains the normal host wallet's job.

## I-028 — Steady-state shared sync

After initial catch-up, Coppice SHOULD consume the same live CompactBlock stream already used by the host wallet.

The application should avoid a second independent polling loop when a shared feed is available.

If the current high-level librustzcash sync API does not expose observer hooks, the adapter may wrap/reuse the same block source/cache and the host's canonical tip/reorg decisions.

Do not fake a Coppice account with birthday equal to activation.

## I-029 — librustzcash compatibility requirements

The chosen upstream revision must coherently support:

- Ironwood compact scanning;
- Ironwood wallet notes;
- Orchard/UFVK full viewing key access;
- `InputSource`;
- enumeration of unspent Ironwood notes;
- `LockFilter::Unfiltered` or equivalent;
- `OutputLockStore` or equivalent;
- owner-scoped output locks;
- default exclusion of locked inputs from ordinary selection;
- chain state including Ironwood frontier/tree metadata;
- reorg/truncation APIs used by the host wallet.

Pin all related librustzcash crates to one coherent revision.

Do not mix incompatible git and crates.io revisions.

## I-030 — Bond inventory API

Suggested adapter types:

```rust
pub struct OwnedBond<NoteRef> {
    pub name: String,
    pub note_ref: NoteRef,
    pub output_ref: OutputRef,
    pub bond_tag: [u8; 32],
    pub note_value: Zatoshis,
}

pub struct BondInventory<NoteRef> {
    pub bonds: Vec<OwnedBond<NoteRef>>,
    pub tip: ReplayTip,
}
```

The actual full note value is reported.

## I-031 — Balance presentation

A wallet SHOULD distinguish:

```text
total balance
ordinary spendable balance
Coppice bonded value
other locked value
pending value
```

`locked_value` from librustzcash is generic.

Coppice-specific bonded value comes from the derived `BondInventory`.

## I-032 — RELEASE reorg example

Suppose:

```text
H: RELEASE alice
```

Canonical state becomes:

```text
alice = Released
bond note unlocked after reconciliation
```

Then host detects a reorg removing H.

Flow:

```text
host rewinds wallet DB
host tells Coppice rewind_to(H-1)
Coppice restores alice = Active
replacement branch is replayed
wallet note becomes unspent again in host DB
bond reconciliation derives matching active tag
bond note is relocked
```

No special inverse RELEASE protocol code is required outside generic rewind.

## I-033 — Bond-spend reorg example

Suppose a bond spend at height H marks:

```text
alice = BondSpent
```

If H is reorged away:

```text
Coppice rewind restores Active
host wallet rewind restores the note as unspent
reconciliation relocks it
```

Again, desired state is derived from the canonical post-reorg world.

## I-034 — Multiple accounts

Use one global Coppice reducer per deployment/network, not one per account.

```text
             CoppiceReducer
                   |
        +----------+----------+
        |          |          |
     account A  account B  account C
```

Each account performs its own private note/tag matching.

## I-035 — Multiple devices with the same seed

After an active REVEAL is mined, another Coppice-aware device with the same account can recover:

- the active name from global replay;
- the bond tag from NameRecord;
- the bond note from UFVK note/tag matching;
- the default owner signer from the account Orchard spending key + name + bond tag.

No active-registration side database needs to be synchronized.

Pending pre-REVEAL state remains the exception.

## I-036 — Core API sketch

Recommended high-level API:

```rust
pub struct CoppiceReducer {
    ...
}

impl CoppiceReducer {
    pub fn new(
        params: DeploymentParameters,
        checkpoint: ActivationCheckpoint,
    ) -> Result<Self, InitError>;

    pub fn deployment_id(&self) -> [u8; 32];

    pub fn tip(&self) -> ReplayTip;

    pub fn state_root(&self) -> [u8; 32];

    pub fn apply_block(
        &mut self,
        block: &CanonicalBlockInput,
    ) -> Result<BlockOutcome, ApplyBlockError>;

    pub fn rewind_to(
        &mut self,
        height: u32,
        block_hash: [u8; 32],
    ) -> Result<(), RewindError>;

    pub fn resolve(
        &self,
        name: &str,
    ) -> Result<Resolution, ResolveError>;

    pub fn resolve_for_payment(
        &self,
        name: &str,
    ) -> Result<VerifiedDestination, ResolveError>;

    pub fn live_bonds(
        &self,
    ) -> impl Iterator<Item = LiveBond<'_>>;

    pub fn is_live_bond_tag(
        &self,
        tag: &[u8; 32],
    ) -> bool;

    pub fn snapshot(&self) -> Result<Vec<u8>, SnapshotError>;

    pub fn restore(
        params: DeploymentParameters,
        bytes: &[u8],
    ) -> Result<Self, SnapshotError>;
}
```

## I-037 — Live-bond API

```rust
pub struct LiveBond<'a> {
    pub name: &'a str,
    pub record: &'a NameRecord,
}
```

Definition:

```text
record.status == Active
```

Because bond spends are materialized directly into `NameStatus::BondSpent`, wallet integrations do not need to combine NameTree semantics with a separate spent-tree proof.

## I-038 — Note-to-bond-tag API

Core SHOULD expose:

```rust
pub fn bond_tag_from_nullifier(
    nf: [u8; 32],
) -> Result<[u8; 32], BondTagError>;
```

The librustzcash adapter SHOULD expose:

```rust
pub fn bond_tag_for_note(
    note: &orchard::note::Note,
    fvk: &orchard::keys::FullViewingKey,
) -> Result<[u8; 32], BondTagError>;
```

The second function MUST call the first after canonical nullifier derivation.

There must be exactly one protocol implementation of the nullifier-to-tag relation.

## I-039 — Chain-source adapter API

Conceptually:

```rust
pub trait CoppiceChainSource {
    type Error;

    fn activation_checkpoint(
        &mut self,
        params: &DeploymentParameters,
    ) -> Result<ActivationCheckpoint, Self::Error>;

    fn canonical_tip(
        &mut self,
    ) -> Result<ReplayTip, Self::Error>;

    fn compact_blocks(
        &mut self,
        start: u32,
        end_inclusive: u32,
    ) -> Result<Vec<CompactBlock>, Self::Error>;

    fn full_transaction(
        &mut self,
        txid: [u8; 32],
    ) -> Result<Vec<u8>, Self::Error>;
}
```

Actual async/streaming APIs may differ.

The architecture, not this exact trait syntax, is normative.

## I-040 — Shared sync contract

The adapter should expose two modes of chain feeding:

### Catch-up

Fetch every canonical block from:

```text
max(reducer.next_height, activation_height)
```

to current host tip.

### Live observer

Consume each newly host-accepted canonical block.

### Reorg

Receive host-selected rewind event and call:

```text
reducer.rewind_to(...)
```

Then consume replacement blocks.

The host remains chain authority in all three modes.

## I-041 — No fake Coppice account

Do not create a fake librustzcash account whose birthday equals Coppice activation.

Coppice's rendezvous incoming key is public protocol scanning capability, not a user's account key.

Global Coppice history and personal wallet history must remain conceptually and structurally separate.

## I-042 — No custom ordinary coin selector

Coppice SHOULD NOT fork or reimplement ordinary wallet coin selection.

Instead:

```text
Coppice reconciliation
-> standard output locks
-> ordinary librustzcash selection excludes locked notes
```

Only bond-candidate selection for a new registration needs a Coppice-specific "smallest suitable note" policy.

## I-043 — Dependency policy

`CoppiceBondCircuit` SHOULD reuse Orchard/Ironwood cryptographic gadgets and
primitive definitions, but it MUST be a dedicated Coppice statement rather than
a modified Orchard Action circuit.

The project MAY vendor or expose a narrowly scoped non-consensus Orchard/halo2
gadget API patch if required primitives are not public upstream.

Such a patch MUST:

- be documented file by file;
- avoid changing Zcash consensus semantics;
- preserve upstream tests;
- expose or refactor only the generic gadgets needed by `CoppiceBondCircuit`;
- not add Coppice semantics to the Zcash consensus Action circuit.

Do not fork librustzcash wallet scanning/coin selection merely for Coppice.

## I-044 — Cryptographic setup

Coppice deliberately uses two hash domains:

```text
byte-oriented protocol hashing:
    personalized BLAKE2b-256

field/circuit-native hashing:
    Poseidon<P128Pow5T3>
```

BLAKE2b-256 is used for public byte strings, identifiers, commitments,
authenticated state hashes, and carrier payload digests. The default owner-key
derivation uses keyed personalized BLAKE2b-512. This keeps Coppice's
byte-oriented cryptography within one primitive family and follows the
personalized BLAKE2b approach already used for modern Zcash transaction
digests.

Poseidon is used only where the relation must be efficient to constrain inside
the Pasta-field proof circuit, most importantly the public nullifier-to-bond-tag
relation and field-valued semantic bindings.

`CoppiceBondCircuit` uses the Halo2 PLONKish proving system with the IPA
polynomial commitment scheme over the Pasta cycle. This keeps the proof system
aligned with Orchard's existing Zcash proving stack and requires no trusted
setup.

The circuit is purpose-built and MUST NOT carry irrelevant Orchard Action
semantics merely to reuse an Action circuit implementation.

The implementation SHOULD retain deterministic circuit-shape tests and
measurement tools for:

- constraint count / circuit degree;
- minimum feasible `k`;
- proving-key and verifying-key identity;
- proof size;
- proving time;
- verification time;
- peak memory.

These measurements are engineering data until the proof-format freeze gate
promotes the selected circuit version, `k`, and serialization to normative v1
parameters.

## I-045 — BondProof negative tests

The test suite MUST instantiate the purpose-built `CoppiceBondCircuit` directly;
it MUST NOT satisfy these tests by wrapping the complete Orchard Action circuit.

At minimum prove rejection for:

1. note value below minimum;
2. note position below freshness floor;
3. wrong Merkle path;
4. wrong anchor;
5. wrong bond tag;
6. wrong owner;
7. wrong name;
8. wrong address;
9. wrong deployment binding;
10. wrong spending authorization key;
11. malformed/canonicality-invalid public input.

Also prove acceptance exactly at:

```text
note_value == minimum
note_position == position_floor
```

The threshold relations are inclusive.

## I-046 — Core state-machine tests

At minimum:

- COMMIT inserts pending state;
- duplicate live COMMIT rejected;
- same-block REVEAL rejected;
- REVEAL at `C+1` accepted;
- REVEAL at `C+TTL` accepted;
- REVEAL after deadline rejected;
- expired commitment pruned;
- successful REVEAL consumes commitment;
- failed REVEAL does not;
- absent name can register;
- Active name cannot;
- Released cooldown enforced;
- BondSpent cooldown enforced;
- pre-terminal COMMIT cannot claim later;
- first valid same-block REVEAL wins;
- duplicate active bond tag rejected;
- recently spent candidate bond rejected;
- freshness floor rejects old note;
- UPDATE correct;
- UPDATE wrong sequence rejected;
- UPDATE wrong signer rejected;
- RELEASE correct;
- bond spend marks Active record BondSpent;
- same-tx bond spend occurs before operation;
- released record not converted to BondSpent by later spend;
- state roots deterministic.

## I-047 — RecentSpent boundary tests

Explicitly test off-by-one boundaries.

For `F` and `TTL`:

- oldest still-eligible note creation;
- earliest possible spend of that note;
- latest legal REVEAL;
- spent tag retained exactly long enough;
- one block later old tag may prune;
- after pruning, the old note must already fail freshness proof.

This theorem must be encoded in tests, not left only as documentation.

## I-048 — Carrier tests

At minimum:

- START-only single-frame round trip;
- START + CONT maximum-payload round trip;
- missing CONT frame;
- extra CONT frame;
- second START frame;
- START not first;
- incorrect required frame count;
- non-final short chunk;
- wrong payload digest;
- wrong deployment ID;
- wrong magic;
- wrong frame type;
- nonzero padding;
- oversized frame count;
- oversized payload;
- multiple START payloads;
- candidate with no valid Coppice frames;
- compact candidate detection;
- full/compact txid mismatch;
- full/compact effects mismatch;
- maximum-size REVEAL builds a standard-fee transaction and remains below consensus/policy size limits.

Parsers MUST never panic on arbitrary bytes.

## I-049 — Property and fuzz testing

Use property tests/fuzzing for:

- operation parser;
- frame parser;
- frame reconstruction;
- name canonicalization;
- record encoding;
- state transition no-op on rejection;
- snapshot decode;
- replay determinism;
- block atomicity.

Useful invariant:

```text
serialize(parse(x)) == canonical_x
```

for accepted canonical encodings.

## I-050 — Reorg tests

At minimum:

- rewind UPDATE;
- rewind RELEASE;
- rewind BondSpent;
- rewind successful REVEAL;
- rewind commitment expiry;
- rewind recent-spent pruning boundary;
- rewind checkpoint pruning boundary;
- replacement branch with different name winner;
- local retention exceeded -> NeedsRebuild.

After rewind + replacement replay, compare roots against a fresh replay of the replacement branch.

## I-051 — Wallet-adapter tests

At minimum:

- owned Active bond locks note;
- nonmatching note untouched;
- already locked desired note is idempotent;
- lost lock reconstructed;
- RELEASE unlocks;
- BondSpent removes active reservation;
- reorg restores reservation;
- pending local bond locks before REVEAL;
- expired pending attempt unlocks;
- foreign lock conflict fails closed;
- multiple accounts isolated;
- UFVK-only classification works;
- UIVK-only returns capability error;
- actual full note value reported;
- same seed restores active bond;
- deterministic owner signer restores UPDATE/RELEASE authority;
- host/Coppice same height but different hash prevents send;
- wallet birthday later than activation does not alter Coppice catch-up;
- enabling Coppice years later reconstructs registry correctly.

## I-052 — Integration-test topology

A useful local integration topology is:

```text
reference wallet / adapter
        |
        v
      Zaino
        |
        v
      Zebra
        |
        v
mining/funding wallet
```

Tests SHOULD exercise real Ironwood transactions for:

- create recent bond note;
- COMMIT;
- REVEAL with real BondProof;
- UPDATE;
- RELEASE;
- ordinary spend of active bond;
- reorg where practical;
- multi-wallet same-seed recovery where practical.

The reference integration must not define protocol semantics differently from core tests.

## I-053 — Security-review checklist

Before any production claim, independently review:

- BondCircuit soundness;
- position-floor comparison;
- value threshold comparison;
- spending-key authorization relation;
- bond-tag Poseidon relation;
- owner binding;
- registration context binding;
- deployment binding;
- commitment semantics;
- commit claim-epoch rule;
- recent-spent retention proof;
- parser canonicality;
- block ordering;
- same-transaction spend ordering;
- reorg recovery;
- wallet lock reconciliation;
- keyed BLAKE2b owner-key KDF and scalar reduction;
- BLAKE2b personalization/domain separation;
- rendezvous spam surface;
- state persistence assumptions.

## I-054 — Recommended implementation phases

Although the target is one complete system, implementation should be staged so invariants become testable early.

### Phase 1 — protocol primitives

Implement:

- deployment parameters/ID;
- names;
- UA canonical validation;
- operation encoding;
- owner signatures;
- commitment;
- bond tag;
- carrier frames;
- deterministic test vectors.

### Phase 2 — BondProof

Implement the dedicated `CoppiceBondCircuit`:

- real Ironwood/V3 note witness;
- exact Ironwood note commitment relation;
- Sinsemilla Ironwood Merkle membership;
- exact Orchard/Ironwood nullifier derivation;
- spend-authority / viewing-key authorization relation;
- inclusive minimum-value constraint;
- Poseidon bond-tag relation;
- private-position / public-floor comparison;
- deployment/context/owner bindings;
- smallest feasible circuit `k`, determined by measurement rather than inherited from Orchard Action;
- proof API and frozen verifying-key identity;
- negative and boundary tests;
- proof-size/proving-time/verification-time benchmarks.

Phase 2 MUST NOT be implemented by wrapping the complete Orchard Action circuit.

### Phase 3 — pure state reducer

Implement:

- records/statuses;
- NameTree;
- pending commitments;
- RecentSpent;
- active bond index;
- Ironwood frontier/checkpoints;
- transitions;
- state root;
- block application.

### Phase 4 — persistence and reorg

Implement:

- snapshot;
- validation;
- undo journal;
- rewind;
- NeedsRebuild;
- deterministic replay tests.

### Phase 5 — librustzcash chain adapter

Implement:

- compact conversion;
- public rendezvous candidate scan;
- full tx retrieval contract;
- catch-up;
- shared live feed contract;
- host-driven reorg events.

### Phase 6 — wallet bond adapter

Implement:

- note-to-tag;
- inventory;
- output locks;
- reconciliation;
- pre-spend guard;
- Enabled/GuardOnly/Off;
- deterministic default owner signer.

### Phase 7 — real-chain integration

Implement:

- local regtest lifecycle;
- real Ironwood BondProof registration;
- spend invalidation;
- restore;
- reorg test where feasible.

### Phase 8 — documentation/vector freeze

Generate and review all normative docs and vectors.

## I-055 — Acceptance criteria

The v1 implementation is complete only when all are true.

### Core protocol

- four operations only;
- exact canonical wire format implemented;
- personalized BLAKE2b-256 byte-hash suite implemented exactly;
- no SHA-256 application-level protocol hash;
- exact domains and 16-byte personalizations documented;
- no transfer/rebond code path;
- canonical UA enforcement;
- commit TTL;
- claim-epoch rule;
- deterministic cooldown.

### Bond

- purpose-built `CoppiceBondCircuit`;
- no dummy Orchard Action/output/value-commitment semantics;
- real Ironwood note commitment and membership;
- spending authority proof;
- 1 ZEC default threshold capability;
- hidden exact value;
- canonical Poseidon bond tag;
- dynamic freshness position floor;
- deployment/name/address/owner bindings;
- final circuit `k` and verifying key selected from the purpose-built circuit, not inherited by compatibility.

### Bounded state

- no preactivation nullifier scan;
- no unbounded global spent-tag tree;
- RecentSpent bounded by `F + TTL`;
- Ironwood checkpoint history bounded;
- pending COMMITs bounded by TTL;
- reorg undo bounded local policy.

### Replay

- host is canonical-chain/reorg authority;
- account birthday never controls Coppice replay start;
- candidate tx unavailability stalls replay;
- block application atomic;
- full/compact effects cross-checked;
- exact state root deterministic.

### Wallet

- UFVK can reconstruct owned active bonds;
- normal sends exclude those notes;
- lost locks regenerate;
- same-seed restore works;
- standard deterministic owner key can be restored from spending authority;
- RELEASE unlocks by reconciliation;
- explicit bond spend terminates name;
- GuardOnly protects bonds;
- Off behaves like unaware wallet.

### Quality

- no parser panics;
- comprehensive negative tests;
- reorg vs fresh-replay equivalence tests;
- deterministic test vectors;
- fmt/clippy/tests clean;
- vendored cryptographic patch documented.

## I-900 — BondProof implementation decision

Use the dedicated **parallel-Merkle `CoppiceBondCircuit`**.

Measured reference:

```text
k                     11
proof bytes            4,960
public inputs          7
advice columns         10
fixed columns          14
instance columns       1
lookup arguments       3
equality columns       15
permutation sets       3
prove time             ~393 ms
verify time            ~4.97 ms
peak RSS               ~88,344 KiB
```

These measurements are not performance requirements. They are regression
signals. A major unexplained regression SHOULD block release.

The circuit MUST contain exactly the semantic relations listed by
`P-BOND-002` and the seven public inputs in `P-BOND-004`.

The single instance column MUST use this exact order:

```text
0 anchor
1 minimum_value
2 position_floor
3 protocol_binding
4 context_binding
5 owner_binding
6 bond_tag
```

The frozen verifier identifier is:

```text
BOND_VK_ID = a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc
```

The circuit MUST NOT reintroduce the following Action-only machinery:

```text
output note
output commitment
v_new
value commitment / trapdoor
value-balance sign or magnitude
alpha
randomized action key
cmx public effect
enable-spend flag
enable-output flag
cross-address Action checks
```

The existing Orchard V3 note-commitment, Sinsemilla Merkle, CommitIvk/ECC,
nullifier, and related gadgets SHOULD be reused unchanged.

### Position-floor comparator

Implement the freshness condition as an integer relation, not field subtraction
alone.

Constrain canonical 32-bit values:

```text
note_position
position_floor
delta
```

with:

```text
note_position = position_floor + delta
```

and constrain all three to the unsigned 32-bit range. The equality must not be
allowed to wrap modulo the Pallas field.

Required boundaries:

```text
position == floor       PASS
position == floor - 1   FAIL
floor == 0              supported
position == u32::MAX    supported if the underlying tree position permits it
```

## I-901 — Requirement-to-test policy

Every protocol requirement ID SHOULD appear in at least one test name or test
comment.

Preferred style:

```rust
#[test] // P-CARRIER-003
fn rejects_nonzero_carrier_padding() { ... }
```

A machine-generated coverage report SHOULD list:

```text
requirement_id
implementing module/function
positive test
negative/boundary test
status
```

Codex verification should audit this mapping rather than rediscover the whole
design from prose.

## I-902 — Cheap-model implementation order

The implementation model SHOULD work in this order and avoid touching later
layers early:

```text
1 protocol constants + hashing
2 names + UA + owner keys
3 operation encodings
4 carrier
5 pure records + NameTree
6 Pending + RecentSpent
7 pure reducer
8 reorg journal/snapshot
9 BondProof verifier/prover
10 chain adapter
11 owned-note inventory
12 output-lock reconciliation
13 registration/update/release workflows
14 integration tests
15 vectors + conformance report
```

At the end of each numbered step:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Do not defer a failing earlier layer while implementing later functionality.

## I-903 — What Codex should verify

Use expensive review primarily for:

1. `CoppiceBondCircuit` soundness and unconstrained-witness mistakes;
2. integer/range constraints, especially freshness;
3. nullifier/tag derivation equivalence with native Orchard;
4. reducer transaction/block ordering;
5. `RecentSpent` retention theorem boundaries;
6. reorg equivalence to fresh replay;
7. compact/full candidate consistency and fail-closed behavior;
8. wallet pre-spend guard and lock reconstruction;
9. requirement-ID coverage;
10. byte-for-byte conformance vectors.

Do not spend expensive review on formatting, obvious getters, or mechanical
serde/database plumbing unless tests expose a discrepancy.

## I-904 — Definition of done

v1 implementation is complete only when:

- F-001 is frozen;
- all `P-*` normative vectors exist;
- all protocol/reducer tests pass;
- the BondProof positive/negative/boundary suite passes;
- reorg-to-fresh-replay property tests pass;
- real Zebra/Z3 carrier and lifecycle integration passes;
- output-lock reconstruction passes restore/reorg tests;
- requirement coverage has no unexplained gap;
- `cargo fmt`, `cargo clippy`, and `cargo test` pass.

Concrete wallets persist the reducer snapshot separately from secret-bearing
local registration intents. Pending intents MUST be reconstructed through the
canonical `PendingRegistration` constructor on load and the local file MUST be
treated as private wallet material. After normal wallet scanning, canonical
chain reconciliation updates the reducer first and then refreshes cached
canonical COMMIT heights. Before every ordinary proposal, the same concrete
wallet backend MUST reconcile active and pending Coppice output locks at the
next-block target height; the ordinary locked-input exclusion policy then keeps
those notes out of fee selection.

The enhanced reference `zcash-devtool` persists `Enabled`, `GuardOnly`, or
`Off` independently of reducer snapshots. Protected mode with missing or
unusable state fails closed until sync rebuilds from activation. Successful
sync reconciles locks for every account, and ordinary send, ordinary proposal,
and automatic PCZT proposal paths all pass through the same guard. Its
`wallet coppice` command group composes the library controllers with the normal
proposal/construction/storage/submission path for REGISTER/REVEAL, UPDATE,
RELEASE, canonical name payment, completion/abandonment, and explicit Break
Bond. Manual transparent-only PCZT construction does not select shielded bond
notes.


## I-905 — Specification readiness

The Coppice v1 protocol package is implementation-ready.

All freeze/completion gates are closed. In particular:

```text
BondProof source commit:
a9521cdf995ffcfd2627ddfdd750253512172d73

BondProof final/vector HEAD:
0c2c177487bb868c848eae4eef33b1b58d59fcfe

BOND_VK_ID:
a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc

P-OWNER-002 scalar:
901a508ef3ce3434c02d57c2b4087afbd3e4d7505bbcec10ea1e6e7194819b0c

P-OWNER-002 RedPallas VK:
4a2130d359513478362bf3c4e7d9c42ec501f6d62424db91d7ee6b66e8bf3da3
```

An implementation model MUST NOT change these values without creating a new
protocol version / explicit spec revision.
