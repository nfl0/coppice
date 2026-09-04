# ADR 0002: Host-owned transactions for large application state

Status: Accepted for the undeployed Core protocol

Date: 2026-09-04

## Context

The clone-staged `CoppiceRuntime` gives small applications a clear atomic block
boundary, but cloning a million-record state machine per block is not a viable
storage architecture. Core must not choose SQLite or any other database, and a
Names-only transaction cannot atomically cover wallet scan state or the host's
canonical tip.

## Decision

Core retains `CoppiceApplication` and `CoppiceRuntime` for small applications.
It additionally defines:

- `TransactionHost`, whose higher-ranked closure owns commit and rollback and
  prevents a borrowed transaction from escaping;
- `TransactionalCoppiceApplication<Tx>`, whose mutable state is accessed only
  through the host transaction; and
- staged Core advancement and rewind, prepared against an exact base tip and
  published in memory only after durable host commit.

The host owns one outer transaction for a bounded sync batch. It uses one
savepoint per block. A deterministic block failure may commit the valid prefix
ending before that block; a storage, integrity, transaction, interruption, or
panic failure rolls back the outer transaction. After a panic the runtime is
poisoned and restarted. The host serializes runtime mutation, persists the
staged Core snapshot with the other layers, commits, and then performs the
base-tip-checked in-memory handoff.

Rollback journals have a host-selected retention depth no smaller than every
participating application's declared minimum. Journal rows are pruned only
after explicit host finalization. A reorganization beyond retained history
requires replay from an earlier authenticated checkpoint.

## Consequences

- Large state is updated record-by-record without application cloning.
- Wallet, Core, applications, derived indexes, and rollback metadata can share
  one storage-engine transaction without Core knowing its engine or schema.
- A committed database remains restart authority if the process stops between
  durable commit and the in-memory handoff.
- Hosts must treat a base-tip mismatch after durable commit as a fatal
  serialization bug and restart from durable state.

## Rejected alternatives

- **Make Core own SQLite:** couples consensus-neutral routing to one wallet
  database and prevents other hosts from supplying their own atomic boundary.
- **Let every application commit independently:** permits cross-layer split
  brain after an error or crash.
- **Automatically switch from clone to transaction mode:** makes performance
  and failure semantics depend on hidden thresholds instead of an explicit
  application choice.
