# Native application authoring

Coppice applications are deliberately narrow native components. They are
ordinary compiled, reviewable code that consumes canonical Core context and
maintains an application-owned deterministic state machine. This is not a
smart-contract platform.

## Application contract

An application declares:

- one exact non-empty application identity, producing an `ApplicationId`;
- an unsigned `application_version`, forming the routing key
  `ApplicationId + application_version`;
- an activation height no earlier than the Core runtime activation height;
- application-owned state, state root, snapshot representation, and rewind
  behavior.

Core carries the application envelope as `CA01` inside CPV1. It validates the
transport and route, then exposes an application-scoped context. Before the
application activates, the application receives canonical position but not
native Core effects or routed messages. A later application can activate
without changing `CoreRuntimeId` or another application's state.

## What an application can see

After activation, the context can contain canonical block metadata, ordered
transaction positions and IDs, validated Ironwood commitments and nullifiers,
candidate/full-transaction status, and the message routed to that application.
The application may interpret its own payload and use native Ironwood effects
as inputs to its transition. Core remains unaware of the payload semantics.

For example, a small native application could define conceptual messages:

```text
SET(key, value)    -> state[key] = value
DELETE(key)        -> remove state[key]
```

It would apply them in canonical transaction order, serialize keys and values
according to its own frozen specification, and derive its own root. This is a
conceptual example only; it does not add a generic key/value feature to Core.

## Isolation and rewind

Each application owns its mutable state, state root, snapshot layer, and undo
journal. Core and application state are staged and published atomically at a
successful block boundary. A fatal Core input or application invariant error
leaves the composed runtime unchanged; an ordinary application protocol
rejection is a deterministic application outcome while canonical Ironwood
effects still advance.

Rewind is requested against the host-selected canonical chain. Core and the
application must rewind to the same height and block hash. If the common
ancestor is outside retained history, the host adapter reports that a rebuild
from the configured activation checkpoint is required. Applications must make
fresh replay, rewind followed by replay, and persisted restoration converge on
the same root.

## Unsupported model

Applications must not:

- mutate Core ordering, fork choice, Ironwood validation, or another application;
- share mutable state, roots, or undo journals across applications;
- reinterpret an unknown route or malformed envelope as their own payload;
- add WASM, arbitrary contracts, gas accounting, contract calls, or
  application-defined consensus;
- use a remote registry or operator key as state authority.

Unknown `(ApplicationId, version)` routes are structurally valid but ignored by
an unrelated application. Malformed transport or envelopes are routed
rejections. Missing or inconsistent canonical Zcash input is a fatal host-input
boundary and must not be converted into an application no-op.

See [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md) for the frozen Core transport and
Names v1 application route, and [`RUNTIME_ARCHITECTURE.md`](RUNTIME_ARCHITECTURE.md)
for the implemented lifecycle trait and crate boundaries.
