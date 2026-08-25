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
- application-owned state, state root, snapshot representation, rewind
  behavior, and required rewind retention.

Core carries the application envelope as `CA01` inside CPV1. It validates the
transport and route, then exposes an application-scoped context. Before the
application activates, the application receives canonical position but not
native Core effects or routed messages. A later application can activate
without changing `CoreRuntimeId` or another application's state.

## What an application can see

After activation, the context contains canonical block metadata and ordered
transactions with validated Ironwood commitments and nullifiers. Each
transaction has only the payload routed to that application, or no payload.
Full transactions selectively acquired by the host also expose typed public
value commitments, randomized keys, flags, and bundle value balance. Core
remains unaware of payload semantics.

## Application-specific proofs and authorization

An application may put any deterministic protocol data in its routed payload,
including a proof verified by Halo2 or another proof system. The proof bytes
are opaque to Core. In `apply_block`, an application can decode its payload,
construct the public inputs it defines from `transaction.core()` and its own
state, invoke its own verifier, and apply the transition only when that
verification succeeds. Ordinary invalid operations or invalid proofs should
normally become an application-owned rejected outcome while `apply_block`
returns `Ok`; returning an application error is appropriate for a state or
context invariant failure and causes the compositor's staged block to remain
unpublished.

The generic context supplies the values needed to bind a proof to canonical
history:

- `ApplicationId` and application version are available from the application's
  own `ApplicationDescriptor`;
- `CoreRuntimeId` is available from the validated Core parameters and can be
  retained as application configuration when deployment or network separation
  matters;
- `txid`, `tx_index`, block position, and ordered compact `nf`/`cmx` values are
  available from the transaction context;
- `cv`, `rk`, bundle flags, and value balance are available from
  `ironwood_effects().extended()` after the application requests
  `ExtendedEffects`; and
- the routed payload supplies the proof bytes, operation discriminator, and
  application-specific public fields.

A protocol should freeze a domain-separated, canonical encoding of the subset
it needs. A typical binding may include a protocol-specific domain,
`CoreRuntimeId`, application ID/version, the exact `txid` and `tx_index`, an
action index plus the corresponding canonical effects, an operation
discriminator, and application public inputs. These are guidance, not a
universal required tuple: an application must choose fields that prevent the
replays relevant to its own protocol. Its state must also record whatever
application nonce, nullifier, operation identifier, or other anti-replay
condition the protocol requires. Core does not enforce any of those meanings.
No generic `ApplicationProofBinding` helper is required here: the existing
typed IDs and context values make the inputs available, while fixing a single
Core-owned tuple would either omit valid application designs or silently
dictate their proof semantics.

This boundary is independent of the proof system. Switching a verifier,
verification key, circuit version, signature scheme, or proof encoding is an
application protocol change; it does not require a Coppice Core change unless
the application also changes which canonical Core facts it requests.

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
journal. `CoppiceRuntime` stages Core and all hosted applications atomically at
a successful block boundary. A fatal Core input or application invariant error
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

Unknown `(ApplicationId, version)` routes and malformed transport/envelopes do
not become an unrelated application's payload. Missing or inconsistent
canonical Zcash input is a fatal host-input boundary and must not be converted
into an application no-op.

See [`RUNTIME_ARCHITECTURE.md`](RUNTIME_ARCHITECTURE.md) for the implemented
lifecycle, persistence, selective-observation, and composition boundaries.
