# Coppice

Coppice is a deterministic application runtime over canonical Zcash Ironwood
history. It is application-blind: Zcash remains chain and fork-choice
authority, while native applications consume one validated canonical scan.

Core provides authenticated Ironwood replay, exact-receiver compact candidate
detection, CPV1 transport, CA01 application routing, isolated application
lifecycles, bounded rewind, snapshots, and a static multi-application
compositor. It is not a blockchain, smart-contract VM, gas environment, or
application registry.

## Crates

```text
coppice-core          canonical replay, CPV1/CA01, application contracts,
                      compositor, persistence metadata, typed Ironwood effects
coppice               public runtime facade and small deterministic testkit
coppice-librustzcash  compact-block adapter and selective full-transaction host boundary
```

Applications declare their own `ApplicationKey`, activation, state root,
snapshot encoding, and retention needs. The compositor stages Core and every
application atomically, uses deterministic static application ordering, and
derives the effective common rewind horizon.

An active application receives canonical transaction metadata and Core's public
Ironwood effects, plus only the CA01 payload addressed to its exact key.
Pre-activation it receives position only. Unknown and malformed routes are
never exposed as another application's payload.

Full Ironwood transaction acquisition remains selective. When a validated full
transaction is available, Core also exposes typed per-action value commitments
and randomized keys plus bundle flags and value balance; no wallet-private
plaintext, viewing key, recipient, memo, or ownership information enters
deterministic state.

## Applications

[Coppice Names](../coppice-names/) is an external application repository. It
contains the Names protocol, state machine, bond/owner semantics, wallet
helpers, and normative vectors. Removing it does not remove the machinery
needed to build another Coppice application.

See [application authoring](docs/APPLICATION_AUTHORING.md) and
[runtime architecture](docs/RUNTIME_ARCHITECTURE.md), plus the normative
[Core protocol](docs/PROTOCOL_SPEC.md) and [implementation guide](docs/IMPLEMENTATION.md).

## Status

This is pre-release cryptographic software. No public deployment or security
audit is claimed by this repository.

## License

MIT OR Apache-2.0.
