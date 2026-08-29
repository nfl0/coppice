# Coppice

Coppice is a deterministic application runtime over canonical Zcash Ironwood
history. It is application-blind: Zcash remains chain and fork-choice
authority, while native applications consume one validated canonical scan.

Applications are deterministic native state machines. Their payloads may carry
application-specific proofs, signatures, commitments, Merkle data, or ordinary
fields; the application interprets and verifies those bytes as part of its own
transition rules. Core remains proof-system agnostic and does not become a
ZKVM, proof verifier, or second consensus layer.

Core provides authenticated Ironwood replay, exact-receiver compact candidate
detection, CPV1 transport, CA01 application routing, isolated application
lifecycles, bounded rewind, snapshots, and a static multi-application
compositor. It is not a blockchain, smart-contract VM, gas environment, or
application registry.

The Rust workspace uses the released Zakura cryptography packages
(`zakura-orchard`, `zakura-primitives`, and `zakura-client-backend`) as one
coherent Orchard type family. Coppice does not add a second consensus or
transaction implementation; the package aliases preserve the usual
`orchard`, `zcash_primitives`, and `zcash_client_backend` library names for
callers. A Names-specific Orchard extension is maintained separately and is
only patched into applications that opt into that feature.

## Crates

```text
coppice-core          canonical replay, CPV1/CA01, application contracts,
                      compositor, persistence metadata, typed Ironwood effects
coppice               public runtime facade and small deterministic testkit
coppice-librustzcash  compact-block adapter and selective full-transaction host boundary
coppice-zcash-rpc     native zcashd-compatible JSON-RPC server adapter
```

## Server integrations

The recommended server deployment is a normal Zakura (or sufficiently
compatible Zcash full node) connected through standard JSON-RPC:

```text
Zcash full node (Zakura reference implementation)
  -> standard JSON-RPC
  -> coppice-zcash-rpc
  -> CoppiceRuntime<Apps>
```

No modified consensus node and no Coppice-aware node behavior are required.
Zakura remains canonical fork-choice authority; JSON-RPC is an untrusted
transport boundary and the adapter validates its replies before passing
canonical facts to the existing runtime path.

`coppice-librustzcash` remains supported for compact/light-client or
bandwidth-efficient synchronization:

```text
Zcash full node -> Zaino/lightwalletd -> coppice-librustzcash -> CoppiceRuntime<Apps>
```

Zaino/lightwalletd is therefore optional for a server running beside a full
node, not a prerequisite. See [the RPC compatibility contract](docs/ZCASH_RPC.md).

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
[Core protocol](docs/PROTOCOL_SPEC.md), [implementation guide](docs/IMPLEMENTATION.md),
and [the generalization proposal](docs/GENERALIZATION_PROPOSAL.md).

## Status

This is pre-release cryptographic software. No public deployment or security
audit is claimed by this repository.

## License

MPL-2.0.
