# Coppice

Coppice is a deterministic application runtime over canonical Zcash history.
It lets a native application derive authenticated state from the Zcash chain
without creating a second blockchain or consensus layer.

The runtime uses Zcash because Zcash already supplies canonical ordering,
shielded transaction effects, and compact-block synchronization. Coppice adds
application routing and deterministic replay on top of that host history; it
does not choose forks or ask a registry operator to vouch for state.

## Coppice Names v1

Coppice Names v1 is the first application hosted by the runtime. It provides
bonded names with owner authorization and deterministic resolution. Its
application operations are `COMMIT`, `REVEAL`, `UPDATE`, and `RELEASE`.

The protocol name is the bare canonical label: `alice`. A wallet or user
interface may present that same name as `alice.zec`; the `.zec` suffix is
presentation-only and is not part of Names state, hashes, commitments, or
wire bytes.

## Runtime pipeline

```text
host-selected canonical Zcash CompactBlocks
    -> exact-receiver compact candidate classification
    -> full transaction fetch only for candidates
    -> txid and Ironwood-effect validation
    -> Coppice Core replay and native Ironwood effects
    -> CPV1(CoreRuntimeId) transport and CA01 routing
    -> application-scoped state, root, and rewind
    -> wallet resolution and protection policy
```

The exact configured rendezvous receiver matters at both carrier boundaries:
decryptability under the public Ironwood IVK alone is insufficient. Core
performs the same receiver-bound check for compact candidates and for the
authoritative full transaction extraction.

Coppice v1 uses Ironwood shielded notes/actions for carriers, bond notes, and
canonical shielded effects. Sapling and pre-Ironwood Orchard funds remain
ordinary Zcash wallet funds, but are outside Coppice state, carrier detection,
and bond protection.

## What Coppice is not

Coppice is not:

- a blockchain or alternative fork-choice system;
- a Zcash consensus change;
- a WASM, smart-contract, or arbitrary contract VM;
- a gas or protocol-fee execution environment;
- a custodial or remotely authoritative registry.

The generic layer is Coppice Core / Core Runtime: canonical replay, Ironwood
effects, CPV1 transport, CA01 routing, application lifecycle, and rewind
context. Names state and Names operations belong to Coppice Names v1.

## Status

The qualified/frozen executable baseline is Coppice
`1e9c886c9f0adbdde3a613f9a4bee0d8bdd3bff8`; current repository HEAD may include
documentation-only commits. The companion
`zcash-devtool` qualification baseline is `050994b796343ef46ef82273fd306e8c342a31c2`.
This is pre-release cryptographic software. There is currently no announced
public Coppice Testnet or Mainnet deployment and no independent security audit.
Local qualification evidence is described in [`docs/QUALIFICATION.md`](docs/QUALIFICATION.md).

## Authority

For protocol work, read [`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md) first,
then the normative [`test-vectors/`](test-vectors/), followed by
[`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md). Historical documents and
implementation behavior do not override the specification or vectors.

## Crate layout

```text
crates/coppice-core/          generic Core Runtime, identities, transport, replay
crates/coppice/               Coppice Names v1 application and state
crates/coppice-librustzcash/  wallet and CompactBlock integration
test-vectors/                 normative machine-readable interoperability vectors
docs/                         protocol, architecture, integration, and qualification docs
```

## Where to read next

- [Protocol specification](docs/PROTOCOL_SPEC.md) — normative bytes and state transitions
- [Runtime architecture](docs/RUNTIME_ARCHITECTURE.md) — Core/application boundaries
- [Coppice Names v1](docs/NAMES_V1.md) — conceptual Names model
- [Wallet integration](docs/WALLET_INTEGRATION.md) — host and wallet contract
- [Application authoring](docs/APPLICATION_AUTHORING.md) — native application model
- [Implementation guide](docs/IMPLEMENTATION.md) — code and crate mapping
- [Qualification](docs/QUALIFICATION.md) — deterministic and live evidence
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

## Development

For ordinary documentation changes, use the lightweight checks described in
`CONTRIBUTING.md`. For executable changes, the normal Rust checks are:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
```

## License

MIT OR Apache-2.0.
