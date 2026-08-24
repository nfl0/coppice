# Coppice

Coppice is a pre-release deterministic application runtime over Zcash. Coppice
Names v1 is its first application.

The production path is:

```text
host-selected CompactBlocks
  -> candidate-only full transaction fetch
  -> coppice-core canonical replay and Ironwood checkpoints
  -> CPV1(CoreRuntimeId) -> CA01(ApplicationId, version)
  -> independently owned Coppice Names state/root/undo
```

Core performs no fork choice and contains no Names, bond, owner, address, or
operation semantics. See `docs/RUNTIME_ARCHITECTURE.md` for the stable crate and
wallet integration boundaries.

## Shielded protocol scope

Coppice v1 is Ironwood-only. Sapling notes/actions and notes/actions from the
pre-Ironwood Orchard protocol are not valid Coppice carriers, MUST NOT serve as
Coppice bonded notes, and MUST NEVER be interpreted as Coppice protocol state.

Coppice-aware wallets MAY still hold and spend Sapling and pre-Ironwood Orchard
funds through their normal Zcash wallet behavior. Those funds are simply outside
Coppice: they do not contribute Coppice state, carrier effects, or bond
protection. The Rust `orchard` crate is used for Ironwood cryptographic and
wallet machinery; its name does not expand Coppice v1 to the pre-Ironwood
Orchard protocol.

## Protocol authority

For development, use these sources in this order:

1. `docs/PROTOCOL_SPEC.md` — normative protocol
2. `test-vectors/` — normative interoperability vectors
3. `docs/IMPLEMENTATION.md` — implementation guidance
4. existing implementation behavior

Historical Coppice behavior is not protocol authority.

Before making changes, read `docs/CODEX_SESSION_ORIENTATION.md`.

## Development

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
```

Coppice is pre-release cryptographic software and has not been independently
audited for production use.

## License

MIT OR Apache-2.0.
