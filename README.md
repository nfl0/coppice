# Coppice

Coppice is a pre-release adminless naming protocol built on Zcash.

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
