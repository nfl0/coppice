# Coppice

Coppice is a pre-release adminless naming protocol built on Zcash.

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
