# Contributing to Coppice

Thank you for helping improve Coppice. Start with the [README](README.md),
then read the [protocol specification](docs/PROTOCOL_SPEC.md) and the
[runtime architecture](docs/RUNTIME_ARCHITECTURE.md) before changing behavior.

## Authority and change classes

The project follows this order:

```text
docs/PROTOCOL_SPEC.md
    > test-vectors/
    > docs/IMPLEMENTATION.md
    > implementation behavior and historical material
```

Protocol-sensitive changes include bytes, identities, cryptographic domains,
carrier rules, state-transition order, rejection/fatal boundaries, and rewind
semantics. They require an explicit protocol decision, an exact semantic review,
and updated normative vectors only when the protocol version or frozen oracle
is intentionally changed. Never edit vector outputs by hand or make a prose
cleanup silently change implementation semantics.

Implementation-only changes include documentation, diagnostics, adapter
plumbing, persistence wrappers, and wallet integration that preserve the
specified inputs and outputs. Keep the dependency direction intact:

```text
coppice-core -> generic Core Runtime
coppice      -> Core + Coppice Names v1
coppice-librustzcash -> Core + Names + host wallet integration
```

Core must remain application-blind. Applications must not share mutable state,
roots, or undo journals. Wallet policy and account data stay outside the
deterministic Core state machine.

## Normal workflow

1. Inspect the current tree and the relevant source before editing.
2. Read the authoritative specification and relevant vectors.
3. Keep the change narrow and explain any authority or compatibility impact.
4. Run `git diff --check` and lightweight link/path or search checks for docs.
5. For Rust or executable changes, run the smallest relevant focused checks;
   use the locked workspace suite when the change warrants it.
6. Report what actually ran. Do not present skipped, interrupted, or local-only
   qualification as an audit or public deployment.

Markdown should use repository-relative links, stable headings, and precise
terms such as `CoreRuntimeId`, `ApplicationId + application_version`,
`NamesDeploymentId`, Coppice Core / Core Runtime, and Coppice Names v1. Avoid a
naked “deployment ID”, “registry”, “reducer”, or “Coppice operation” when the
Core-versus-Names scope matters.

There is deliberately no deployment guide in this repository yet. Network
choice, activation height, rollout, public endpoints, and operational policy
remain future packaging and deployment decisions.
