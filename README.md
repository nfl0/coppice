# Coppice 🪵

**Coppice** is an experimental, adminless naming protocol for Zcash.

It maps human-readable names to Zcash Unified Addresses using ordinary Zcash transactions as the authoritative history. Coppice has no registry administrator, no separate blockchain, and no required Zcash consensus changes.

> **Status:** proof of concept. The core protocol has been exercised with real Zcash testnet v6/Ironwood transactions, but Coppice is not production software and has not received an independent security audit.

## What Coppice demonstrates

The current POC demonstrates a minimal naming lifecycle:

- `REGISTER` — claim an available name, set an owner and Unified Address, and attach a private ZEC bond proof.
- `UPDATE` — let the current owner change the name's Unified Address.
- `RELEASE` — let the current owner make the name available again.
- **Bond-spend invalidation** — if the ZEC note backing a registration is later spent, replay detects its nullifier and the name becomes inactive automatically.

The intended wallet model is deliberately simple:

```text
Zcash chain from Coppice activation height
        |
        v
compact sync data (txid + Ironwood effects)
        |
        +-- txid does not match Coppice tag --> continue
        |
        `-- txid matches Coppice tag
                |
                v
          fetch full transaction
                |
                v
          decrypt/reassemble Coppice memo
                |
                v
       deterministic Coppice replay
                |
        +-------+--------+
        |                |
        v                v
    NameTree        SpentTagTree
        \                /
         \              /
          v            v
           local resolution
```

A fresh wallet can reconstruct Coppice state by replaying Zcash history from the protocol's activation height. An already-synced wallet may persist its own local derived state and resume from its last processed chain position.

No snapshot system is part of the current protocol POC.

## Private ZEC bonds

A registration includes a Halo2 `BondProof` for a hidden Ironwood note.

The proof demonstrates, without revealing the note itself, that:

- the note is a valid Ironwood note;
- its commitment belongs to the supplied Ironwood commitment-tree root;
- the prover possesses the required spending authority;
- the note value is at least the required bond threshold;
- its canonical nullifier maps to the public `bond_tag`;
- the proof is bound to the Coppice registration context.

The note commitment, nullifier, exact value, tree position, receiver, and spending key remain private.

The current bond tag is derived using a Pasta/Halo2-native Poseidon construction. When the bonded note is eventually spent, its ordinary Zcash nullifier becomes public. Coppice replay derives the same `bond_tag` and marks the corresponding name inactive.

## Transport

Coppice operations are carried inside ordinary encrypted Zcash memos sent to a deterministic public bulletin receiver.

Large operations are split across multiple memo frames. A txid-prefix tag allows wallets to identify candidate Coppice transactions without trial-decrypting every shielded output.

The POC has demonstrated pre-authorization txid grinding:

```text
construct fixed transaction effects
        |
vary only transport nonce / memo encryption
        |
find desired txid prefix
        |
prove once
        |
sign once
        |
finalize
```

No Halo2 proof generation or transaction signing is performed inside the grinding loop.

## Derived state

Coppice has no authoritative external database.

The authoritative history is the ordered Zcash chain data. Wallets deterministically derive current Coppice state from that history.

The current reference implementation maintains:

- **NameTree** — authenticated sparse tree keyed by canonical name identifiers.
- **SpentTagTree** — authenticated state recording bond tags whose underlying Ironwood nullifiers have appeared.

Name resolution is local once replay has caught up:

```text
resolve(name)
    |
    v
NameRecord
    |
    +-- released -----------------> Released / available
    |
    `-- active
          |
          v
      bond_tag in SpentTagTree?
          |
      +---+---+
      |       |
     yes      no
      |       |
      v       v
   Inactive  Active -> Unified Address
```

The resolver does not require the caller to supply a bond tag; the verified tag is part of the authenticated name record.

## Repository layout

The standalone repository keeps the protocol implementation reusable by Zcash wallets while keeping development tooling separate.

Layout:

```text
coppice/
├── Cargo.toml
├── README.md
├── REFERENCE.md
├── crates/
│   ├── coppice/          # reusable protocol/library crate
│   └── coppice-poc/      # POC, tests, and development harness
├── test-vectors/
└── vendor/
    └── orchard/          # only if the BondCircuit API refactor is required
```

Wallet-specific UI, Flutter/FFI bindings, and networking integrations should live outside the core protocol crate.

## Orchard dependency

The BondCircuit requires constrained Orchard/Ironwood circuit logic that upstream Orchard 0.15.3
does not expose. `vendor/orchard` therefore retains the exact small non-consensus refactor used by
the validated POC. Its three affected source files and rationale are documented in
`vendor/orchard/COPPICE_PATCH.md`; Cargo selects it through `[patch.crates-io]`.

The Coppice POC does **not** require a Zcash consensus change.

## Current validation

The POC has demonstrated the following on real Zcash testnet transactions:

- bonded registration;
- owner-authorized update;
- second registration;
- ordinary spend of a bonded Ironwood note;
- automatic bond-spend invalidation during replay;
- owner-authorized release;
- REGISTER carrying an embedded `BondProof` and `bond_tag`;
- replay verification of the proof and its registration bindings;
- local `resolve(name)` without externally supplied bond metadata.

The local test suite also covers deterministic replay and rejection of invalid bond proofs/bindings.

Exact test vectors and protocol byte semantics belong in [`REFERENCE.md`](REFERENCE.md) and `test-vectors/`, not this overview.

## Non-goals of the minimal POC

The current POC intentionally does not implement:

- name transfer;
- rebonding or renewal;
- auctions;
- subnames;
- delegation;
- multi-owner/FROST policies;
- commit/reveal registration;
- expiration;
- governance or treasury logic;
- recursive whole-history proofs;
- snapshots;
- PIR/Tor lookup infrastructure;
- wallet-specific UI integrations.

These may be explored later after the standalone reference implementation is preserved.

## Security and trust model

Coppice aims for protocol state that is reproducible from Zcash itself:

```text
authoritative history = Zcash chain
derived registry state = deterministic Coppice replay
remote indexers = optional convenience, not authority
```

A wallet that independently replays from the Coppice activation height does not need to trust a registry server for name state.

Coppice is experimental cryptographic software. The POC and any vendored cryptographic-library changes require independent review before production use.

## Development

Basic validation is:

```bash
cargo fmt --all -- --check
cargo test --workspace
```

If the vendored Orchard implementation is modified, its relevant upstream test suite should also remain passing.

## License

The Coppice crates are licensed under MIT OR Apache-2.0. Vendored dependencies retain their
upstream licenses.
