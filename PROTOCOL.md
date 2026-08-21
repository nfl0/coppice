# Coppice protocol and developer guide

> Coppice is a cryptographically self-verifying Zcash namespace, built from private bond proofs, public nullifier liveness, and deterministic state derivation.

It maps human-readable names to Zcash Unified Addresses using ordinary Zcash transactions as the
authoritative history. The remaining sections specify the architecture, development workflow, and
experimental tooling in detail.

> **Status:** experimental reference implementation. The core protocol has been exercised with real Zcash testnet v6/Ironwood transactions, but Coppice is not production software and has not received an independent security audit.

## What Coppice demonstrates

The current implementation demonstrates a minimal naming lifecycle:

- `COMMIT` / `REVEAL` — hide a prospective registration until a prior-block commitment is mined,
  then claim the available name with an owner, Unified Address, and private ZEC bond proof.
- `UPDATE` — let the current owner change the name's Unified Address.
- `RELEASE` — let the current owner make the name available again.
- `TRANSFER_WITH_NEW_BOND` — move ownership and install a fresh private bond atomically. Setting
  the new owner to the current owner is the canonical rebond operation.
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

A fresh wallet first accumulates Ironwood nullifiers from the network's Ironwood activation, then
loads the authenticated Ironwood tree frontier immediately before Coppice activation and
reconstructs naming operations from that height. This ensures a pre-Coppice note spent before
Coppice activation cannot be reused as a registration bond. An
already-synced wallet may persist its own local derived state and resume from its last processed
chain position.

The wallet library retains a minimal local compact-effects journal. If a Zcash block predecessor
changes, callers rewind to the common ancestor and replay the replacement branch; this is derived
wallet state, not a portable snapshot or a new consensus mechanism.

No snapshot system is part of the current protocol.

The public Testnet V0 parameters are exposed as `coppice::config::TESTNET_V0`; wallet integrations
should not duplicate activation heights, tag widths, or bond thresholds. An integration skeleton
is available with `cargo run -p coppice --example wallet_replay`.

## Private ZEC bonds

A registration includes a Halo2 `BondProof` for a hidden Ironwood note.

The proof demonstrates, without revealing the note itself, that:

- the note is a valid Ironwood note;
- its commitment belongs to the supplied Ironwood commitment-tree root;
- the prover possesses the required spending authority;
- the note value is at least the required bond threshold;
- its canonical nullifier maps to the public `bond_tag`;
- the proof is bound to the Coppice name, initial address, owner, network, and registration context.

The note commitment, nullifier, exact value, tree position, receiver, and spending key remain private.

The current experimental minimum bond is **1 ZEC (100,000,000 zatoshis)**. The BondCircuit proves
the inclusive relation `note_value >= minimum`, so a note worth exactly 1 ZEC qualifies. This
replaces the earlier experimental Testnet V0 threshold of 500,000 zatoshis; proofs made against that earlier
minimum are intentionally not accepted by the current experimental semantics.

Replay accepts that proof only when the embedded root was independently derived by the wallet's
authenticated Zcash chain scanner. This prevents a proof against an attacker-chosen tree from
creating an unbacked registration.

The current bond tag is derived using a Pasta/Halo2-native Poseidon construction. When the bonded note is eventually spent, its ordinary Zcash nullifier becomes public. Coppice replay derives the same `bond_tag` and marks the corresponding name inactive.

## Transport

Coppice operations are carried inside ordinary encrypted Zcash memos sent to a deterministic public bulletin receiver.

Large operations are split across multiple memo frames. A txid-prefix tag allows wallets to identify candidate Coppice transactions without trial-decrypting every shielded output.

The implementation has demonstrated pre-authorization txid grinding:

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
│   └── coppice/          # protocol library, integration tests, and reference examples
├── test-vectors/
└── vendor/
    └── orchard/          # only if the BondCircuit API refactor is required
```

Wallet-specific UI, Flutter/FFI bindings, and networking integrations should live outside the core protocol crate.

The real PCZT pre-authorization grinding regression now lives directly in
`crates/coppice/tests/preauth_grind.rs`. Reference demos and deterministic vector tooling are
available without a separate harness crate:

```bash
cargo run -p coppice --example reference -- carrier-demo
cargo run -p coppice --example reference -- replay-demo
cargo run -p coppice --example reference -- bond-demo
cargo run -p coppice --example reference -- print-test-vectors
```

## Patched dependency APIs

The current implementation uses two explicitly documented non-consensus dependency changes: the vendored
Orchard BondCircuit/gadget refactor and a small librustzcash wallet-layer PCZT lifecycle hook used by
`coppice-cli`. See [`DEPENDENCY_PATCHES.md`](DEPENDENCY_PATCHES.md) for exact revisions, changed
files, rationale, integration consequences, and consensus-compatibility boundaries.

### Orchard dependency

The BondCircuit requires constrained Orchard/Ironwood circuit logic that upstream Orchard 0.15.3
does not expose. `vendor/orchard` therefore retains the exact small non-consensus refactor used by
the validated implementation. Its three affected source files and rationale are documented in
`vendor/orchard/COPPICE_PATCH.md`; Cargo selects it through `[patch.crates-io]`.

The Coppice implementation does **not** require a Zcash consensus change.

## Current validation

The implementation has demonstrated the following on real Zcash testnet transactions:

- bonded registration;
- owner-authorized update;
- second registration;
- ordinary spend of a bonded Ironwood note;
- automatic bond-spend invalidation during replay;
- owner-authorized release;
- REVEAL and TRANSFER_WITH_NEW_BOND carrying an embedded `BondProof` and `bond_tag`;
- replay verification of the proof and its registration bindings;
- local `resolve(name)` without externally supplied bond metadata.

The local test suite also covers deterministic replay and rejection of invalid bond proofs/bindings.

Exact test vectors and protocol byte semantics belong in [`REFERENCE.md`](REFERENCE.md) and `test-vectors/`, not this overview.

## Deferred protocol features

The current reference implementation intentionally does not implement:

- renewal;
- auctions;
- subnames;
- delegation;
- multi-owner/FROST policies;
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

The v1 candidate uses a prior-block commitment before reveal to prevent a mempool observer from
copying a cleartext registration and winning it with a higher-priority transaction. Chain order
remains authoritative when multiple independently valid reveals race. The new operation encoding
supersedes the earlier experimental direct-REGISTER encoding; a public deployment needs an explicit
new activation decision before treating this candidate as live.

## Development

Basic validation is:

```bash
cargo fmt --all -- --check
cargo test --workspace
```

If the vendored Orchard implementation is modified, its relevant upstream test suite should also remain passing.

## Experimental name-manager playground

`coppice-playground.sh` is experimental terminal tooling for the public Zcash testnet registry. It
uses the sibling `coppice-cli` checkout for wallet sync, transaction construction, proving,
signing, and broadcast, while all Coppice encoding and replay remains in the `coppice` crate.

```bash
git clone https://github.com/nfl0/coppice.git
git clone https://github.com/nfl0/coppice-cli.git
cd coppice
./coppice-playground.sh
```

The first run creates a dedicated encrypted testnet wallet under `.coppice-testnet-v0`, prints its
Unified Address, syncs, and replays Coppice from fixed activation height `4,288,414`. Fund that
address with TAZ from <https://zcashfaucet.jinolabs.xyz/>; faucet access is never automated.
REVEAL uses a real wallet-owned Ironwood note as its private bond and locks that note against
accidental fee selection. The wallet therefore also needs a separate spendable note for the
carrier transaction fee; a single-note test wallet may need one ordinary self-split transaction
and a confirmation before registering.

Automatic commands are deliberately small:

```bash
./coppice-playground.sh sync
./coppice-playground.sh status
./coppice-playground.sh register alice utest1...
# after COMMIT is mined, run the same command to publish REVEAL
./coppice-playground.sh register alice utest1...
./coppice-playground.sh resolve alice
./coppice-playground.sh names
./coppice-playground.sh pending
./coppice-playground.sh owner-key
./coppice-playground.sh update alice utest1...
./coppice-playground.sh release alice
./coppice-playground.sh watch
```

`names` displays the locally replayed registry with record status, owner, sequence, address, and
bond tag. `pending` shows commit/reveal registrations staged by this wallet, and `owner-key` prints
its canonical RedPallas owner key. Local state resumes on later runs. A fresh installation reconstructs it by replaying testnet from
the activation height. This is experimental tooling, not a production wallet.

## Local Z3 regtest playground

The minimal regtest playground runs the official external
[Z3](https://github.com/ZcashFoundation/z3) Zebra, Zaino, and Zallet stack with Podman Compose. Z3
is not vendored or patched. Keep sibling checkouts of `z3`, `coppice-cli`, and this repository,
then run:

```bash
cargo build --release --features regtest_support --manifest-path ../coppice-cli/Cargo.toml
./scripts/regtest-playground.sh
```

With no arguments, the playground resets the disposable regtest, starts Z3, runs the deterministic
multi-wallet lifecycle with explicit script-controlled mining, writes a timestamped log under
`logs/`, and stops Z3 even if the test fails. The same flow is available explicitly as
`./scripts/regtest-playground.sh test`.

For operator-controlled exploration instead, use:

```bash
./scripts/regtest-playground.sh start
./scripts/regtest-playground.sh status
./scripts/regtest-playground.sh mine 1
./scripts/regtest-playground.sh play
./scripts/regtest-playground.sh stop
```

The underlying lifecycle test can also be invoked directly, but unlike the no-argument wrapper it
leaves the stack running for diagnosis:

```bash
./scripts/regtest-multiwallet-test.sh --reset
```

This test script mines fixed block counts at explicit lifecycle boundaries and has no background
miner. Outside that test, `start` never mines and `mine COUNT` remains operator-controlled.

`start` creates or reuses three local regtest wallets under `.coppice-regtest/` after two explicit
bootstrap blocks, then starts Z3 through the installed `podman-compose`. It never mines. The Z3
regtest network upgrades activate at heights 1 and 2, and the local Zaino endpoint is
`127.0.0.1:28137`. The interactive flow switches among wallets and invokes the same Coppice
commit/reveal registration, UPDATE, RELEASE, and RESOLVE commands used by the public playground.
`mine` confirms
pending transactions only when explicitly invoked, then syncs all three wallets. On a fresh chain,
run `start`, `mine 2`, and `start` again; thereafter mine the activation and maturity blocks you
want. The default mining address is wallet 1 once it exists; use `COPPICE_REGTEST_MINER_ADDRESS`
when restarting the services to direct new coinbases elsewhere. Use the normal `coppice-cli`
send/shield commands to distribute test funds. `reset` removes only the local Z3 volumes and
`.coppice-regtest/` wallet state.

### Current funding observation

On this Zebra regtest setup, the generic transparent-input selector can choose a newer immature
coinbase output even when older rewards are mature. A first shield attempt can therefore be
rejected until the selected output receives 100 confirmations. Zaino currently reports this as a
generic backing-node error; Zebra's `sendrawtransaction` response exposes the useful
`immature transparent coinbase spend` detail. This is local wallet/test-harness friction, not a
Coppice protocol failure: mine enough blocks and retry before treating the result as a funded
Ironwood bond.

Z3 currently pins Zaino 0.6; the script overrides only that container image to the public Zaino
0.8 no-TLS image because 0.6 predates the Ironwood compact-sync enum used by `coppice-cli`.

To print newly replayed local activity, run:

```bash
./scripts/watch-regtest.py
```

The watcher polls only Zebra's block height. For each new block it invokes the existing Rust
`coppice-cli coppice watch --once` path, which performs candidate detection, transaction fetch,
memo decoding, and canonical replay through Zaino. It prints COMMIT, REGISTER (successful REVEAL),
UPDATE, RELEASE, rejected
candidates, and observed bond spends with height and txid. Use `--once` for a single catch-up pass.

This is disposable developer infrastructure. Do not use its keys, activation height, reduced
8-bit local discovery tag, or chain as public protocol parameters.

## License

The Coppice crates are licensed under MIT OR Apache-2.0. Vendored dependencies retain their
upstream licenses.
