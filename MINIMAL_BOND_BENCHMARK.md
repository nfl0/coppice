# Minimal Coppice BondCircuit benchmark

Measured 2026-08-22 in release mode on the same Ryzen 7 5800X Linux host as the
existing IPA baseline. The dedicated circuit remains Halo2 IPA over Vesta and
uses the existing vendored Orchard gadgets unchanged.

## Result

| Metric | Old Action-derived | Dedicated, smallest | Dedicated, parallel Merkle |
|---|---:|---:|---:|
| Minimum working `k` | 11 | 12 | 11 |
| Proof bytes | 5,024 B | 4,672 B | 4,960 B |
| Public inputs | 10 | 7 | 7 |
| Advice columns | 10 | 10 | 10 |
| Fixed columns | 14 | 13 | 14 |
| Instance columns | 1 | 1 | 1 |
| Lookup arguments | 3 | 2 | 3 |
| Permutation equality columns | 15 | 15 | 15 |
| Permutation product sets | 3 | 3 | 3 |
| Prove time | 439.6 ms | 585.4 ms | 393.078 ms |
| Verify time | 4.3 ms | 7.5 ms | 4.968 ms |
| Peak RSS | 89,920 KiB | 155,008 KiB | 88,344 KiB |

Column and argument counts come from Halo2's pinned constraint system after
selector compression. Both circuits have degree 9; the 15 equality-enabled
columns are split into three permutation product sets of at most seven columns.
The dedicated timings are the arithmetic mean of ten prove/verify iterations
after one warm-up. The parallel-Merkle numbers are from the requested fresh
rerun with the same methodology. Peak RSS is Linux `VmHWM` for the test process
and includes fixture construction, parameter construction, key generation, the
lower-`k` probes, and proving.

The lower-size layout intentionally shares one Sinsemilla/Merkle configuration.
This removes one lookup argument and its selectors, but prevents the two-column
groups from packing Merkle levels side by side. Actual prove-and-verify probes
failed for `k = 9`, `10`, and `11`; `k = 12` passed.

The durable parallel-Merkle circuit uses the second existing Sinsemilla/Merkle
configuration to pack the Merkle levels side by side. It retains the complete
dedicated relation and all positive, negative, and floor-boundary tests. Actual
prove-and-verify probes failed at `k = 9` and `10`; `k = 11` passed. It saves 64
bytes (1.3%) versus the old Action-derived proof and is 288 bytes (6.2%) larger
than the smallest dedicated proof. Relative to the supplied old baseline, its
measured proving time is 10.6% lower, verification time is 15.5% higher, and
peak RSS is 1.8% lower.

## Proven relation

`CoppiceBondCircuit` contains only:

- the existing Orchard V3 note-commitment gadget;
- the existing Sinsemilla Merkle gadget over all 32 Ironwood levels, constrained
  to the public anchor;
- `CommitIvk`, address ownership, and `[ask] SpendAuthG = ak` using the existing
  Orchard ECC gadgets;
- the existing canonical Orchard nullifier derivation followed by the existing
  Coppice domain-separated Poseidon bond tag, constrained public;
- a canonical 64-bit range check for `value - public minimum`;
- a canonical 32-bit range check for `private position - public position_floor`;
  and
- public deployment/protocol, context, and owner bindings.

The following Action-only data and synthesis are absent: output note and output
commitment, `v_new`, value commitment and trapdoor, value-balance sign/magnitude,
`alpha`, randomized action key, `cmx`, enable-spend/enable-output flags, and the
Action cross-address flag/checks. The existing production `BondCircuit` remains
unchanged and continues to use its original fixture path.

The ten-advice/eight-explicit-fixed Orchard ECC configuration is the minimum
width imposed by the reused `EccChip`; rewriting that gadget was out of scope.
Selector compression raises the final fixed-column count from the eight
explicit columns to 13.

## Tests

The focused relation test covers:

- valid proof and verification;
- corrupted Merkle membership bound to the accepted anchor;
- a spend-authorizing key that does not match the note's validating key;
- value one unit below the public minimum;
- wrong deployment/protocol, context, owner, and bond-tag public inputs;
- `position == position_floor` passing; and
- `position == position_floor - 1` failing.

The fixture was factored, not recreated: both circuits consume the existing V3
wallet/note generation in `crates/coppice/src/bond.rs`. The boundary test places
that generated note at position 1 by preceding it with an ephemeral copy of the
same canonical leaf.

Validation commands:

```text
cargo test -p coppice minimal_bond_relation_positive_and_negative --release -- --nocapture
cargo test -p coppice minimal_bond_benchmark --release -- --ignored --nocapture
cargo test -p coppice --release --no-fail-fast
```

The full suite result was 25 passed, 0 failed, 1 ignored (the manual benchmark),
plus 0 doc-test failures.

## Recommendation

The durable parallel-Merkle layout is the better operational tradeoff: it retains
`k = 11`, slightly reduces proof size and peak RSS versus the old circuit, and
proves faster in this rerun. Its proof-size reduction is only 64 bytes, while
verification is slightly slower. The smallest dedicated layout saves more bytes
but requires `k = 12` and materially more time and memory. Keep both as
benchmark-only evidence; do not replace the production bond proof on these
measurements alone.
