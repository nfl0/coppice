# Coppice v1 Freeze / Completion Gates

## F-001 — BondProof verifier identity — CLOSED

Frozen source circuit commit:

```text
a9521cdf995ffcfd2627ddfdd750253512172d73
```

Reported vector/final HEAD:

```text
cf9f7102ddec7f6fb6133b2299a11e71e9ffc8ce
```

Frozen parameters:

```text
halo2_proofs = 0.3.2
Params::<vesta::Affine>::new(11)
Halo2 IPA / Vesta
Blake2bRead / Blake2bWrite + Challenge255
proof length = 4960
BOND_VK_ID = d9e24e9de209f3256b4e3b7d0c681211792677bd3a6398bf6079cc2c581c0af3
```

Normative vector: `test-vectors/coppice_bond_v1.json`.

Independent package audit recomputed `BOND_VK_ID` from the supplied verifier
artifact and confirmed an exact match. It also confirmed the proof byte count,
all seven failed public-input mutations, and the two position-floor boundaries.

## C-001 — deterministic default owner-key KDF vector — CLOSED

The v1 P-OWNER-002 fixture is now complete.

Native Rust outputs:

```text
expected_pallas_scalar_hex =
901a508ef3ce3434c02d57c2b4087afbd3e4d7505bbcec10ea1e6e7194819b0c

expected_redpallas_verification_key_hex =
4a2130d359513478362bf3c4e7d9c42ec501f6d62424db91d7ee6b66e8bf3da3
```

The focused native Rust recomputation test passed.

## Final status

All Coppice v1 protocol freeze gates and conformance-vector completion gates are
closed.

No protocol architecture, cryptographic constant, proof identity, or normative
test-vector value remains intentionally unresolved.
