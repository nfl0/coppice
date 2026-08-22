# Coppice v1 Implementation Handoff

The specification is frozen enough for implementation.

Read in this order:

```text
1. PROTOCOL_SPEC.md
2. test-vectors/MANIFEST.md
3. test-vectors/*.json
4. IMPLEMENTATION.md
5. CHEAP_MODEL_BOOTSTRAP.md
```

Authority:

```text
PROTOCOL_SPEC.md
    >
normative test vectors
    >
IMPLEMENTATION.md
    >
legacy Coppice code/docs
```

Frozen cryptographic anchors:

```text
Bond circuit source commit:
a9521cdf995ffcfd2627ddfdd750253512172d73

Vector/final HEAD:
cf9f7102ddec7f6fb6133b2299a11e71e9ffc8ce

Halo2:
0.3.2 / IPA Vesta / k=11 / Blake2b+Challenge255

BOND_VK_ID:
d9e24e9de209f3256b4e3b7d0c681211792677bd3a6398bf6079cc2c581c0af3

Owner KDF scalar:
901a508ef3ce3434c02d57c2b4087afbd3e4d7505bbcec10ea1e6e7194819b0c

Owner RedPallas SpendAuth VK:
4a2130d359513478362bf3c4e7d9c42ec501f6d62424db91d7ee6b66e8bf3da3
```

Implementation policy:

- reuse `vendor/orchard` cryptographic gadgets;
- preserve the frozen dedicated parallel-Merkle BondCircuit;
- legacy application/state code may be rewritten freely;
- no protocol redesign;
- every `P-*` requirement must map to implementation + tests;
- vectors are oracles, not examples;
- do not regenerate expected vector values during conformance tests.

Recommended model split:

```text
cheaper implementation model:
    mechanical implementation + test fixing

Codex:
    only final adversarial audit of crypto, reorgs, wallet safety,
    reducer ordering, and requirement coverage
```
