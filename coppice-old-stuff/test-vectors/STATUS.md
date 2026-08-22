# Vector completion status

## Frozen / complete

- hashes.json
- deployment.json
- names.json
- operations.json
- carrier.json
- records.json
- name_tree.json
- pending.json
- recent_spent.json
- state_roots.json
- transitions.json
- reorg.json
- bond_tags.json
- coppice_bond_v1.json

`coppice_bond_v1.json` freezes the dedicated parallel-Merkle circuit at
source commit `a9521cdf995ffcfd2627ddfdd750253512172d73`, `k = 11`,
4,960 proof bytes, and:

```text
BOND_VK_ID = d9e24e9de209f3256b4e3b7d0c681211792677bd3a6398bf6079cc2c581c0af3
```

The package independently recomputed that identifier from the supplied verifier
artifact and got an exact match.

## Supplemental primitive vector

- owner_keys_redpallas_reference.json

This remains as a non-normative primitive cross-check.

## Owner KDF vector — complete

- owner_keys.json

The P-OWNER-002 native outputs are frozen as:

```text
pallas scalar =
901a508ef3ce3434c02d57c2b4087afbd3e4d7505bbcec10ea1e6e7194819b0c

RedPallas SpendAuth verification key =
4a2130d359513478362bf3c4e7d9c42ec501f6d62424db91d7ee6b66e8bf3da3
```

Focused native Rust test: PASS.

## Final vector-suite status

All required v1 vector categories in `MANIFEST.md` are now populated or
represented by a frozen normative vector file. No missing value has been guessed.
