# Coppice v1 vector audit

## BondProof vector

Supplied `coppice_bond_v1.json` reports:

```text
source circuit commit = a9521cdf995ffcfd2627ddfdd750253512172d73
final/vector HEAD      = cf9f7102ddec7f6fb6133b2299a11e71e9ffc8ce
halo2_proofs           = 0.3.2
k                      = 11
proof bytes            = 4960
BOND_VK_ID              = d9e24e9de209f3256b4e3b7d0c681211792677bd3a6398bf6079cc2c581c0af3
```

Independent checks performed while assembling this package:

```text
hex-decoded accepted proof length == 4960             PASS
declared proof_length == decoded length                PASS
BLAKE2b-256 CoppiceBondV1(verifier_artifact) == ID     PASS
accepted == true                                       PASS
7/7 public-input mutations accepted == false           PASS
position == floor                                      PASS
position == floor - 1                                  FAIL as required
```

The returned circuit's actual public-input order is now normative:

```text
0 anchor
1 minimum_value
2 position_floor
3 protocol_binding
4 context_binding
5 owner_binding
6 bond_tag
```

This differs from the provisional order in the pre-freeze specification; the
specification has been corrected to follow the frozen durable circuit.

## Bond-tag vector

The supplied v1 vector is retained verbatim in `test-vectors/bond_tags.json`.

## Owner-key vector

The supplied file is retained as
`test-vectors/owner_keys_redpallas_reference.json`. It is not substituted for
the v1 P-OWNER-002 KDF vector because it starts from an already-selected Pallas
scalar and therefore does not test the new keyed BLAKE2b-512 derivation.

## Owner-key KDF completion

The P-OWNER-002 KDF fixture was completed by a focused native Rust test using the
repository's pinned dependencies.

```text
expected_pallas_scalar_hex =
901a508ef3ce3434c02d57c2b4087afbd3e4d7505bbcec10ea1e6e7194819b0c

expected_redpallas_verification_key_hex =
4a2130d359513478362bf3c4e7d9c42ec501f6d62424db91d7ee6b66e8bf3da3

test = PASS
```

This closes the final vector-completeness item.
