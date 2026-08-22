# Coppice v1 Normative Vector Manifest

This directory manifest defines the vectors that MUST exist before v1 is frozen.
Do not populate expected values by hand from guesses. Generate each expected
value from the frozen reference implementation, independently cross-check the
primitive where practical, then commit the JSON as immutable protocol evidence.

Required files:

```text
hashes.json
deployment.json
names.json
owner_keys.json
bond_tags.json
operations.json
carrier.json
records.json
name_tree.json
pending.json
recent_spent.json
state_roots.json
transitions.json
reorg.json
coppice_bond_v1.json
```

`carrier.json` freezes the indexed CPV1 transport: one-byte frame indices,
438/505-byte chunk capacities, permutation-independent reconstruction, and the
16,093-byte maximum payload.

Every vector entry SHOULD contain:

```json
{
  "id": "stable-human-readable-id",
  "requirement_ids": ["P-..."],
  "inputs": {},
  "expected": {},
  "valid": true
}
```

Invalid vectors additionally contain:

```json
{
  "expected_error": "TypedProtocolError"
}
```

`coppice_bond_v1.json` is part of freeze gate F-001 and MUST include:

- exact circuit/source identifier;
- `k = 11`;
- IPA parameter construction identifier;
- transcript identifier;
- canonical verifier/VK identifier;
- all seven public inputs as canonical 32-byte field encodings;
- accepted proof bytes;
- proof byte length;
- one mutation failure for every public input;
- `position == floor`;
- `position == floor - 1`;
- below-minimum-value failure;
- bad Merkle path/root failure;
- wrong spend-authority failure.

The conformance harness MUST consume these files without regenerating expected
values during the test run.
