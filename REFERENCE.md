# Coppice Reference State Machine v0

All integers are unsigned big-endian. `H` is SHA-256. Concatenation is written `||`. Domain
strings are the exact ASCII bytes shown, without a terminator.

## Scope and synchronization

V0 has exactly three operations: REGISTER, UPDATE, and RELEASE. The only automatic lifecycle
event is bond inactivity when the registered public bond tag appears in `SpentTagTree` after its
Ironwood nullifier is observed. Transfer, rebond, renewal, expiration, commit/reveal, governance,
and recursive history proofs are not part of v0.

A fresh wallet starts at the Coppice activation height and replays authenticated Zcash history in
order. An already-synced wallet may persist its own derived NameTree and SpentTagTree state and
resume at the next height. V0 defines no portable bootstrap-state format or distribution protocol.

Compact synchronization supplies each transaction ID and every Ironwood `nullifier` and `cmx`.
Only transactions whose IDs match the Coppice prefix require full transaction retrieval for memo
decryption.

## Constants and names

The protocol identifier is `COPPICE_POC_V1`; the POC network identifier is `poc-local`.
Names contain 1 through 63 ASCII bytes from `[a-z0-9-]`, with neither first nor last byte `-`.
`name_id = H("CoppiceName" || canonical_name_bytes)`. The 12-bit default candidate tag is a POC
test parameter, not a production parameter. Payloads are at most 16384 bytes and frame count is
1 through 32.

## Owner and record encoding

An owner key is the unique 32-byte RedPallas `VerificationKey<SpendAuth>` encoding accepted by
`TryFrom<[u8;32]>`. Invalid encodings are rejected. The 32-byte `bond_tag` is stored in the
authenticated record; resolvers never accept a caller-supplied tag. A record is:

```text
owner_key[32] || bond_tag[32] || sequence_u64 || status_u8 || address_len_u16 || address
```

Status is 1 for Active and 2 for Released. `previous_record_hash =
H("CoppiceRecordV1" || record_bytes)`.

Owner signature messages begin:

```text
"CoppiceOwnerSigV0" || u16(14) || "COPPICE_POC_V1" ||
u16(9) || "poc-local"
```

UPDATE appends `0x02 || name_id[32] || previous_sequence_u64 || next_sequence_u64 ||
previous_record_hash[32] || H(new_address)[32]`. RELEASE appends `0x03 || name_id[32] ||
previous_sequence_u64 || next_sequence_u64 || previous_record_hash[32]`. Signatures are canonical
64-byte RedPallas `Signature<SpendAuth>` encodings. Verification uses the owner key in the current
record.

## Operation encoding

Every variable byte string is `length_u16 || bytes`. No trailing bytes are allowed.

```text
REGISTER = 0x01 || name || owner_key[32] || bond_tag[32] || bond_anchor[32] ||
           bond_proof_as_bytestring || address
UPDATE   = 0x02 || name || next_sequence_u64 || new_address || signature_64_as_bytestring
RELEASE  = 0x03 || name || next_sequence_u64 || signature_64_as_bytestring
```

Unknown types, invalid names or keys, non-64-byte signatures, out-of-bounds lengths, truncation,
and trailing bytes are invalid.

## Memo frames

A frame is:

```text
"COPPICE_POC_V1"[14] || version_u8(1) || operation_id_u8(1) ||
frame_index_u8 || frame_count_u8 || payload_length_u16 || payload_hash[32] ||
transport_nonce_u64 || chunk_length_u16 || chunk
```

The header is 62 bytes; transport nonce occupies offsets 52 through 59 inclusive. Standard memo
padding after the declared chunk is all zero. Grinding changes only the transport nonce and the
resulting encrypted memo bytes. It never changes the logical payload, operation ID, payload hash,
or chunk bytes.

All decryptable bulletin frames in one transaction are collected and may appear in any Action
order. They must agree on operation ID, count, payload length, and payload hash; indexes must be
exactly `0..count-1` with no duplicate; concatenated length and SHA-256 must match. Exactly one
complete operation is permitted. Zero sets produce `CandidateNoOperation`; malformed, ambiguous,
or multiple sets are a deterministic no-op.

## Candidate tag

Interpret the canonical 32-byte `TxId` encoding from byte zero. The candidate tag is the first
`tag_bits` most-significant bits, in network byte order. V0 POC uses an all-zero tag and permits
1 through 16 bits. Untagged transactions are never memo-decrypted.

## Transitions

REGISTER succeeds only for an available canonical name whose embedded BondProof verifies against the
embedded `bond_anchor` and `bond_tag`, the supplied owner key, the registration name context, the
fixed POC network, and minimum value 500000 zatoshis. In addition, `bond_anchor` must be an
Ironwood root that the replaying wallet independently derived from authenticated Zcash history;
proof membership in an arbitrary caller-supplied root is never sufficient. The proof bytes are part of the canonical
REGISTER payload; only the verified tag is retained in the NameRecord. Invalid proofs and tag,
owner, name/context, network, minimum-value, or anchor mismatches deterministically reject the
operation without changing state. A name is available when absent, Released, or its current
`bond_tag` is present in SpentTagTree. The new registration's own tag must not already be spent.
A valid REGISTER replaces any available record and creates sequence 0, Active, with the supplied
owner, verified bond tag, and address. Resolution reads the tag from this authenticated record and
returns bond-inactive whenever it is present in SpentTagTree. UPDATE succeeds only for an existing
Active name with an unspent current bond, sequence exactly current plus one without overflow, and a
valid owner signature over the exact current record and new address. RELEASE has the same
existence, Active, unspent-bond, sequence and signature requirements and sets Released.
All invalid operations leave every state byte unchanged and return a typed audit rejection.

## NameTree

The key is `name_id`. Key bits are traversed most-significant bit first. Depth is 256. At depth
zero, `empty[0]=H("CoppiceNameEmptyV0")`; recursively `empty[i+1]=node(empty[i],empty[i])`.
`leaf(record)=H("CoppiceNameLeafV0" || previous_record_hash)` and
`node(left,right)=H("CoppiceNameNodeV0" || left[32] || right[32])`. Absence uses `empty[0]`.
Proofs contain exactly 256 sibling hashes, bottom-up, and therefore occupy 8192 bytes.

## SpentTagTree

The canonical 32-byte Ironwood nullifier is decoded with `pallas::Base::from_repr`; noncanonical
encodings are rejected and are never reduced. The exact 16 ASCII bytes `CoppiceBondTagV0` are
interpreted as a little-endian `u128` and injected into the Pallas base field (there is no
reduction). Using the reviewed `P128Pow5T3` Poseidon parameterization and `ConstantLength<2>` from
`halo2_gadgets 0.5`, `spent_tag_field = Poseidon(domain_field, nullifier_field)` and `spent_tag` is
the canonical 32-byte little-endian `to_repr()` of that field. The spent tag is itself the 256-bit sparse key. The tree uses
the NameTree algorithm with domains `CoppiceSpentEmptyV0`, `CoppiceSpentLeafV0`, and
`CoppiceSpentNodeV0`; a present leaf is `H(leaf_domain || spent_tag)`. Proofs are 8192 bytes.

## Replay and state commitment

Blocks are processed by ascending height and transactions by ascending `tx_index`. For each
transaction: parse canonical bytes; extract every Ironwood `cmx` and nullifier; insert every spent
tag; test the txid candidate prefix; decrypt/reconstruct at most one operation; then apply it.
Consequently, a nullifier in a transaction is visible before an operation in the same transaction.
Wallet integration records authenticated Ironwood roots before replaying registrations that may
refer to them. A REGISTER referring to an unknown root produces `UnknownBondAnchor` and is a no-op.

For the synthetic fixture context:

```text
CoppiceStateRoot = H(
  "CoppiceStateV0" || "poc-local" || height_u32 || fixture_block_id[32] ||
  NameTreeRoot[32] || SpentTagTreeRoot[32]
)
```

`fixture_block_id` is explicitly not a Zcash block hash. A production revision must define binding
to canonical chain identity. A candidate with no bulletin frame produces `CandidateNoOperation`;
a Coppice-prefixed but invalid frame set produces the typed `MalformedCarrier` rejection. Parser
failures and rejected operations are deterministic no-ops; Ironwood spent effects already applied
earlier in the transaction are not rolled back.

## Private BondCircuit POC

The non-recursive Halo2 circuit has one instance column with ten Pallas base-field elements:

```text
0 Ironwood anchor
1 minimum value B
2 protocol/network binding
3 registration context binding
4 external Coppice owner binding
5 bond_tag_field
6 zero (unused compatibility slot)
7 one (enableSpend)
8 one (enableOutput)
9 zero (disableCrossAddress)
```

The protocol/network binding is `Poseidon(field("CoppiceProtoV0"), field("poc-local"))`, where
`field(s)` zero-pads at the high end to 16 bytes, interprets the bytes as a little-endian `u128`,
and injects it into the Pallas base field. The registration context is
`Poseidon(field("CoppiceCtxV0"), Poseidon(lo128(name_id), hi128(name_id)))`; the owner binding uses
the same construction with domain `CoppiceOwnerV0` and the canonical 32-byte owner key. Both are
reconstructed by replay from REGISTER rather than accepted as independent fields. Context and owner
bindings are constrained into the proof and do not reveal the note's wallet key. The witness
contains the Orchard note, its full viewing-key material, `ask`, position and authentication path.
The reused Orchard constraints derive the commitment, root, address and canonical nullifier.
An additional fixed-base multiplication enforces `[ask] SpendAuthG = ak`. A 64-bit range check on
`value-B` proves the threshold. The bond-tag Poseidon relation is constrained to instance 5. The
old note commitment, nullifier, exact value, position, receiver, `ask`, and wallet keys are never
instance values.
