use crate::envelope::{Operation, valid_name};
use crate::name_tree::{NameProof, prove, root, verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Active,
    Released,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub owner_pk: [u8; 32],
    pub bond_tag: [u8; 32],
    pub sequence: u64,
    pub address: Vec<u8>,
    pub status: Status,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoppiceState {
    pub names: BTreeMap<String, NameRecord>,
    #[serde(default, with = "commitment_map_serde")]
    pub commitments: BTreeMap<[u8; 32], ChainPosition>,
}

mod commitment_map_serde {
    use super::ChainPosition;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        value: &BTreeMap<[u8; 32], ChainPosition>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<[u8; 32], ChainPosition>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<([u8; 32], ChainPosition)>::deserialize(deserializer)?;
        let mut value = BTreeMap::new();
        for (commitment, position) in entries {
            if value.insert(commitment, position).is_some() {
                return Err(D::Error::custom("duplicate registration commitment"));
            }
        }
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    Applied,
    Rejected(TransitionRejectReason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionRejectReason {
    InvalidName,
    InvalidOwnerKey,
    DuplicateRegister,
    UnknownName,
    ReleasedName,
    InvalidSequence,
    OversizedAddress,
    InvalidBondProof,
    BondAlreadyInUse,
    BondSpent,
    InvalidSignature,
    DuplicateCommitment,
    UnknownCommitment,
    CommitmentNotMature,
    BondUnchanged,
}
impl CoppiceState {
    pub fn state_root(&self) -> [u8; 32] {
        root(&self.names)
    }
    pub fn prove_name(&self, n: &str) -> NameProof {
        prove(&self.names, n)
    }
    pub fn verify_name(&self, n: &str, r: Option<&NameRecord>, p: &NameProof) -> bool {
        verify(self.state_root(), n, r, p)
    }
    pub fn commitment_root(&self) -> [u8; 32] {
        let mut bytes = crate::constants::COMMITMENT_SET_DOMAIN.to_vec();
        bytes.extend_from_slice(&(self.commitments.len() as u32).to_be_bytes());
        for (commitment, position) in &self.commitments {
            bytes.extend_from_slice(commitment);
            bytes.extend_from_slice(&position.block_height.to_be_bytes());
            bytes.extend_from_slice(&position.tx_index.to_be_bytes());
        }
        Sha256::digest(bytes).into()
    }
}

pub fn registration_commitment(
    name: &str,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    bond_anchor: [u8; 32],
    address: &[u8],
    secret: [u8; 32],
) -> [u8; 32] {
    let mut bytes = crate::constants::REGISTRATION_COMMITMENT_DOMAIN.to_vec();
    bytes.extend_from_slice(&(crate::constants::PROTOCOL_ID.len() as u16).to_be_bytes());
    bytes.extend_from_slice(crate::constants::PROTOCOL_ID);
    bytes.extend_from_slice(&(crate::constants::NETWORK_ID.len() as u16).to_be_bytes());
    bytes.extend_from_slice(crate::constants::NETWORK_ID);
    bytes.extend_from_slice(&crate::owner::name_id(name));
    bytes.extend_from_slice(&owner_pk);
    bytes.extend_from_slice(&bond_tag);
    bytes.extend_from_slice(&bond_anchor);
    bytes.extend_from_slice(&Sha256::digest(address));
    bytes.extend_from_slice(&secret);
    Sha256::digest(bytes).into()
}
#[cfg(test)]
pub(crate) fn apply_operation(
    s: &mut CoppiceState,
    op: Operation,
    position: ChainPosition,
) -> Transition {
    apply_operation_with_spent(s, None, op, position)
}

/// Applies an operation against the complete authenticated registry state.
/// The spent-tag view is required for chain replay; the wrapper above remains
/// useful for isolated transition tests.
pub(crate) fn apply_operation_with_spent(
    s: &mut CoppiceState,
    spent: Option<&crate::spent::SpentTagTree>,
    op: Operation,
    position: ChainPosition,
) -> Transition {
    match &op {
        Operation::Commit { commitment } => {
            if s.commitments.contains_key(commitment) {
                return Transition::Rejected(TransitionRejectReason::DuplicateCommitment);
            }
            s.commitments.insert(*commitment, position);
            Transition::Applied
        }
        Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            bond_anchor,
            bond_proof,
            address,
            secret,
        } => {
            if !valid_name(name) {
                return Transition::Rejected(TransitionRejectReason::InvalidName);
            }
            if address.len() > crate::constants::MAX_PAYLOAD_LEN {
                return Transition::Rejected(TransitionRejectReason::OversizedAddress);
            }
            if crate::owner::parse_owner_key(*owner_pk).is_err() {
                return Transition::Rejected(TransitionRejectReason::InvalidOwnerKey);
            }
            let commitment =
                registration_commitment(name, *owner_pk, *bond_tag, *bond_anchor, address, *secret);
            let Some(committed_at) = s.commitments.get(&commitment).copied() else {
                return Transition::Rejected(TransitionRejectReason::UnknownCommitment);
            };
            let Some(maturity_height) = committed_at
                .block_height
                .checked_add(crate::constants::MIN_COMMIT_CONFIRMATIONS)
            else {
                return Transition::Rejected(TransitionRejectReason::CommitmentNotMature);
            };
            if position.block_height < maturity_height {
                return Transition::Rejected(TransitionRejectReason::CommitmentNotMature);
            }
            if spent.is_some_and(|tree| tree.contains(bond_tag)) {
                return Transition::Rejected(TransitionRejectReason::BondSpent);
            }
            if let Some(existing) = s.names.get(name) {
                let available = existing.status == Status::Released
                    || spent.is_some_and(|tree| tree.contains(&existing.bond_tag));
                if !available {
                    return Transition::Rejected(TransitionRejectReason::DuplicateRegister);
                }
            }
            if s.names.iter().any(|(other_name, record)| {
                other_name != name
                    && record.status == Status::Active
                    && record.bond_tag == *bond_tag
                    && !spent.is_some_and(|tree| tree.contains(&record.bond_tag))
            }) {
                return Transition::Rejected(TransitionRejectReason::BondAlreadyInUse);
            }
            if !crate::bond::verify_registration_bond(
                name,
                *owner_pk,
                *bond_tag,
                *bond_anchor,
                bond_proof,
                address,
            ) {
                return Transition::Rejected(TransitionRejectReason::InvalidBondProof);
            }
            s.names.insert(
                name.clone(),
                NameRecord {
                    owner_pk: *owner_pk,
                    bond_tag: *bond_tag,
                    sequence: 0,
                    address: address.clone(),
                    status: Status::Active,
                },
            );
            s.commitments.remove(&commitment);
            Transition::Applied
        }
        Operation::Update {
            name,
            sequence,
            address,
            ..
        } => {
            let Some(old) = s.names.get(name).cloned() else {
                return Transition::Rejected(TransitionRejectReason::UnknownName);
            };
            if old.status != Status::Active {
                return Transition::Rejected(TransitionRejectReason::ReleasedName);
            }
            if spent.is_some_and(|tree| tree.contains(&old.bond_tag)) {
                return Transition::Rejected(TransitionRejectReason::BondSpent);
            }
            if old.sequence.checked_add(1) != Some(*sequence) {
                return Transition::Rejected(TransitionRejectReason::InvalidSequence);
            }
            if address.len() > crate::constants::MAX_PAYLOAD_LEN {
                return Transition::Rejected(TransitionRejectReason::OversizedAddress);
            }
            if !crate::owner::verify_operation(old.owner_pk, &op, &old) {
                return Transition::Rejected(TransitionRejectReason::InvalidSignature);
            }
            if let Some(r) = s.names.get_mut(name) {
                r.sequence = *sequence;
                r.address = address.clone();
                Transition::Applied
            } else {
                Transition::Rejected(TransitionRejectReason::UnknownName)
            }
        }
        Operation::Release { name, sequence, .. } => {
            let Some(old) = s.names.get(name).cloned() else {
                return Transition::Rejected(TransitionRejectReason::UnknownName);
            };
            if old.status != Status::Active {
                return Transition::Rejected(TransitionRejectReason::ReleasedName);
            }
            if spent.is_some_and(|tree| tree.contains(&old.bond_tag)) {
                return Transition::Rejected(TransitionRejectReason::BondSpent);
            }
            if old.sequence.checked_add(1) != Some(*sequence) {
                return Transition::Rejected(TransitionRejectReason::InvalidSequence);
            }
            if !crate::owner::verify_operation(old.owner_pk, &op, &old) {
                return Transition::Rejected(TransitionRejectReason::InvalidSignature);
            }
            if let Some(r) = s.names.get_mut(name) {
                r.sequence = *sequence;
                r.status = Status::Released;
                Transition::Applied
            } else {
                Transition::Rejected(TransitionRejectReason::UnknownName)
            }
        }
        Operation::TransferWithNewBond {
            name,
            sequence,
            new_owner_pk,
            new_bond_tag,
            new_bond_anchor,
            new_bond_proof,
            address,
            ..
        } => {
            let Some(old) = s.names.get(name).cloned() else {
                return Transition::Rejected(TransitionRejectReason::UnknownName);
            };
            if old.status != Status::Active {
                return Transition::Rejected(TransitionRejectReason::ReleasedName);
            }
            if spent.is_some_and(|tree| tree.contains(&old.bond_tag)) {
                return Transition::Rejected(TransitionRejectReason::BondSpent);
            }
            if old.sequence.checked_add(1) != Some(*sequence) {
                return Transition::Rejected(TransitionRejectReason::InvalidSequence);
            }
            if old.bond_tag == *new_bond_tag {
                return Transition::Rejected(TransitionRejectReason::BondUnchanged);
            }
            if address.len() > crate::constants::MAX_PAYLOAD_LEN {
                return Transition::Rejected(TransitionRejectReason::OversizedAddress);
            }
            if crate::owner::parse_owner_key(*new_owner_pk).is_err() {
                return Transition::Rejected(TransitionRejectReason::InvalidOwnerKey);
            }
            if spent.is_some_and(|tree| tree.contains(new_bond_tag)) {
                return Transition::Rejected(TransitionRejectReason::BondSpent);
            }
            if s.names.iter().any(|(other_name, record)| {
                other_name != name
                    && record.status == Status::Active
                    && record.bond_tag == *new_bond_tag
                    && !spent.is_some_and(|tree| tree.contains(&record.bond_tag))
            }) {
                return Transition::Rejected(TransitionRejectReason::BondAlreadyInUse);
            }
            if !crate::owner::verify_operation(old.owner_pk, &op, &old) {
                return Transition::Rejected(TransitionRejectReason::InvalidSignature);
            }
            if !crate::bond::verify_registration_bond(
                name,
                *new_owner_pk,
                *new_bond_tag,
                *new_bond_anchor,
                new_bond_proof,
                address,
            ) {
                return Transition::Rejected(TransitionRejectReason::InvalidBondProof);
            }
            if let Some(record) = s.names.get_mut(name) {
                record.owner_pk = *new_owner_pk;
                record.bond_tag = *new_bond_tag;
                record.sequence = *sequence;
                record.address = address.clone();
                Transition::Applied
            } else {
                Transition::Rejected(TransitionRejectReason::UnknownName)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{OwnerSigningKey, owner_key_bytes, sign_operation};
    fn authorize_reveal(state: &mut CoppiceState, operation: &Operation, height: u32) {
        let Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            bond_anchor,
            address,
            secret,
            ..
        } = operation
        else {
            return;
        };
        state.commitments.insert(
            registration_commitment(name, *owner_pk, *bond_tag, *bond_anchor, address, *secret),
            ChainPosition {
                block_height: height.saturating_sub(1),
                tx_index: 0,
            },
        );
    }
    #[test]
    fn commit_reveal_update_release() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let mut s = CoppiceState::default();
        let x = Operation::Reveal {
            name: "alice".into(),
            owner_pk,
            bond_tag: bond.bond_tag,
            bond_anchor: bond.anchor,
            bond_proof: bond.proof.clone(),
            address: b"UA_A".to_vec(),
            secret: [7; 32],
        };
        authorize_reveal(&mut s, &x, 1);
        assert_eq!(
            apply_operation(
                &mut s,
                x.clone(),
                ChainPosition {
                    block_height: 1,
                    tx_index: 0
                }
            ),
            Transition::Applied
        );
        assert_ne!(s.state_root(), [0; 32]);

        assert_ne!(
            apply_operation(
                &mut s,
                x,
                ChainPosition {
                    block_height: 1,
                    tx_index: 1
                }
            ),
            Transition::Applied
        );
        let previous = s.names["alice"].clone();
        let mut update = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA_B".to_vec(),
            signature: vec![],
        };
        if let Some(sig) = sign_operation(&key, &update, &previous) {
            if let Operation::Update { signature, .. } = &mut update {
                *signature = sig;
            }
        }
        assert_eq!(
            apply_operation(
                &mut s,
                update,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                }
            ),
            Transition::Applied
        );
        let previous = s.names["alice"].clone();
        let mut release = Operation::Release {
            name: "alice".into(),
            sequence: 2,
            signature: vec![],
        };
        if let Some(sig) = sign_operation(&key, &release, &previous) {
            if let Operation::Release { signature, .. } = &mut release {
                *signature = sig;
            }
        }
        assert_eq!(
            apply_operation(
                &mut s,
                release,
                ChainPosition {
                    block_height: 3,
                    tx_index: 0
                }
            ),
            Transition::Applied
        );
        assert_eq!(s.names["alice"].status, Status::Released)
    }

    #[test]
    fn rejected_owner_mutations_are_noops() {
        use rand_core::OsRng;
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner = owner_key_bytes(&(&key).into());
        let base = || {
            let mut s = CoppiceState::default();
            s.names.insert(
                "alice".into(),
                NameRecord {
                    owner_pk: owner,
                    bond_tag: [1; 32],
                    sequence: 0,
                    address: b"UA_A".to_vec(),
                    status: Status::Active,
                },
            );
            s
        };
        let previous = base().names["alice"].clone();
        let mut valid = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA_B".to_vec(),
            signature: vec![],
        };
        let sig = sign_operation(&key, &valid, &previous).unwrap();
        if let Operation::Update { signature, .. } = &mut valid {
            *signature = sig;
        }
        let mut variants = Vec::new();
        let mut x = valid.clone();
        if let Operation::Update { name, .. } = &mut x {
            *name = "bob".into()
        }
        variants.push(x);
        let mut x = valid.clone();
        if let Operation::Update { sequence, .. } = &mut x {
            *sequence = 2
        }
        variants.push(x);
        let mut x = valid.clone();
        if let Operation::Update { address, .. } = &mut x {
            *address = b"UA_X".to_vec()
        }
        variants.push(x);
        let mut x = valid.clone();
        if let Operation::Update { signature, .. } = &mut x {
            signature[0] ^= 1
        }
        variants.push(x);
        let mut altered = crate::owner::authorization_message(
            &Operation::Update {
                name: "alice".into(),
                sequence: 1,
                address: b"UA_B".to_vec(),
                signature: vec![],
            },
            &previous,
        )
        .unwrap();
        altered[0] ^= 1;
        let bad_sig = <[u8; 64]>::from(&key.sign(OsRng, &altered)).to_vec();
        let mut x = valid.clone();
        if let Operation::Update { signature, .. } = &mut x {
            *signature = bad_sig
        }
        variants.push(x);
        for op in variants {
            let mut s = base();
            let before = s.state_root();
            assert_ne!(
                apply_operation(
                    &mut s,
                    op,
                    ChainPosition {
                        block_height: 2,
                        tx_index: 0
                    }
                ),
                Transition::Applied
            );
            assert_eq!(before, s.state_root());
        }
        let other = OwnerSigningKey::try_from([2; 32]).unwrap();
        let mut wrong = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA_B".to_vec(),
            signature: vec![],
        };
        let sig = sign_operation(&other, &wrong, &previous).unwrap();
        if let Operation::Update { signature, .. } = &mut wrong {
            *signature = sig
        }
        let mut s = base();
        let before = s.state_root();
        assert_ne!(
            apply_operation(
                &mut s,
                wrong,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                }
            ),
            Transition::Applied
        );
        assert_eq!(before, s.state_root());
        let mut release = Operation::Release {
            name: "alice".into(),
            sequence: 1,
            signature: vec![],
        };
        if let Operation::Release { signature, .. } = &mut release {
            *signature = sign_operation(
                &key,
                &Operation::Release {
                    name: "alice".into(),
                    sequence: 1,
                    signature: vec![],
                },
                &previous,
            )
            .unwrap();
        }
        let mut as_update = valid.clone();
        if let (Operation::Update { signature: a, .. }, Operation::Release { signature: b, .. }) =
            (&mut as_update, &release)
        {
            *a = b.clone()
        }
        let mut s = base();
        let before = s.state_root();
        assert_ne!(
            apply_operation(
                &mut s,
                as_update,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                }
            ),
            Transition::Applied
        );
        assert_eq!(before, s.state_root());
    }

    #[test]
    fn owner_operation_helpers_use_the_next_sequence() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner = owner_key_bytes(&(&key).into());
        let previous = NameRecord {
            owner_pk: owner,
            bond_tag: [1; 32],
            sequence: 41,
            address: b"UA_A".to_vec(),
            status: Status::Active,
        };
        let update =
            crate::owner::signed_update(&key, "alice", b"UA_B".to_vec(), &previous).unwrap();
        assert!(crate::owner::verify_operation(owner, &update, &previous));
        assert!(matches!(update, Operation::Update { sequence: 42, .. }));
        let release = crate::owner::signed_release(&key, "alice", &previous).unwrap();
        assert!(crate::owner::verify_operation(owner, &release, &previous));
        assert!(matches!(release, Operation::Release { sequence: 42, .. }));
    }

    #[test]
    fn spent_bond_blocks_owner_actions_and_release_makes_name_available() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let bond = crate::bond::test_registration_bond("alice", b"UA_NEW");
        let mut state = CoppiceState::default();
        state.names.insert(
            "alice".into(),
            NameRecord {
                owner_pk,
                bond_tag: bond.bond_tag,
                sequence: 0,
                address: b"UA_A".to_vec(),
                status: Status::Active,
            },
        );
        let previous = state.names["alice"].clone();
        let mut update = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA_B".to_vec(),
            signature: vec![],
        };
        let update_signature = sign_operation(&key, &update, &previous).unwrap();
        if let Operation::Update { signature, .. } = &mut update {
            *signature = update_signature;
        }
        let mut spent = crate::spent::SpentTagTree::default();
        spent.insert_spent_tag(previous.bond_tag);
        let root = state.state_root();
        assert_eq!(
            apply_operation_with_spent(
                &mut state,
                Some(&spent),
                update,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Rejected(TransitionRejectReason::BondSpent)
        );
        assert_eq!(root, state.state_root());

        let spent_register = Operation::Reveal {
            name: "alice".into(),
            owner_pk,
            bond_tag: bond.bond_tag,
            bond_anchor: bond.anchor,
            bond_proof: bond.proof.clone(),
            address: b"UA_NEW".to_vec(),
            secret: [7; 32],
        };
        authorize_reveal(&mut state, &spent_register, 2);
        assert_eq!(
            apply_operation_with_spent(
                &mut state,
                Some(&spent),
                spent_register,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Rejected(TransitionRejectReason::BondSpent)
        );

        state.names.get_mut("alice").unwrap().status = Status::Released;
        let register = Operation::Reveal {
            name: "alice".into(),
            owner_pk,
            bond_tag: bond.bond_tag,
            bond_anchor: bond.anchor,
            bond_proof: bond.proof.clone(),
            address: b"UA_NEW".to_vec(),
            secret: [8; 32],
        };
        authorize_reveal(&mut state, &register, 3);
        assert_eq!(
            apply_operation_with_spent(
                &mut state,
                None,
                register,
                ChainPosition {
                    block_height: 3,
                    tx_index: 0
                },
            ),
            Transition::Applied
        );
        assert_eq!(state.names["alice"].sequence, 0);
        assert_eq!(state.names["alice"].address, b"UA_NEW");
    }

    #[test]
    fn one_unspent_bond_cannot_back_two_active_names() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let alice_bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let bob_bond = crate::bond::test_registration_bond("bob", b"UA_C");
        assert_ne!(alice_bond.bond_tag, bob_bond.bond_tag);
        let mut state = CoppiceState::default();
        state.names.insert(
            "alice".into(),
            NameRecord {
                owner_pk,
                bond_tag: bob_bond.bond_tag,
                sequence: 0,
                address: b"UA_A".to_vec(),
                status: Status::Active,
            },
        );
        let root = state.state_root();
        let register_bob = Operation::Reveal {
            name: "bob".into(),
            owner_pk,
            bond_tag: bob_bond.bond_tag,
            bond_anchor: bob_bond.anchor,
            bond_proof: bob_bond.proof.clone(),
            address: b"UA_C".to_vec(),
            secret: [7; 32],
        };
        authorize_reveal(&mut state, &register_bob, 2);
        assert_eq!(
            apply_operation_with_spent(
                &mut state,
                None,
                register_bob,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Rejected(TransitionRejectReason::BondAlreadyInUse)
        );
        assert_eq!(root, state.state_root());
    }

    #[test]
    fn commit_reveal_requires_a_prior_block_and_is_atomic() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let secret = [42; 32];
        let commitment = registration_commitment(
            "alice",
            owner_pk,
            bond.bond_tag,
            bond.anchor,
            b"UA_A",
            secret,
        );
        let reveal = Operation::Reveal {
            name: "alice".into(),
            owner_pk,
            bond_tag: bond.bond_tag,
            bond_anchor: bond.anchor,
            bond_proof: bond.proof.clone(),
            address: b"UA_A".to_vec(),
            secret,
        };
        let mut state = CoppiceState::default();
        assert_eq!(
            apply_operation(
                &mut state,
                Operation::Commit { commitment },
                ChainPosition {
                    block_height: 10,
                    tx_index: 0
                },
            ),
            Transition::Applied
        );
        let encoded = serde_json::to_vec(&state).unwrap();
        let decoded: CoppiceState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, state);
        let before = state.clone();
        assert_eq!(
            apply_operation(
                &mut state,
                reveal.clone(),
                ChainPosition {
                    block_height: 10,
                    tx_index: 1
                },
            ),
            Transition::Rejected(TransitionRejectReason::CommitmentNotMature)
        );
        assert_eq!(state, before);
        let mut wrong = reveal.clone();
        if let Operation::Reveal { secret, .. } = &mut wrong {
            secret[0] ^= 1;
        }
        assert_eq!(
            apply_operation(
                &mut state,
                wrong,
                ChainPosition {
                    block_height: 11,
                    tx_index: 0
                },
            ),
            Transition::Rejected(TransitionRejectReason::UnknownCommitment)
        );
        assert_eq!(state, before);
        assert_eq!(
            apply_operation(
                &mut state,
                reveal,
                ChainPosition {
                    block_height: 11,
                    tx_index: 1
                },
            ),
            Transition::Applied
        );
        assert!(state.commitments.is_empty());
        assert_eq!(state.names["alice"].address, b"UA_A");
    }

    #[test]
    fn transfer_installs_new_owner_and_fresh_bond() {
        let old_key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let old_owner = owner_key_bytes(&(&old_key).into());
        let old_bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let new_key = OwnerSigningKey::try_from([2; 32]).unwrap();
        let new_owner = owner_key_bytes(&(&new_key).into());
        let new_bond = crate::bond::test_registration_bond_with_owner_and_seed(
            "alice",
            new_owner,
            b"UA_TRANSFER",
            b"alice-transfer-note",
        );
        let previous = NameRecord {
            owner_pk: old_owner,
            bond_tag: old_bond.bond_tag,
            sequence: 0,
            address: b"UA_A".to_vec(),
            status: Status::Active,
        };
        let mut state = CoppiceState::default();
        state.names.insert("alice".into(), previous.clone());
        let transfer = crate::owner::signed_transfer_with_new_bond(
            &old_key,
            "alice",
            new_owner,
            new_bond.bond_tag,
            new_bond.anchor,
            new_bond.proof.clone(),
            b"UA_TRANSFER".to_vec(),
            &previous,
        )
        .unwrap();
        let mut tampered = transfer.clone();
        if let Operation::TransferWithNewBond { address, .. } = &mut tampered {
            *address = b"UA_TAMPERED".to_vec();
        }
        let before = state.clone();
        assert_eq!(
            apply_operation(
                &mut state,
                tampered,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Rejected(TransitionRejectReason::InvalidSignature)
        );
        assert_eq!(state, before);
        assert_eq!(
            apply_operation(
                &mut state,
                transfer,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Applied
        );
        let record = &state.names["alice"];
        assert_eq!(record.owner_pk, new_owner);
        assert_eq!(record.bond_tag, new_bond.bond_tag);
        assert_eq!(record.address, b"UA_TRANSFER");
        assert_eq!(record.sequence, 1);

        let mut old_spent = crate::spent::SpentTagTree::default();
        old_spent.insert_spent_tag(old_bond.bond_tag);
        let update =
            crate::owner::signed_update(&new_key, "alice", b"UA_AFTER".to_vec(), record).unwrap();
        assert_eq!(
            apply_operation_with_spent(
                &mut state,
                Some(&old_spent),
                update,
                ChainPosition {
                    block_height: 3,
                    tx_index: 0
                },
            ),
            Transition::Applied
        );
    }

    #[test]
    fn transfer_to_self_is_rebond() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner = owner_key_bytes(&(&key).into());
        let old_bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let new_bond = crate::bond::test_registration_bond_with_owner_and_seed(
            "alice",
            owner,
            b"UA_NEW",
            b"alice-rebond-note",
        );
        let previous = NameRecord {
            owner_pk: owner,
            bond_tag: old_bond.bond_tag,
            sequence: 4,
            address: b"UA_A".to_vec(),
            status: Status::Active,
        };
        let mut state = CoppiceState::default();
        state.names.insert("alice".into(), previous.clone());
        let rebond = crate::owner::signed_transfer_with_new_bond(
            &key,
            "alice",
            owner,
            new_bond.bond_tag,
            new_bond.anchor,
            new_bond.proof.clone(),
            b"UA_NEW".to_vec(),
            &previous,
        )
        .unwrap();
        assert_eq!(
            apply_operation(
                &mut state,
                rebond,
                ChainPosition {
                    block_height: 2,
                    tx_index: 0
                },
            ),
            Transition::Applied
        );
        assert_eq!(state.names["alice"].owner_pk, owner);
        assert_eq!(state.names["alice"].bond_tag, new_bond.bond_tag);
        assert_eq!(state.names["alice"].sequence, 5);
    }
}
