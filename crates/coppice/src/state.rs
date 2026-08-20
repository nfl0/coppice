use crate::envelope::{Operation, valid_name};
use crate::name_tree::{NameProof, prove, root, verify};
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoppiceState {
    pub names: BTreeMap<String, NameRecord>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    InvalidSignature,
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
}
pub fn apply_operation(s: &mut CoppiceState, op: Operation, _: ChainPosition) -> Transition {
    match &op {
        Operation::Register {
            name,
            owner_pk,
            bond_tag,
            bond_anchor,
            bond_proof,
            address,
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
            if s.names.contains_key(name) {
                return Transition::Rejected(TransitionRejectReason::DuplicateRegister);
            }
            if !crate::bond::verify_registration_bond(
                name,
                *owner_pk,
                *bond_tag,
                *bond_anchor,
                bond_proof,
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
            if *sequence != old.sequence.saturating_add(1) {
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
            if *sequence != old.sequence.saturating_add(1) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{OwnerSigningKey, owner_key_bytes, sign_operation};
    #[test]
    fn register_update_release() {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let bond = crate::bond::test_registration_bond("alice");
        let mut s = CoppiceState::default();
        let x = Operation::Register {
            name: "alice".into(),
            owner_pk,
            bond_tag: bond.bond_tag,
            bond_anchor: bond.anchor,
            bond_proof: bond.proof.clone(),
            address: vec![2],
        };
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
}
