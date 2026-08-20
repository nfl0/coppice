//! Minimal local wallet persistence for replay resumed after a process restart.
use crate::{
    replay::{
        ChainContext, ReplayOutcome, ReplayState, SerializedReplayError,
        process_serialized_transaction,
    },
    spent::SpentTagTree,
    state::{CoppiceState, Status},
};
use serde::{Deserialize, Serialize};

const LOCAL_STATE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncrementalError {
    NonSequentialHeight,
    InvalidTransaction,
    InvalidLocalState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalResolution {
    Active { address: Vec<u8> },
    InactiveBondSpent,
    Released,
    Absent,
}

#[derive(Serialize, Deserialize)]
struct LocalWalletState {
    version: u8,
    activation_height: u32,
    last_height: Option<u32>,
    fixture_context: [u8; 32],
    tag_bits: u8,
    names: CoppiceState,
    spent: SpentTagTree,
}

pub struct IncrementalWallet {
    pub state: ReplayState,
    activation_height: u32,
    last_height: Option<u32>,
    fixture_context: [u8; 32],
}

impl IncrementalWallet {
    pub fn new(activation_height: u32, fixture_context: [u8; 32], tag_bits: u8) -> Self {
        Self {
            state: ReplayState::new(tag_bits),
            activation_height,
            last_height: None,
            fixture_context,
        }
    }

    pub fn process_block(
        &mut self,
        height: u32,
        transactions: &[Vec<u8>],
    ) -> Result<Vec<ReplayOutcome>, IncrementalError> {
        let expected = self
            .last_height
            .map_or(self.activation_height, |h| h.saturating_add(1));
        if height != expected {
            return Err(IncrementalError::NonSequentialHeight);
        }
        let outcomes = transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                process_serialized_transaction(&mut self.state, height, index as u32, tx)
                    .map(|result| result.outcome)
                    .map_err(|SerializedReplayError::InvalidTransaction| {
                        IncrementalError::InvalidTransaction
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.last_height = Some(height);
        Ok(outcomes)
    }

    pub fn save_local(&self) -> Result<Vec<u8>, IncrementalError> {
        serde_json::to_vec(&LocalWalletState {
            version: LOCAL_STATE_VERSION,
            activation_height: self.activation_height,
            last_height: self.last_height,
            fixture_context: self.fixture_context,
            tag_bits: self.state.tag_bits,
            names: self.state.names.clone(),
            spent: self.state.spent.clone(),
        })
        .map_err(|_| IncrementalError::InvalidLocalState)
    }

    pub fn load_local(bytes: &[u8]) -> Result<Self, IncrementalError> {
        let saved: LocalWalletState =
            serde_json::from_slice(bytes).map_err(|_| IncrementalError::InvalidLocalState)?;
        if saved.version != LOCAL_STATE_VERSION {
            return Err(IncrementalError::InvalidLocalState);
        }
        Ok(Self {
            state: ReplayState {
                names: saved.names,
                spent: saved.spent,
                tag_bits: saved.tag_bits,
            },
            activation_height: saved.activation_height,
            last_height: saved.last_height,
            fixture_context: saved.fixture_context,
        })
    }

    pub fn state_commitment(&self) -> [u8; 32] {
        self.state.state_commitment(&ChainContext {
            height: self.last_height.unwrap_or(self.activation_height),
            fixture_block_id: self.fixture_context,
        })
    }

    pub fn resolve(&self, name: &str) -> LocalResolution {
        let Some(record) = self.state.names.names.get(name) else {
            return LocalResolution::Absent;
        };
        let proof = self.state.names.prove_name(name);
        if !self.state.names.verify_name(name, Some(record), &proof) {
            return LocalResolution::Absent;
        }
        if record.status == Status::Released {
            return LocalResolution::Released;
        }
        let bond_spent = {
            let tag = record.bond_tag;
            if self.state.spent.contains(&tag) {
                SpentTagTree::verify_spent(
                    self.state.spent.root(),
                    tag,
                    &self.state.spent.prove_spent(tag),
                )
            } else {
                let _valid_unspent = SpentTagTree::verify_unspent(
                    self.state.spent.root(),
                    tag,
                    &self.state.spent.prove_unspent(tag),
                );
                false
            }
        };
        if bond_spent {
            LocalResolution::InactiveBondSpent
        } else {
            LocalResolution::Active {
                address: record.address.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        carrier,
        envelope::Operation,
        owner::{OwnerSigningKey, owner_key_bytes, sign_operation},
        state::{NameRecord, Status},
    };
    use sha2::{Digest, Sha256};

    fn serialized(tx: &zcash_primitives::transaction::Transaction) -> Vec<u8> {
        let mut bytes = Vec::new();
        tx.write(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn local_restart_matches_uninterrupted_replay() {
        let signing_key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&signing_key).into());
        let alice_bond = crate::bond::test_registration_bond("alice");
        let bob_bond = crate::bond::test_registration_bond("bob");
        let register_alice = Operation::Register {
            name: "alice".into(),
            owner_pk,
            bond_tag: alice_bond.bond_tag,
            bond_anchor: alice_bond.anchor,
            bond_proof: alice_bond.proof.clone(),
            address: b"UA_A".to_vec(),
        };
        let register_bob = Operation::Register {
            name: "bob".into(),
            owner_pk,
            bond_tag: bob_bond.bond_tag,
            bond_anchor: bob_bond.anchor,
            bond_proof: bob_bond.proof.clone(),
            address: b"UA_B".to_vec(),
        };
        let alice_record = NameRecord {
            owner_pk,
            bond_tag: alice_bond.bond_tag,
            sequence: 0,
            address: b"UA_A".to_vec(),
            status: Status::Active,
        };
        let mut release_alice = Operation::Release {
            name: "alice".into(),
            sequence: 1,
            signature: vec![],
        };
        let signature = sign_operation(&signing_key, &release_alice, &alice_record).unwrap();
        if let Operation::Release { signature: s, .. } = &mut release_alice {
            *s = signature;
        }
        let alice = carrier::build_coppice_transaction(&register_alice, 5).unwrap();
        let bob = carrier::build_coppice_transaction(&register_bob, 5).unwrap();
        let release = carrier::build_coppice_transaction(&release_alice, 5).unwrap();
        let blocks = [
            vec![serialized(&alice.tx)],
            vec![serialized(&bob.tx)],
            vec![serialized(&release.tx)],
        ];
        let context: [u8; 32] = Sha256::digest(b"CoppiceIncrementalFixtureV0").into();

        let mut full = IncrementalWallet::new(100, context, 5);
        for (offset, block) in blocks.iter().enumerate() {
            full.process_block(100 + offset as u32, block).unwrap();
        }

        let mut interrupted = IncrementalWallet::new(100, context, 5);
        interrupted.process_block(100, &blocks[0]).unwrap();
        interrupted.process_block(101, &blocks[1]).unwrap();
        let local_state = interrupted.save_local().unwrap();
        let mut resumed = IncrementalWallet::load_local(&local_state).unwrap();
        resumed.process_block(102, &blocks[2]).unwrap();

        assert_eq!(
            full.state.names.state_root(),
            resumed.state.names.state_root()
        );
        assert_eq!(full.state.spent.root(), resumed.state.spent.root());
        assert_eq!(full.state_commitment(), resumed.state_commitment());
        assert_eq!(full.resolve("alice"), LocalResolution::Released);
        assert_eq!(full.resolve("charlie"), LocalResolution::Absent);
        assert_eq!(
            full.resolve("bob"),
            LocalResolution::Active {
                address: b"UA_B".to_vec()
            }
        );
        full.state.spent.insert_spent_tag(bob_bond.bond_tag);
        assert_eq!(full.resolve("bob"), LocalResolution::InactiveBondSpent);
    }
}
