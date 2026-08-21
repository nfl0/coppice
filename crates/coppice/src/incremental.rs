//! Minimal local wallet persistence for replay resumed after a process restart.
use crate::{
    replay::{
        ChainContext, ReplayOutcome, ReplayState, SerializedReplayError,
        process_serialized_transaction,
    },
    spent::SpentTagTree,
    state::{CoppiceState, Status},
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

const LOCAL_STATE_VERSION: u8 = 5;
pub type IronwoodTree = CommitmentTree<MerkleHashOrchard, 32>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncrementalError {
    NonSequentialHeight,
    NonCanonicalOrder,
    InvalidTransaction,
    InvalidCommitment,
    InvalidLocalState,
    InvalidRewind,
    NonCanonicalChain,
    InitializationClosed,
}

/// Compact chain data needed by Coppice. Full transaction bytes are required
/// only when the transaction ID matches the configured Coppice prefix.
#[derive(Clone)]
pub struct CompactReplayTx {
    pub tx_index: u32,
    pub txid: TxId,
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub candidate_transaction: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct JournalTx {
    tx_index: u32,
    txid: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    candidate_transaction: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct JournalBlock {
    height: u32,
    block_id: [u8; 32],
    prev_block_id: [u8; 32],
    transactions: Vec<JournalTx>,
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
    #[serde(default)]
    accepted_bond_anchors: std::collections::BTreeSet<[u8; 32]>,
    ironwood_tree: Vec<u8>,
    initial_ironwood_tree: Vec<u8>,
    initial_bond_anchors: std::collections::BTreeSet<[u8; 32]>,
    initial_spent: SpentTagTree,
    journal: Vec<JournalBlock>,
}

pub struct IncrementalWallet {
    pub state: ReplayState,
    activation_height: u32,
    last_height: Option<u32>,
    fixture_context: [u8; 32],
    ironwood_tree: IronwoodTree,
    initial_ironwood_tree: IronwoodTree,
    initial_bond_anchors: std::collections::BTreeSet<[u8; 32]>,
    initial_spent: SpentTagTree,
    journal: Vec<JournalBlock>,
}

impl IncrementalWallet {
    /// Creates a wallet replay state for the frozen public Testnet V0
    /// deployment from the authenticated pre-activation Ironwood frontier.
    pub fn testnet_v0(fixture_context: [u8; 32], ironwood_tree: IronwoodTree) -> Self {
        let config = crate::config::TESTNET_V0;
        Self::new_with_ironwood_tree(
            config.activation_height,
            fixture_context,
            config.tag_bits,
            ironwood_tree,
        )
    }

    pub fn new(activation_height: u32, fixture_context: [u8; 32], tag_bits: u8) -> Self {
        Self::new_with_ironwood_tree(
            activation_height,
            fixture_context,
            tag_bits,
            IronwoodTree::empty(),
        )
    }

    /// Starts replay from a wallet-authenticated Ironwood frontier at the end
    /// of the block immediately preceding `activation_height`.
    pub fn new_with_ironwood_tree(
        activation_height: u32,
        fixture_context: [u8; 32],
        tag_bits: u8,
        ironwood_tree: IronwoodTree,
    ) -> Self {
        let mut state = ReplayState::new(tag_bits);
        state.accept_bond_anchor(ironwood_tree.root().to_bytes());
        Self {
            state,
            activation_height,
            last_height: None,
            fixture_context,
            ironwood_tree: ironwood_tree.clone(),
            initial_ironwood_tree: ironwood_tree,
            initial_bond_anchors: std::collections::BTreeSet::new(),
            initial_spent: SpentTagTree::default(),
            journal: vec![],
        }
    }

    fn append_commitments(
        tree: &mut IronwoodTree,
        commitments: &[[u8; 32]],
    ) -> Result<(), IncrementalError> {
        for cmx in commitments {
            let node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(cmx))
                .ok_or(IncrementalError::InvalidCommitment)?;
            tree.append(node)
                .map_err(|_| IncrementalError::InvalidCommitment)?;
        }
        Ok(())
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
        let mut next_state = self.state.clone();
        let mut next_tree = self.ironwood_tree.clone();
        let mut outcomes = Vec::with_capacity(transactions.len());
        let mut journal = Vec::with_capacity(transactions.len());
        for (index, tx) in transactions.iter().enumerate() {
            let result = process_serialized_transaction(&mut next_state, height, index as u32, tx)
                .map_err(|SerializedReplayError::InvalidTransaction| {
                    IncrementalError::InvalidTransaction
                })?;
            Self::append_commitments(&mut next_tree, &result.effects.commitments)?;
            let txid = zcash_primitives::transaction::Transaction::read(
                tx.as_slice(),
                zcash_protocol::consensus::BranchId::Nu6_3,
            )
            .map_err(|_| IncrementalError::InvalidTransaction)?
            .txid();
            journal.push(JournalTx {
                tx_index: index as u32,
                txid: txid.into(),
                nullifiers: result.effects.nullifiers,
                commitments: result.effects.commitments,
                candidate_transaction: crate::is_coppice_candidate(&txid, next_state.tag_bits)
                    .then(|| tx.clone()),
            });
            outcomes.push(result.outcome);
        }
        next_state.accept_bond_anchor(next_tree.root().to_bytes());
        self.state = next_state;
        self.ironwood_tree = next_tree;
        self.last_height = Some(height);
        self.journal.push(JournalBlock {
            height,
            block_id: [0; 32],
            prev_block_id: [0; 32],
            transactions: journal,
        });
        Ok(outcomes)
    }

    pub fn process_compact_block(
        &mut self,
        height: u32,
        transactions: &[CompactReplayTx],
    ) -> Result<Vec<ReplayOutcome>, IncrementalError> {
        self.process_compact_block_with_chain(height, [0; 32], [0; 32], transactions)
    }

    /// Processes a compact block while binding the local journal to its real
    /// chain identity. A predecessor mismatch is rejected before state changes.
    pub fn process_compact_block_with_chain(
        &mut self,
        height: u32,
        block_id: [u8; 32],
        prev_block_id: [u8; 32],
        transactions: &[CompactReplayTx],
    ) -> Result<Vec<ReplayOutcome>, IncrementalError> {
        let expected = self
            .last_height
            .map_or(self.activation_height, |h| h.saturating_add(1));
        if height != expected {
            return Err(IncrementalError::NonSequentialHeight);
        }
        if let Some(previous) = self.journal.last()
            && previous.block_id != [0; 32]
            && previous.block_id != prev_block_id
        {
            return Err(IncrementalError::NonCanonicalChain);
        }
        if transactions
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        {
            return Err(IncrementalError::NonCanonicalOrder);
        }
        let mut next_state = self.state.clone();
        let mut next_tree = self.ironwood_tree.clone();
        let mut outcomes = Vec::with_capacity(transactions.len());
        for tx in transactions {
            for nullifier in &tx.nullifiers {
                next_state
                    .spent
                    .insert_nullifier(*nullifier)
                    .map_err(|_| IncrementalError::InvalidTransaction)?;
            }
            Self::append_commitments(&mut next_tree, &tx.commitments)?;
            if !crate::is_coppice_candidate(&tx.txid, next_state.tag_bits) {
                outcomes.push(ReplayOutcome::NotCandidate);
                continue;
            }
            let Some(raw) = tx.candidate_transaction.as_deref() else {
                return Err(IncrementalError::InvalidTransaction);
            };
            let parsed = zcash_primitives::transaction::Transaction::read(
                raw,
                zcash_protocol::consensus::BranchId::Nu6_3,
            )
            .map_err(|_| IncrementalError::InvalidTransaction)?;
            if parsed.txid() != tx.txid {
                return Err(IncrementalError::InvalidTransaction);
            }
            let full_effects = crate::ironwood::extract_ironwood_effects(&parsed);
            if full_effects.nullifiers != tx.nullifiers
                || full_effects.commitments != tx.commitments
            {
                return Err(IncrementalError::InvalidTransaction);
            }
            let result = process_serialized_transaction(&mut next_state, height, tx.tx_index, raw)
                .map_err(|_| IncrementalError::InvalidTransaction)?;
            outcomes.push(result.outcome);
        }
        next_state.accept_bond_anchor(next_tree.root().to_bytes());
        self.state = next_state;
        self.ironwood_tree = next_tree;
        self.last_height = Some(height);
        self.journal.push(JournalBlock {
            height,
            block_id,
            prev_block_id,
            transactions: transactions
                .iter()
                .map(|tx| JournalTx {
                    tx_index: tx.tx_index,
                    txid: tx.txid.into(),
                    nullifiers: tx.nullifiers.clone(),
                    commitments: tx.commitments.clone(),
                    candidate_transaction: tx.candidate_transaction.clone(),
                })
                .collect(),
        });
        Ok(outcomes)
    }

    pub fn next_height(&self) -> u32 {
        self.last_height
            .map_or(self.activation_height, |h| h.saturating_add(1))
    }

    pub fn activation_height(&self) -> u32 {
        self.activation_height
    }

    pub fn last_height(&self) -> Option<u32> {
        self.last_height
    }

    /// Seeds the public spent detector with Ironwood nullifiers observed before
    /// Coppice activation. This closes the otherwise-invalid path where an old,
    /// already-spent note is proven against a later commitment-tree root.
    pub fn seed_prior_nullifiers(
        &mut self,
        nullifiers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<(), IncrementalError> {
        if self.last_height.is_some() || !self.journal.is_empty() {
            return Err(IncrementalError::InitializationClosed);
        }
        let mut spent = self.state.spent.clone();
        for nullifier in nullifiers {
            spent
                .insert_nullifier(nullifier)
                .map_err(|_| IncrementalError::InvalidTransaction)?;
        }
        self.state.spent = spent.clone();
        self.initial_spent = spent;
        Ok(())
    }

    pub fn block_id_at(&self, height: u32) -> Option<[u8; 32]> {
        self.journal
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.block_id)
    }

    /// Rewinds derived state to `height` and deterministically replays the
    /// retained local block journal. Passing activation_height - 1 returns to
    /// the initial empty Coppice state and authenticated Ironwood frontier.
    pub fn rewind_to(&mut self, height: u32) -> Result<(), IncrementalError> {
        let prior = self
            .activation_height
            .checked_sub(1)
            .ok_or(IncrementalError::InvalidRewind)?;
        if height < prior || self.last_height.is_some_and(|tip| height > tip) {
            return Err(IncrementalError::InvalidRewind);
        }
        let retained = self
            .journal
            .iter()
            .filter(|block| block.height <= height)
            .cloned()
            .collect::<Vec<_>>();
        let mut rebuilt = Self::new_with_ironwood_tree(
            self.activation_height,
            self.fixture_context,
            self.state.tag_bits,
            self.initial_ironwood_tree.clone(),
        );
        for anchor in &self.initial_bond_anchors {
            rebuilt.accept_bond_anchor(*anchor);
        }
        rebuilt.state.spent = self.initial_spent.clone();
        rebuilt.initial_spent = self.initial_spent.clone();
        for block in retained {
            let transactions = block
                .transactions
                .iter()
                .map(|tx| CompactReplayTx {
                    tx_index: tx.tx_index,
                    txid: TxId::from_bytes(tx.txid),
                    nullifiers: tx.nullifiers.clone(),
                    commitments: tx.commitments.clone(),
                    candidate_transaction: tx.candidate_transaction.clone(),
                })
                .collect::<Vec<_>>();
            rebuilt.process_compact_block_with_chain(
                block.height,
                block.block_id,
                block.prev_block_id,
                &transactions,
            )?;
        }
        *self = rebuilt;
        Ok(())
    }

    /// Adds an Ironwood tree root independently derived by the wallet's Zcash
    /// chain scanner. This must be called before replaying a REGISTER that uses
    /// the root.
    pub fn accept_bond_anchor(&mut self, anchor: [u8; 32]) {
        self.state.accept_bond_anchor(anchor);
        if self.last_height.is_none() {
            self.initial_bond_anchors.insert(anchor);
        }
    }

    pub fn save_local(&self) -> Result<Vec<u8>, IncrementalError> {
        let mut ironwood_tree = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(
            &self.ironwood_tree,
            &mut ironwood_tree,
        )
        .map_err(|_| IncrementalError::InvalidLocalState)?;
        let mut initial_ironwood_tree = Vec::new();
        zcash_primitives::merkle_tree::write_commitment_tree(
            &self.initial_ironwood_tree,
            &mut initial_ironwood_tree,
        )
        .map_err(|_| IncrementalError::InvalidLocalState)?;
        serde_json::to_vec(&LocalWalletState {
            version: LOCAL_STATE_VERSION,
            activation_height: self.activation_height,
            last_height: self.last_height,
            fixture_context: self.fixture_context,
            tag_bits: self.state.tag_bits,
            names: self.state.names.clone(),
            spent: self.state.spent.clone(),
            accepted_bond_anchors: self.state.accepted_bond_anchors().clone(),
            ironwood_tree,
            initial_ironwood_tree,
            initial_bond_anchors: self.initial_bond_anchors.clone(),
            initial_spent: self.initial_spent.clone(),
            journal: self.journal.clone(),
        })
        .map_err(|_| IncrementalError::InvalidLocalState)
    }

    pub fn load_local(bytes: &[u8]) -> Result<Self, IncrementalError> {
        let saved: LocalWalletState =
            serde_json::from_slice(bytes).map_err(|_| IncrementalError::InvalidLocalState)?;
        if saved.version != LOCAL_STATE_VERSION
            || saved.tag_bits == 0
            || saved.tag_bits > 16
            || saved.names.names.iter().any(|(name, record)| {
                !crate::envelope::valid_name(name)
                    || crate::owner::parse_owner_key(record.owner_pk).is_err()
                    || record.address.len() > crate::constants::MAX_PAYLOAD_LEN
            })
            || saved.journal.iter().enumerate().any(|(index, block)| {
                block.height != saved.activation_height.saturating_add(index as u32)
                    || block
                        .transactions
                        .windows(2)
                        .any(|pair| pair[0].tx_index >= pair[1].tx_index)
                    || (index > 0
                        && block.prev_block_id != [0; 32]
                        && saved.journal[index - 1].block_id != [0; 32]
                        && block.prev_block_id != saved.journal[index - 1].block_id)
            })
            || saved.last_height != saved.journal.last().map(|block| block.height)
        {
            return Err(IncrementalError::InvalidLocalState);
        }
        let mut cursor = std::io::Cursor::new(&saved.ironwood_tree);
        let ironwood_tree = zcash_primitives::merkle_tree::read_commitment_tree(&mut cursor)
            .map_err(|_| IncrementalError::InvalidLocalState)?;
        if cursor.position() != saved.ironwood_tree.len() as u64 {
            return Err(IncrementalError::InvalidLocalState);
        }
        let mut initial_cursor = std::io::Cursor::new(&saved.initial_ironwood_tree);
        let initial_ironwood_tree =
            zcash_primitives::merkle_tree::read_commitment_tree(&mut initial_cursor)
                .map_err(|_| IncrementalError::InvalidLocalState)?;
        if initial_cursor.position() != saved.initial_ironwood_tree.len() as u64 {
            return Err(IncrementalError::InvalidLocalState);
        }
        Ok(Self {
            state: {
                let mut state = ReplayState::new(saved.tag_bits);
                state.names = saved.names;
                state.spent = saved.spent;
                for anchor in saved.accepted_bond_anchors {
                    state.accept_bond_anchor(anchor);
                }
                state
            },
            activation_height: saved.activation_height,
            last_height: saved.last_height,
            fixture_context: saved.fixture_context,
            ironwood_tree,
            initial_ironwood_tree,
            initial_bond_anchors: saved.initial_bond_anchors,
            initial_spent: saved.initial_spent,
            journal: saved.journal,
        })
    }

    pub fn state_commitment(&self) -> [u8; 32] {
        self.state.state_commitment(&ChainContext {
            height: self.last_height.unwrap_or(self.activation_height),
            fixture_block_id: self
                .journal
                .last()
                .filter(|block| block.block_id != [0; 32])
                .map_or(self.fixture_context, |block| block.block_id),
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
        let alice_bond = crate::bond::test_registration_bond("alice", b"UA_A");
        let bob_bond = crate::bond::test_registration_bond("bob", b"UA_B");
        let alice_secret = [7; 32];
        let alice_commitment = crate::state::registration_commitment(
            "alice",
            owner_pk,
            alice_bond.bond_tag,
            alice_bond.anchor,
            b"UA_A",
            alice_secret,
        );
        let reveal_alice = Operation::Reveal {
            name: "alice".into(),
            owner_pk,
            bond_tag: alice_bond.bond_tag,
            bond_anchor: alice_bond.anchor,
            bond_proof: alice_bond.proof.clone(),
            address: b"UA_A".to_vec(),
            secret: alice_secret,
        };
        let bob_secret = [8; 32];
        let bob_commitment = crate::state::registration_commitment(
            "bob",
            owner_pk,
            bob_bond.bond_tag,
            bob_bond.anchor,
            b"UA_B",
            bob_secret,
        );
        let reveal_bob = Operation::Reveal {
            name: "bob".into(),
            owner_pk,
            bond_tag: bob_bond.bond_tag,
            bond_anchor: bob_bond.anchor,
            bond_proof: bob_bond.proof.clone(),
            address: b"UA_B".to_vec(),
            secret: bob_secret,
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
        let commit_alice = carrier::build_coppice_transaction(
            &Operation::Commit {
                commitment: alice_commitment,
            },
            5,
        )
        .unwrap();
        let commit_bob = carrier::build_coppice_transaction(
            &Operation::Commit {
                commitment: bob_commitment,
            },
            5,
        )
        .unwrap();
        let alice = carrier::build_coppice_transaction(&reveal_alice, 5).unwrap();
        let bob = carrier::build_coppice_transaction(&reveal_bob, 5).unwrap();
        let release = carrier::build_coppice_transaction(&release_alice, 5).unwrap();
        let blocks = [
            vec![serialized(&commit_alice.tx), serialized(&commit_bob.tx)],
            vec![serialized(&alice.tx), serialized(&bob.tx)],
            vec![serialized(&release.tx)],
        ];
        let context: [u8; 32] = Sha256::digest(b"CoppiceIncrementalFixtureV0").into();

        let mut full = IncrementalWallet::new(100, context, 5);
        full.seed_prior_nullifiers([[7; 32]]).unwrap();
        full.accept_bond_anchor(alice_bond.anchor);
        full.accept_bond_anchor(bob_bond.anchor);
        for (offset, block) in blocks.iter().enumerate() {
            full.process_block(100 + offset as u32, block).unwrap();
        }

        let mut interrupted = IncrementalWallet::new(100, context, 5);
        interrupted.seed_prior_nullifiers([[7; 32]]).unwrap();
        interrupted.accept_bond_anchor(alice_bond.anchor);
        interrupted.accept_bond_anchor(bob_bond.anchor);
        interrupted.process_block(100, &blocks[0]).unwrap();
        let local_state = interrupted.save_local().unwrap();
        let mut resumed = IncrementalWallet::load_local(&local_state).unwrap();
        resumed.process_block(101, &blocks[1]).unwrap();
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

        let mut reorged = IncrementalWallet::load_local(&full.save_local().unwrap()).unwrap();
        reorged.rewind_to(101).unwrap();
        reorged.process_block(102, &[]).unwrap();
        let mut clean = IncrementalWallet::new(100, context, 5);
        clean.seed_prior_nullifiers([[7; 32]]).unwrap();
        clean.accept_bond_anchor(alice_bond.anchor);
        clean.accept_bond_anchor(bob_bond.anchor);
        clean.process_block(100, &blocks[0]).unwrap();
        clean.process_block(101, &blocks[1]).unwrap();
        clean.process_block(102, &[]).unwrap();
        assert_eq!(
            reorged.state.names.state_root(),
            clean.state.names.state_root()
        );
        assert_eq!(reorged.state.spent.root(), clean.state.spent.root());
        assert_eq!(reorged.state_commitment(), clean.state_commitment());
        assert!(matches!(
            reorged.resolve("alice"),
            LocalResolution::Active { .. }
        ));
        assert_eq!(
            full.seed_prior_nullifiers([[8; 32]]),
            Err(IncrementalError::InitializationClosed)
        );

        full.state.spent.insert_spent_tag(bob_bond.bond_tag);
        assert_eq!(full.resolve("bob"), LocalResolution::InactiveBondSpent);
    }

    #[test]
    fn compact_block_failures_are_atomic_and_order_is_canonical() {
        let mut wallet = IncrementalWallet::new(10, [0; 32], 12);
        let initial = wallet.state.spent.root();
        let invalid = CompactReplayTx {
            tx_index: 0,
            txid: zcash_primitives::transaction::TxId::from_bytes([0x80; 32]),
            nullifiers: vec![[7; 32], [0xff; 32]],
            commitments: vec![],
            candidate_transaction: None,
        };
        assert_eq!(
            wallet.process_compact_block(10, &[invalid]),
            Err(IncrementalError::InvalidTransaction)
        );
        assert_eq!(wallet.state.spent.root(), initial);
        assert_eq!(wallet.last_height(), None);

        let unordered = [
            CompactReplayTx {
                tx_index: 2,
                txid: zcash_primitives::transaction::TxId::from_bytes([0x80; 32]),
                nullifiers: vec![],
                commitments: vec![],
                candidate_transaction: None,
            },
            CompactReplayTx {
                tx_index: 1,
                txid: zcash_primitives::transaction::TxId::from_bytes([0x81; 32]),
                nullifiers: vec![],
                commitments: vec![],
                candidate_transaction: None,
            },
        ];
        assert_eq!(
            wallet.process_compact_block(10, &unordered),
            Err(IncrementalError::NonCanonicalOrder)
        );

        let mut chain = IncrementalWallet::new(10, [0; 32], 12);
        chain
            .process_compact_block_with_chain(10, [1; 32], [0; 32], &[])
            .unwrap();
        let before = chain.state_commitment();
        assert_eq!(
            chain.process_compact_block_with_chain(11, [2; 32], [9; 32], &[]),
            Err(IncrementalError::NonCanonicalChain)
        );
        assert_eq!(chain.state_commitment(), before);
        chain
            .process_compact_block_with_chain(11, [3; 32], [1; 32], &[])
            .unwrap();
        assert_eq!(chain.block_id_at(11), Some([3; 32]));
        assert_ne!(before, chain.state_commitment());
    }

    #[test]
    fn corrupted_local_state_is_rejected() {
        let wallet = IncrementalWallet::new(10, [0; 32], 12);
        let encoded = wallet.save_local().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["tag_bits"] = 0.into();
        assert!(matches!(
            IncrementalWallet::load_local(&serde_json::to_vec(&value).unwrap()),
            Err(IncrementalError::InvalidLocalState)
        ));
    }
}
