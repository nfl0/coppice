//! Minimal local wallet persistence for replay resumed after a process restart.
use crate::{
    legacy_state::{CoppiceState, Status},
    replay::{
        ChainContext, ReplayOutcome, ReplayState, SerializedReplayError,
        process_serialized_transaction,
    },
    spent::SpentTagTree,
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

const LOCAL_STATE_VERSION: u8 = 1;
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
    names: CoppiceState,
    spent: SpentTagTree,
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
        Self::new_with_ironwood_tree(config.activation_height, fixture_context, ironwood_tree)
    }

    pub fn new(activation_height: u32, fixture_context: [u8; 32]) -> Self {
        Self::new_with_ironwood_tree(activation_height, fixture_context, IronwoodTree::empty())
    }

    /// Selects the fixed public bulletin rendez-vous for this deployment.
    pub fn set_rendezvous(&mut self, rendezvous: crate::config::Rendezvous) {
        self.state.set_rendezvous(rendezvous);
    }

    /// Starts replay from a wallet-authenticated Ironwood frontier at the end
    /// of the block immediately preceding `activation_height`.
    pub fn new_with_ironwood_tree(
        activation_height: u32,
        fixture_context: [u8; 32],
        ironwood_tree: IronwoodTree,
    ) -> Self {
        let mut state = ReplayState::new();
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
            let candidate_transaction = crate::carrier::transaction_has_bulletin_output(
                &zcash_primitives::transaction::Transaction::read(
                    tx.as_slice(),
                    zcash_protocol::consensus::BranchId::Nu6_3,
                )
                .map_err(|_| IncrementalError::InvalidTransaction)?,
                next_state.rendezvous,
            )
            .map_err(|_| IncrementalError::InvalidTransaction)?
            .then(|| tx.clone());
            journal.push(JournalTx {
                tx_index: index as u32,
                txid: txid.into(),
                nullifiers: result.effects.nullifiers,
                commitments: result.effects.commitments,
                candidate_transaction,
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
            let Some(raw) = tx.candidate_transaction.as_deref() else {
                outcomes.push(ReplayOutcome::NotCandidate);
                continue;
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
                let mut state = ReplayState::new();
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
    #[test]
    fn compact_block_failures_are_atomic_and_order_is_canonical() {
        let mut wallet = IncrementalWallet::new(10, [0; 32]);
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

        let mut chain = IncrementalWallet::new(10, [0; 32]);
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
    fn old_development_local_state_is_rejected() {
        let wallet = IncrementalWallet::new(10, [0; 32]);
        let encoded = wallet.save_local().unwrap();
        let mut old_version: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        old_version["version"] = 6.into();
        assert!(matches!(
            IncrementalWallet::load_local(&serde_json::to_vec(&old_version).unwrap()),
            Err(IncrementalError::InvalidLocalState)
        ));

        let mut old_schema: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        old_schema
            .as_object_mut()
            .unwrap()
            .remove("accepted_bond_anchors");
        assert!(matches!(
            IncrementalWallet::load_local(&serde_json::to_vec(&old_schema).unwrap()),
            Err(IncrementalError::InvalidLocalState)
        ));
    }
}
