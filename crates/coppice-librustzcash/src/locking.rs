use std::{collections::BTreeSet, fmt::Debug};

use zcash_client_backend::wallet::LockOwner;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    InventoryError, IronwoodOutputId, IronwoodViewingCapability, OwnedBond, OwnedIronwoodNote,
    PendingRegistrationCollection,
    inventory::{ClassifiedNote, classify_notes},
};

/// The smallest wallet-backend seam required by reconstructible Coppice locks.
///
/// The concrete wallet implementation is responsible for making
/// `owned_unspent_ironwood_notes` include already-locked outputs and for
/// reporting the current owner on each output. The only mutation methods are
/// Coppice-scoped; this trait has no operation for clearing arbitrary foreign
/// locks.
pub trait CoppiceLockBackend {
    type Error: Debug;

    fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error>;

    fn lock_owner(&self, output_id: &IronwoodOutputId) -> Result<Option<LockOwner>, Self::Error>;

    fn ensure_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
        expiry_height: BlockHeight,
    ) -> Result<(), Self::Error>;

    fn remove_coppice_lock(
        &mut self,
        output_id: &IronwoodOutputId,
        bond_tag: [u8; 32],
    ) -> Result<bool, Self::Error>;

    fn max_lock_expiry_height(&self) -> BlockHeight;
}

/// Constructs the exact pinned librustzcash lock identity for a Coppice bond.
/// The bond tag is used directly; it is not hashed again.
pub const fn lock_owner_for_bond(bond_tag: [u8; 32]) -> LockOwner {
    LockOwner::new(bond_tag)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesiredLockSetError {
    Inventory(InventoryError),
    MissingPendingBond { bond_tag: [u8; 32] },
}

/// Computes the I-004 desired lock tags.
///
/// Canonical active tags are intersected with tags reconstructed from this
/// wallet's notes. Local pending tags are then unioned in, but a pending tag
/// whose note is missing is reported explicitly rather than silently dropped.
pub fn desired_lock_tags(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    notes: &[OwnedIronwoodNote],
    capability: IronwoodViewingCapability,
) -> Result<BTreeSet<[u8; 32]>, DesiredLockSetError> {
    let classified = classify_notes(notes, capability).map_err(DesiredLockSetError::Inventory)?;
    desired_lock_tags_from_classified(active_tags, pending, &classified)
}

fn desired_lock_tags_from_classified(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    classified: &[ClassifiedNote],
) -> Result<BTreeSet<[u8; 32]>, DesiredLockSetError> {
    let owned_tags: BTreeSet<[u8; 32]> = classified
        .iter()
        .map(|classified| classified.bond_tag)
        .collect();
    let pending_tags = pending.pending_bond_tags();
    for bond_tag in &pending_tags {
        if !owned_tags.contains(bond_tag) {
            return Err(DesiredLockSetError::MissingPendingBond {
                bond_tag: *bond_tag,
            });
        }
    }

    let mut desired = active_tags
        .intersection(&owned_tags)
        .copied()
        .collect::<BTreeSet<_>>();
    desired.extend(pending_tags);
    Ok(desired)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub desired_tags: BTreeSet<[u8; 32]>,
    pub owned_active_bonds: Vec<OwnedBond>,
    pub ensured_locks: usize,
    pub removed_locks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationError<E: Debug> {
    Inventory(InventoryError),
    MissingPendingBond { bond_tag: [u8; 32] },
    Backend(E),
}

fn map_desired_error<E: Debug>(error: DesiredLockSetError) -> ReconciliationError<E> {
    match error {
        DesiredLockSetError::Inventory(error) => ReconciliationError::Inventory(error),
        DesiredLockSetError::MissingPendingBond { bond_tag } => {
            ReconciliationError::MissingPendingBond { bond_tag }
        }
    }
}

/// Reconciles every owned unspent Ironwood note against the reconstructible
/// desired Coppice lock set.
pub fn reconcile_locks<B: CoppiceLockBackend>(
    active_tags: &BTreeSet<[u8; 32]>,
    pending: &PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    backend: &mut B,
) -> Result<ReconciliationReport, ReconciliationError<B::Error>> {
    // Check the capability before asking the backend for notes. Incoming-only
    // wallets must fail explicitly and must not mutate lock state.
    capability
        .require_nullifier_derivation()
        .map_err(ReconciliationError::Inventory)?;
    let notes = backend
        .owned_unspent_ironwood_notes()
        .map_err(ReconciliationError::Backend)?;
    let classified = classify_notes(&notes, capability).map_err(ReconciliationError::Inventory)?;
    let desired = desired_lock_tags_from_classified(active_tags, pending, &classified)
        .map_err(map_desired_error::<B::Error>)?;

    let owned_active_bonds = classified
        .iter()
        .filter(|classified| active_tags.contains(&classified.bond_tag))
        .map(|classified| OwnedBond {
            output_id: classified.note.output_id,
            value_zat: classified.note.value_zat,
            position: classified.note.position,
            bond_tag: classified.bond_tag,
        })
        .collect::<Vec<_>>();

    let expiry_height = backend.max_lock_expiry_height();
    let mut ensured_locks = 0;
    let mut removed_locks = 0;

    // `classify_notes` provides a stable `(bond_tag, output_id)` order, so
    // backend iteration order cannot affect mutation order or the report.
    for classified in classified {
        let note = classified.note;
        let bond_tag = classified.bond_tag;
        if desired.contains(&bond_tag) {
            backend
                .ensure_coppice_lock(&note.output_id, bond_tag, expiry_height)
                .map_err(ReconciliationError::Backend)?;
            ensured_locks += 1;
        } else {
            let owner = backend
                .lock_owner(&note.output_id)
                .map_err(ReconciliationError::Backend)?;
            if owner == Some(lock_owner_for_bond(bond_tag))
                && backend
                    .remove_coppice_lock(&note.output_id, bond_tag)
                    .map_err(ReconciliationError::Backend)?
            {
                removed_locks += 1;
            }
        }
    }

    Ok(ReconciliationReport {
        desired_tags: desired,
        owned_active_bonds,
        ensured_locks,
        removed_locks,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use coppice::{
        config::{DeploymentParameters, REGTEST_V0, Rendezvous},
        constants::REGTEST_V0_ACTIVATION_HEIGHT,
        owner::{OwnerSigningKey, owner_key_bytes},
        registration::registration_commitment,
    };
    use zcash_client_backend::wallet::LockOwner;
    use zcash_protocol::consensus::{BlockHeight, NetworkType};

    use super::*;
    use crate::{IronwoodOutputId, PendingRegistration, PendingRegistrationCollection};

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeLock {
        owner: LockOwner,
        expiry: BlockHeight,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum FakeError {
        ForeignLock,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FakeBackend {
        notes: Vec<OwnedIronwoodNote>,
        locks: BTreeMap<IronwoodOutputId, FakeLock>,
    }

    impl FakeBackend {
        fn new(notes: Vec<OwnedIronwoodNote>) -> Self {
            Self {
                notes,
                locks: BTreeMap::new(),
            }
        }

        fn with_lock(mut self, output_id: IronwoodOutputId, owner: LockOwner) -> Self {
            self.locks.insert(
                output_id,
                FakeLock {
                    owner,
                    expiry: BlockHeight::from_u32(123),
                },
            );
            self.sync_note(output_id);
            self
        }

        fn sync_note(&mut self, output_id: IronwoodOutputId) {
            let lock = self.locks.get(&output_id).copied();
            if let Some(note) = self
                .notes
                .iter_mut()
                .find(|note| note.output_id == output_id)
            {
                note.locked = lock.is_some();
                note.lock_owner = lock.map(|lock| lock.owner);
            }
        }
    }

    impl CoppiceLockBackend for FakeBackend {
        type Error = FakeError;

        fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
            Ok(self.notes.clone())
        }

        fn lock_owner(
            &self,
            output_id: &IronwoodOutputId,
        ) -> Result<Option<LockOwner>, Self::Error> {
            Ok(self.locks.get(output_id).map(|lock| lock.owner))
        }

        fn ensure_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
            expiry_height: BlockHeight,
        ) -> Result<(), Self::Error> {
            let owner = lock_owner_for_bond(bond_tag);
            if self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner != owner)
            {
                return Err(FakeError::ForeignLock);
            }
            self.locks.insert(
                *output_id,
                FakeLock {
                    owner,
                    expiry: expiry_height,
                },
            );
            self.sync_note(*output_id);
            Ok(())
        }

        fn remove_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
        ) -> Result<bool, Self::Error> {
            let owner = lock_owner_for_bond(bond_tag);
            let removable = self
                .locks
                .get(output_id)
                .is_some_and(|lock| lock.owner == owner);
            if removable {
                self.locks.remove(output_id);
                self.sync_note(*output_id);
            }
            Ok(removable)
        }

        fn max_lock_expiry_height(&self) -> BlockHeight {
            BlockHeight::from_u32(u32::MAX)
        }
    }

    fn note(id: u8) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat: 100,
            nullifier: [id; 32],
            position: Some(u32::from(id)),
            locked: false,
            lock_owner: None,
            spendable: true,
            freshness_eligible: true,
        }
    }

    fn tag(id: u8) -> [u8; 32] {
        coppice::bond_tag::derive_v1_bond_tag(&[id; 32]).unwrap()
    }

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST_V0.network_id.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_V0_ACTIVATION_HEIGHT,
            minimum_bond_value: REGTEST_V0.minimum_bond_value,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous {
                orchard_ivk: REGTEST_V0.rendezvous.orchard_ivk,
                orchard_receiver: REGTEST_V0.rendezvous.orchard_receiver,
            },
        }
    }

    fn pending_for(name: &str, bond_tag: [u8; 32]) -> PendingRegistration {
        let deployment = deployment();
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let owner_pk = owner_key_bytes(&(&key).into());
        let secret = [0xa5; 32];
        let commitment =
            registration_commitment(&deployment, name, owner_pk, bond_tag, ADDRESS, secret)
                .unwrap();
        PendingRegistration::new(
            &deployment,
            name.to_owned(),
            ADDRESS.to_vec(),
            owner_pk,
            bond_tag,
            secret,
            commitment,
        )
        .unwrap()
    }

    fn collection_with(pending: PendingRegistration) -> PendingRegistrationCollection {
        let mut collection = PendingRegistrationCollection::new();
        collection.insert(pending).unwrap();
        collection
    }

    fn empty_pending() -> PendingRegistrationCollection {
        PendingRegistrationCollection::new()
    }

    #[test]
    fn owned_active_bond_is_locked() {
        let active = BTreeSet::from([tag(1)]);
        let mut backend = FakeBackend::new(vec![note(1)]);
        let report = reconcile_locks(
            &active,
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, active);
        assert_eq!(
            backend.lock_owner(&note(1).output_id).unwrap(),
            Some(lock_owner_for_bond(tag(1)))
        );
        assert_eq!(
            backend.locks[&note(1).output_id].expiry,
            BlockHeight::from_u32(u32::MAX)
        );
    }

    #[test]
    fn owned_pending_bond_is_locked() {
        let pending = pending_for("alice", tag(2));
        let mut backend = FakeBackend::new(vec![note(2)]);
        let report = reconcile_locks(
            &BTreeSet::new(),
            &collection_with(pending),
            IronwoodViewingCapability::Spending,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, BTreeSet::from([tag(2)]));
        assert_eq!(
            backend.lock_owner(&note(2).output_id).unwrap(),
            Some(lock_owner_for_bond(tag(2)))
        );
    }

    #[test]
    fn same_active_and_pending_tag_is_one_desired_tag() {
        let pending = pending_for("alice", tag(3));
        let mut backend = FakeBackend::new(vec![note(3)]);
        let report = reconcile_locks(
            &BTreeSet::from([tag(3)]),
            &collection_with(pending),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.desired_tags, BTreeSet::from([tag(3)]));
        assert_eq!(report.ensured_locks, 1);
    }

    #[test]
    fn unrelated_owned_coppice_lock_is_removed() {
        let old_tag = tag(4);
        let output_id = note(4).output_id;
        let mut backend =
            FakeBackend::new(vec![note(4)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        let report = reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(report.removed_locks, 1);
        assert_eq!(backend.lock_owner(&output_id).unwrap(), None);
    }

    #[test]
    fn foreign_lock_is_preserved() {
        let output_id = note(5).output_id;
        let foreign = LockOwner::new([0xf5; 32]);
        let mut backend = FakeBackend::new(vec![note(5)]).with_lock(output_id, foreign);
        reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.lock_owner(&output_id).unwrap(), Some(foreign));
    }

    #[test]
    fn active_canonical_tag_without_owned_note_is_harmless() {
        let active = BTreeSet::from([tag(6)]);
        let mut backend = FakeBackend::new(Vec::new());
        let report = reconcile_locks(
            &active,
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert!(report.desired_tags.is_empty());
        assert!(backend.locks.is_empty());
    }

    #[test]
    fn missing_pending_note_is_explicit_and_does_not_mutate() {
        let pending = pending_for("alice", tag(7));
        let mut backend = FakeBackend::new(Vec::new());
        let before = backend.clone();
        assert_eq!(
            reconcile_locks(
                &BTreeSet::new(),
                &collection_with(pending),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
            ),
            Err(ReconciliationError::MissingPendingBond { bond_tag: tag(7) })
        );
        assert_eq!(backend, before);
    }

    #[test]
    fn repeated_reconciliation_is_idempotent() {
        let active = BTreeSet::from([tag(8)]);
        let mut backend = FakeBackend::new(vec![note(8)]);
        let first = reconcile_locks(
            &active,
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        let state_after_first = backend.clone();
        let second = reconcile_locks(
            &active,
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend, state_after_first);
        assert_eq!(first, second);
    }

    #[test]
    fn terminal_active_name_removes_old_lock_but_pending_keeps_it() {
        let old_tag = tag(9);
        let output_id = note(9).output_id;
        let mut backend =
            FakeBackend::new(vec![note(9)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        reconcile_locks(
            &BTreeSet::new(),
            &empty_pending(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.lock_owner(&output_id).unwrap(), None);

        let mut backend =
            FakeBackend::new(vec![note(9)]).with_lock(output_id, lock_owner_for_bond(old_tag));
        reconcile_locks(
            &BTreeSet::new(),
            &collection_with(pending_for("alice", old_tag)),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            backend.lock_owner(&output_id).unwrap(),
            Some(lock_owner_for_bond(old_tag))
        );
    }

    #[test]
    fn incoming_only_fails_before_note_enumeration_or_lock_mutation() {
        let output_id = note(10).output_id;
        let foreign = LockOwner::new([0xaa; 32]);
        let mut backend = FakeBackend::new(vec![note(10)]).with_lock(output_id, foreign);
        let before = backend.clone();
        assert_eq!(
            reconcile_locks(
                &BTreeSet::from([tag(10)]),
                &empty_pending(),
                IronwoodViewingCapability::IncomingOnly,
                &mut backend,
            ),
            Err(ReconciliationError::Inventory(
                InventoryError::InsufficientViewingCapability
            ))
        );
        assert_eq!(backend, before);
    }

    #[test]
    fn desired_lock_set_has_the_same_missing_pending_diagnostic() {
        let pending = pending_for("alice", tag(11));
        assert_eq!(
            desired_lock_tags(
                &BTreeSet::new(),
                &collection_with(pending),
                &[],
                IronwoodViewingCapability::FullViewing,
            ),
            Err(DesiredLockSetError::MissingPendingBond { bond_tag: tag(11) })
        );
    }
}
