use std::collections::{BTreeMap, BTreeSet};

use coppice::{
    config::{DeploymentEncodingError, DeploymentParameters, DeploymentValidationError},
    envelope,
    owner::parse_v1_owner_key,
    pending::PendingTimingError,
    registration::registration_commitment,
    reveal::{RevealValidationError, canonical_v1_address},
};

/// Wallet-local metadata for one registration attempt.
///
/// This type intentionally does not implement `Debug`: it contains the
/// registration secret. It also contains no output reference, witness,
/// signing key, spending key, proof, anchor, or reducer state.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRegistration {
    name: String,
    address: Vec<u8>,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    secret: [u8; 32],
    commitment: [u8; 32],
    commit_txid: Option<[u8; 32]>,
    commit_height: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRegistrationValidationError {
    InvalidDeployment(DeploymentValidationError),
    InvalidName,
    InvalidOwnerKey,
    InvalidAddress(RevealValidationError),
    CommitmentEncoding(DeploymentEncodingError),
    CommitmentMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRegistrationTransitionError {
    CommitTxidAlreadyRecorded,
    CommitHeightRequiresTxid,
    CommitHeightAlreadyRecorded,
}

impl PendingRegistration {
    /// Constructs a validated wallet-local registration intent.
    pub fn new(
        deployment: &DeploymentParameters,
        name: String,
        address: Vec<u8>,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        secret: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<Self, PendingRegistrationValidationError> {
        deployment
            .validate()
            .map_err(PendingRegistrationValidationError::InvalidDeployment)?;
        if !envelope::valid_name(&name) {
            return Err(PendingRegistrationValidationError::InvalidName);
        }
        parse_v1_owner_key(owner_pk)
            .map_err(|_| PendingRegistrationValidationError::InvalidOwnerKey)?;

        let canonical_address = canonical_v1_address(&address, deployment)
            .map_err(PendingRegistrationValidationError::InvalidAddress)?;
        if canonical_address != address {
            return Err(PendingRegistrationValidationError::InvalidAddress(
                RevealValidationError::NonCanonicalAddress,
            ));
        }

        let expected =
            registration_commitment(deployment, &name, owner_pk, bond_tag, &address, secret)
                .map_err(PendingRegistrationValidationError::CommitmentEncoding)?;
        if expected != commitment {
            return Err(PendingRegistrationValidationError::CommitmentMismatch);
        }

        Ok(Self {
            name,
            address,
            owner_pk,
            bond_tag,
            secret,
            commitment,
            commit_txid: None,
            commit_height: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &[u8] {
        &self.address
    }

    pub const fn owner_pk(&self) -> [u8; 32] {
        self.owner_pk
    }

    pub const fn bond_tag(&self) -> [u8; 32] {
        self.bond_tag
    }

    /// Returns the secret for the later reveal builder. Callers must keep it
    /// within the wallet's private workflow.
    pub const fn secret(&self) -> [u8; 32] {
        self.secret
    }

    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub const fn commit_txid(&self) -> Option<[u8; 32]> {
        self.commit_txid
    }

    pub const fn commit_height(&self) -> Option<u32> {
        self.commit_height
    }

    pub fn record_commit_txid(
        &mut self,
        txid: [u8; 32],
    ) -> Result<(), PendingRegistrationTransitionError> {
        match self.commit_txid {
            None => {
                self.commit_txid = Some(txid);
                Ok(())
            }
            Some(existing) if existing == txid => Ok(()),
            Some(_) => Err(PendingRegistrationTransitionError::CommitTxidAlreadyRecorded),
        }
    }

    pub fn record_commit_mined(
        &mut self,
        height: u32,
    ) -> Result<(), PendingRegistrationTransitionError> {
        if self.commit_txid.is_none() {
            return Err(PendingRegistrationTransitionError::CommitHeightRequiresTxid);
        }
        match self.commit_height {
            None => {
                self.commit_height = Some(height);
                Ok(())
            }
            Some(existing) if existing == height => Ok(()),
            Some(_) => Err(PendingRegistrationTransitionError::CommitHeightAlreadyRecorded),
        }
    }
}

/// Errors for the wallet-local pending-registration collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRegistrationCollectionError {
    DuplicateCommitment,
    UnknownCommitment,
    Transition(PendingRegistrationTransitionError),
}

/// In-memory wallet-local pending registration intents.
///
/// This is deliberately distinct from the protocol reducer's global
/// `PendingCommitments` map. It is not consensus state and is not a source of
/// truth for replay.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PendingRegistrationCollection {
    by_commitment: BTreeMap<[u8; 32], PendingRegistration>,
}

impl PendingRegistrationCollection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        pending: PendingRegistration,
    ) -> Result<(), PendingRegistrationCollectionError> {
        let commitment = pending.commitment();
        if self.by_commitment.contains_key(&commitment) {
            return Err(PendingRegistrationCollectionError::DuplicateCommitment);
        }
        self.by_commitment.insert(commitment, pending);
        Ok(())
    }

    pub fn get(&self, commitment: &[u8; 32]) -> Option<&PendingRegistration> {
        self.by_commitment.get(commitment)
    }

    pub fn len(&self) -> usize {
        self.by_commitment.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_commitment.is_empty()
    }

    pub fn pending_bond_tags(&self) -> BTreeSet<[u8; 32]> {
        self.by_commitment
            .values()
            .map(PendingRegistration::bond_tag)
            .collect()
    }

    pub fn iter_pending_bond_tags(&self) -> impl Iterator<Item = [u8; 32]> {
        self.pending_bond_tags().into_iter()
    }

    pub fn mark_commit_broadcast(
        &mut self,
        commitment: &[u8; 32],
        txid: [u8; 32],
    ) -> Result<(), PendingRegistrationCollectionError> {
        self.by_commitment
            .get_mut(commitment)
            .ok_or(PendingRegistrationCollectionError::UnknownCommitment)?
            .record_commit_txid(txid)
            .map_err(PendingRegistrationCollectionError::Transition)
    }

    pub fn mark_commit_mined(
        &mut self,
        commitment: &[u8; 32],
        height: u32,
    ) -> Result<(), PendingRegistrationCollectionError> {
        self.by_commitment
            .get_mut(commitment)
            .ok_or(PendingRegistrationCollectionError::UnknownCommitment)?
            .record_commit_mined(height)
            .map_err(PendingRegistrationCollectionError::Transition)
    }

    /// Removes a completed or deliberately abandoned local attempt.
    pub fn remove(&mut self, commitment: &[u8; 32]) -> Option<PendingRegistration> {
        self.by_commitment.remove(commitment)
    }
}

/// Returns whether a mined local COMMIT is expired at canonical height `height`.
///
/// This delegates to the core's checked pending-expiry arithmetic and never
/// mutates or removes local metadata.
pub fn pending_commit_expired(
    commit_height: u32,
    commit_ttl_blocks: u32,
    height: u32,
) -> Result<bool, PendingTimingError> {
    coppice::pending::commitment_expired_at_end_of_block(commit_height, commit_ttl_blocks, height)
}

/// Returns whether a local attempt with a mined COMMIT is expired. An attempt
/// that has not recorded a mined height is not expired by this helper.
pub fn pending_attempt_expired(
    pending: &PendingRegistration,
    commit_ttl_blocks: u32,
    height: u32,
) -> Result<bool, PendingTimingError> {
    pending.commit_height().map_or(Ok(false), |commit_height| {
        pending_commit_expired(commit_height, commit_ttl_blocks, height)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice::{
        config::{DeploymentParameters, REGTEST_V0, Rendezvous},
        constants::REGTEST_V0_ACTIVATION_HEIGHT,
        owner::{OwnerSigningKey, owner_key_bytes},
    };
    use zcash_protocol::consensus::NetworkType;

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

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

    fn owner_pk() -> [u8; 32] {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        owner_key_bytes(&(&key).into())
    }

    fn pending() -> PendingRegistration {
        let deployment = deployment();
        let commitment = registration_commitment(
            &deployment,
            "alice",
            owner_pk(),
            [0x42; 32],
            ADDRESS,
            [0xa5; 32],
        )
        .unwrap();
        PendingRegistration::new(
            &deployment,
            "alice".to_owned(),
            ADDRESS.to_vec(),
            owner_pk(),
            [0x42; 32],
            [0xa5; 32],
            commitment,
        )
        .unwrap()
    }

    #[test]
    fn constructor_checks_commitment_and_does_not_store_an_output_reference() {
        let pending = pending();
        assert_eq!(pending.name(), "alice");
        assert_eq!(pending.address(), ADDRESS);
        assert_eq!(pending.commit_txid(), None);
        assert_eq!(pending.commit_height(), None);

        let deployment = deployment();
        let mut wrong = pending.commitment();
        wrong[0] ^= 1;
        assert!(matches!(
            PendingRegistration::new(
                &deployment,
                "alice".to_owned(),
                ADDRESS.to_vec(),
                owner_pk(),
                [0x42; 32],
                [0xa5; 32],
                wrong,
            ),
            Err(PendingRegistrationValidationError::CommitmentMismatch)
        ));
    }

    #[test]
    fn constructor_rejects_identity_v1_owner_key() {
        let deployment = deployment();
        let identity = [0; 32];
        let commitment = registration_commitment(
            &deployment,
            "alice",
            identity,
            [0x42; 32],
            ADDRESS,
            [0xa5; 32],
        )
        .unwrap();
        assert!(matches!(
            PendingRegistration::new(
                &deployment,
                "alice".to_owned(),
                ADDRESS.to_vec(),
                identity,
                [0x42; 32],
                [0xa5; 32],
                commitment,
            ),
            Err(PendingRegistrationValidationError::InvalidOwnerKey)
        ));
    }

    #[test]
    fn collection_rejects_duplicates_and_requires_broadcast_before_mined() {
        let first = pending();
        let commitment = first.commitment();
        let mut collection = PendingRegistrationCollection::new();
        collection.insert(first.clone()).unwrap();
        assert_eq!(
            collection.insert(first),
            Err(PendingRegistrationCollectionError::DuplicateCommitment)
        );
        assert_eq!(
            collection.mark_commit_mined(&commitment, 10),
            Err(PendingRegistrationCollectionError::Transition(
                PendingRegistrationTransitionError::CommitHeightRequiresTxid
            ))
        );
        collection
            .mark_commit_broadcast(&commitment, [7; 32])
            .unwrap();
        collection.mark_commit_mined(&commitment, 10).unwrap();
        assert_eq!(
            collection.get(&commitment).unwrap().commit_height(),
            Some(10)
        );
    }

    #[test]
    fn expiration_uses_checked_protocol_arithmetic_without_deleting_metadata() {
        let mut pending = pending();
        assert!(!pending_attempt_expired(&pending, 20, 100).unwrap());
        pending.record_commit_txid([7; 32]).unwrap();
        pending.record_commit_mined(100).unwrap();
        assert!(!pending_attempt_expired(&pending, 20, 119).unwrap());
        assert!(pending_attempt_expired(&pending, 20, 120).unwrap());
        assert_eq!(
            pending_commit_expired(u32::MAX, 1, u32::MAX),
            Err(PendingTimingError::HeightOverflow)
        );
    }
}
