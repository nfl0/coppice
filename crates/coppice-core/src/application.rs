use crate::carrier::MAX_CPV1_PAYLOAD_LEN;
use crate::hash;
use crate::replay::{CoreBlockContext, CoreTransactionContext};

pub const APPLICATION_ID_PERSONALIZATION: [u8; 16] = *b"CoppiceAppIdV1\0\0";
pub const APPLICATION_ENVELOPE_MAGIC: [u8; 4] = *b"CA01";
pub const APPLICATION_ENVELOPE_HEADER_LEN: usize = 4 + 32 + 2;
pub const MAX_APPLICATION_ENVELOPE_LEN: usize = MAX_CPV1_PAYLOAD_LEN;
pub const MAX_APPLICATION_PAYLOAD_LEN: usize =
    MAX_APPLICATION_ENVELOPE_LEN - APPLICATION_ENVELOPE_HEADER_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationId([u8; 32]);

impl ApplicationId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationIdentityError {
    Empty,
}

/// Derives an application family identity from the exact bytes frozen by its
/// application specification. Core performs no Unicode or textual
/// normalization.
pub fn derive_application_id(
    canonical_application_identity: &[u8],
) -> Result<ApplicationId, ApplicationIdentityError> {
    if canonical_application_identity.is_empty() {
        return Err(ApplicationIdentityError::Empty);
    }
    Ok(ApplicationId::from_bytes(hash::hash(
        &APPLICATION_ID_PERSONALIZATION,
        canonical_application_identity,
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationKey {
    pub id: ApplicationId,
    pub version: u16,
}

impl ApplicationKey {
    pub const fn new(id: ApplicationId, version: u16) -> Self {
        Self { id, version }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationDescriptor {
    pub key: ApplicationKey,
    pub activation_height: u32,
}

/// Compact canonical facts available before any full transaction fetch.
///
/// This is the application-facing observation boundary. It deliberately
/// contains no routed payload, sibling application state, wallet-private
/// data, or carrier candidacy. Core owns carrier detection; applications can
/// only request authenticated extended effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationCompactTransactionSummary<'a> {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub ironwood_nullifiers: &'a [[u8; 32]],
    pub ironwood_commitments: &'a [[u8; 32]],
    pub action_count: usize,
}

/// The additional canonical observation an application may request for one
/// compact transaction. Carrier acquisition is intentionally not an
/// application capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationAcquisitionRequirement {
    None,
    ExtendedEffects,
}

/// Canonical compact facts assembled by a host adapter after Core-owned
/// rendezvous classification. The composed runtime consumes this type to
/// union carrier acquisition with application observation requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCompactTransactionSummary<'a> {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub ironwood_nullifiers: &'a [[u8; 32]],
    pub ironwood_commitments: &'a [[u8; 32]],
    pub action_count: usize,
    pub rendezvous_candidate: bool,
}

impl<'a> CanonicalCompactTransactionSummary<'a> {
    /// Returns the restricted view applications may inspect for selective
    /// extended-effect acquisition.
    pub const fn application_view(&self) -> ApplicationCompactTransactionSummary<'a> {
        ApplicationCompactTransactionSummary {
            tx_index: self.tx_index,
            txid: self.txid,
            ironwood_nullifiers: self.ironwood_nullifiers,
            ironwood_commitments: self.ironwood_commitments,
            action_count: self.action_count,
        }
    }
}

/// The portion of one Core block that a specific application is authorized to
/// observe. Before application activation, only the canonical position is
/// exposed; Core effects and routed messages are withheld.
/// One canonical transaction as seen by a single application. The Core effect
/// view is shared by all active applications, but the payload is already
/// filtered to this application's exact key. An application never receives a
/// different application's envelope (including malformed envelopes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationTransactionContext {
    core: CoreTransactionContext,
    payload: Option<Box<[u8]>>,
}

impl ApplicationTransactionContext {
    pub(crate) fn new(core: CoreTransactionContext, payload: Option<Box<[u8]>>) -> Self {
        Self { core, payload }
    }

    pub fn core(&self) -> &CoreTransactionContext {
        &self.core
    }

    /// The decoded CA01 payload addressed to this application, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
}

/// Application-scoped canonical block view. Before activation the position
/// advances but Core effects and messages are deliberately unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationBlockContext {
    pub(crate) tip: ApplicationTip,
    pub(crate) core: Option<CoreBlockContext>,
    pub(crate) transactions: Box<[ApplicationTransactionContext]>,
    pub(crate) active: bool,
}

impl ApplicationBlockContext {
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns canonical block metadata only after application activation.
    /// Pre-activation applications still receive their position through
    /// [`Self::tip`] so they can advance deterministic empty state.
    pub fn core(&self) -> Option<&CoreBlockContext> {
        self.core.as_ref()
    }

    pub fn transactions(&self) -> &[ApplicationTransactionContext] {
        &self.transactions
    }

    pub fn tip(&self) -> ApplicationTip {
        self.tip
    }
}

/// Canonical application position corresponding to a completed Zcash block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

/// Minimal lifecycle implemented by deterministic applications hosted by the
/// Coppice runtime. Core supplies ordered, validated Zcash context and remains
/// unaware of the application's payload, state, and transition semantics.
pub trait CoppiceApplication: Clone {
    type BlockOutput;
    type ApplyError;
    type RewindError;

    fn descriptor(&self) -> ApplicationDescriptor;
    fn tip(&self) -> ApplicationTip;
    fn state_root(&self) -> [u8; 32];
    fn apply_block(
        &mut self,
        block: &ApplicationBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError>;
    fn rewind_to(&mut self, height: u32) -> Result<(), Self::RewindError>;

    /// The number of completed blocks the application must be able to undo.
    /// The composed runtime takes the maximum across hosted applications and
    /// requires Core to retain at least that much canonical history.
    fn rewind_retention_blocks(&self) -> u32;

    fn oldest_rewind_height(&self) -> u32;

    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip>;

    /// Read-only selective observation policy for one compact canonical
    /// transaction. The compositor calls this only after the application is
    /// active for the block being prepared. The default keeps simple
    /// applications compact-only without boilerplate.
    fn full_transaction_acquisition(
        &self,
        _summary: &ApplicationCompactTransactionSummary<'_>,
    ) -> ApplicationAcquisitionRequirement {
        ApplicationAcquisitionRequirement::None
    }
}

/// Self-describing application snapshot envelope. The payload belongs wholly
/// to the application; Core never parses it. The common metadata lets a host
/// reject mismatched application data before handing it to application code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationSnapshot {
    pub format_version: u32,
    pub descriptor: ApplicationDescriptor,
    pub tip: ApplicationTip,
    pub state_root: [u8; 32],
    pub oldest_rewind_height: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationSnapshotValidationError {
    UnsupportedFormat { expected: u32, actual: u32 },
    DescriptorMismatch,
    Activation(ApplicationActivationError),
    TipMismatch,
    StateRootMismatch,
    InvalidRewindBoundary,
}

impl ApplicationSnapshot {
    /// Validates the host-visible snapshot envelope before an application
    /// parses its private payload. Core does not interpret `payload`, but it
    /// can reject identity, activation, tip, root, and bounded-history
    /// mismatches uniformly for every application.
    pub fn validate_for(
        &self,
        expected_format_version: u32,
        expected_descriptor: ApplicationDescriptor,
        runtime_activation_height: u32,
        expected_tip: ApplicationTip,
        expected_state_root: [u8; 32],
    ) -> Result<(), ApplicationSnapshotValidationError> {
        if self.format_version != expected_format_version {
            return Err(ApplicationSnapshotValidationError::UnsupportedFormat {
                expected: expected_format_version,
                actual: self.format_version,
            });
        }
        expected_descriptor
            .validate_for_runtime(runtime_activation_height)
            .map_err(ApplicationSnapshotValidationError::Activation)?;
        if self.descriptor != expected_descriptor {
            return Err(ApplicationSnapshotValidationError::DescriptorMismatch);
        }
        if self.tip != expected_tip {
            return Err(ApplicationSnapshotValidationError::TipMismatch);
        }
        if self.state_root != expected_state_root {
            return Err(ApplicationSnapshotValidationError::StateRootMismatch);
        }
        // An application may activate later than Core and still receive
        // canonical position-only contexts before its own activation. Its
        // rewind horizon is therefore bounded by the Core runtime activation
        // base, not by the application's later activation height.
        let activation_base = runtime_activation_height
            .checked_sub(1)
            .ok_or(ApplicationSnapshotValidationError::InvalidRewindBoundary)?;
        if self.oldest_rewind_height < activation_base
            || self.oldest_rewind_height > self.tip.height
        {
            return Err(ApplicationSnapshotValidationError::InvalidRewindBoundary);
        }
        Ok(())
    }
}

/// Persistence contract for a deterministic application. Applications own
/// their encoding and validation rules while every host gets the same identity,
/// tip, root, and bounded-undo checks.
pub trait PersistedCoppiceApplication: CoppiceApplication {
    type SnapshotError;

    fn snapshot_format_version(&self) -> u32;
    fn save_application_payload(&self) -> Result<Vec<u8>, Self::SnapshotError>;
    fn load_application_payload(
        &mut self,
        snapshot: ApplicationSnapshot,
    ) -> Result<(), Self::SnapshotError>;

    fn save_application_snapshot(&self) -> Result<ApplicationSnapshot, Self::SnapshotError> {
        Ok(ApplicationSnapshot {
            format_version: self.snapshot_format_version(),
            descriptor: self.descriptor(),
            tip: self.tip(),
            state_root: self.state_root(),
            oldest_rewind_height: self.oldest_rewind_height(),
            payload: self.save_application_payload()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationActivationError {
    ZeroActivationHeight,
    BeforeRuntimeActivation,
}

impl ApplicationDescriptor {
    pub const fn validate_for_runtime(
        &self,
        runtime_activation_height: u32,
    ) -> Result<(), ApplicationActivationError> {
        if self.activation_height == 0 {
            Err(ApplicationActivationError::ZeroActivationHeight)
        } else if self.activation_height < runtime_activation_height {
            Err(ApplicationActivationError::BeforeRuntimeActivation)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationEnvelopeV1 {
    key: ApplicationKey,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationEnvelopeError {
    TooShort,
    TooLong,
    WrongMagic,
}

impl ApplicationEnvelopeV1 {
    pub fn new(key: ApplicationKey, payload: Vec<u8>) -> Result<Self, ApplicationEnvelopeError> {
        if payload.len() > MAX_APPLICATION_PAYLOAD_LEN {
            return Err(ApplicationEnvelopeError::TooLong);
        }
        Ok(Self { key, payload })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ApplicationEnvelopeError> {
        if bytes.len() < APPLICATION_ENVELOPE_HEADER_LEN {
            return Err(ApplicationEnvelopeError::TooShort);
        }
        if bytes.len() > MAX_APPLICATION_ENVELOPE_LEN {
            return Err(ApplicationEnvelopeError::TooLong);
        }
        if bytes[..APPLICATION_ENVELOPE_MAGIC.len()] != APPLICATION_ENVELOPE_MAGIC {
            return Err(ApplicationEnvelopeError::WrongMagic);
        }

        let id = ApplicationId::from_bytes(
            bytes[4..36]
                .try_into()
                .expect("application ID slice has fixed length"),
        );
        let version = u16::from_be_bytes(
            bytes[36..38]
                .try_into()
                .expect("application version slice has fixed length"),
        );
        Self::new(ApplicationKey::new(id, version), bytes[38..].to_vec())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(APPLICATION_ENVELOPE_HEADER_LEN + self.payload.len());
        output.extend_from_slice(&APPLICATION_ENVELOPE_MAGIC);
        output.extend_from_slice(self.key.id.as_bytes());
        output.extend_from_slice(&self.key.version.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output
    }

    pub const fn key(&self) -> ApplicationKey {
        self.key
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_identity_is_exact_and_nonempty() {
        let lower = derive_application_id(b"example.app").unwrap();
        assert_eq!(lower, derive_application_id(b"example.app").unwrap());
        assert_ne!(lower, derive_application_id(b"Example.App").unwrap());
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/core_application_id.json"
        ))
        .unwrap();
        assert_eq!(
            hex::encode(lower.to_bytes()),
            vector["expected_application_id_hex"].as_str().unwrap()
        );
        assert_eq!(
            derive_application_id(b""),
            Err(ApplicationIdentityError::Empty)
        );
    }

    #[test]
    fn application_activation_is_independent_and_not_before_runtime() {
        let key = ApplicationKey::new(derive_application_id(b"example.app").unwrap(), 1);
        let at_runtime = ApplicationDescriptor {
            key,
            activation_height: 10,
        };
        let later = ApplicationDescriptor {
            key,
            activation_height: 20,
        };
        let earlier = ApplicationDescriptor {
            key,
            activation_height: 9,
        };
        assert_eq!(at_runtime.validate_for_runtime(10), Ok(()));
        assert_eq!(later.validate_for_runtime(10), Ok(()));
        assert_eq!(
            ApplicationDescriptor {
                key,
                activation_height: 0,
            }
            .validate_for_runtime(10),
            Err(ApplicationActivationError::ZeroActivationHeight)
        );
        assert_eq!(
            earlier.validate_for_runtime(10),
            Err(ApplicationActivationError::BeforeRuntimeActivation)
        );
    }

    #[test]
    fn application_snapshot_envelope_rejects_common_metadata_mismatches() {
        let key = ApplicationKey::new(derive_application_id(b"example.snapshot").unwrap(), 1);
        let descriptor = ApplicationDescriptor {
            key,
            activation_height: 10,
        };
        let tip = ApplicationTip {
            height: 20,
            block_hash: [2; 32],
        };
        let snapshot = ApplicationSnapshot {
            format_version: 1,
            descriptor,
            tip,
            state_root: [7; 32],
            oldest_rewind_height: 9,
            payload: vec![1, 2, 3],
        };
        assert_eq!(
            snapshot.validate_for(1, descriptor, 10, tip, [7; 32]),
            Ok(())
        );

        let mut wrong_format = snapshot.clone();
        wrong_format.format_version = 2;
        assert_eq!(
            wrong_format.validate_for(1, descriptor, 10, tip, [7; 32]),
            Err(ApplicationSnapshotValidationError::UnsupportedFormat {
                expected: 1,
                actual: 2,
            })
        );

        let mut wrong_root = snapshot.clone();
        wrong_root.state_root = [8; 32];
        assert_eq!(
            wrong_root.validate_for(1, descriptor, 10, tip, [7; 32]),
            Err(ApplicationSnapshotValidationError::StateRootMismatch)
        );

        let mut invalid_boundary = snapshot;
        invalid_boundary.oldest_rewind_height = 8;
        assert_eq!(
            invalid_boundary.validate_for(1, descriptor, 10, tip, [7; 32]),
            Err(ApplicationSnapshotValidationError::InvalidRewindBoundary)
        );

        // A later-activating application may have position-only history from
        // the Core activation base. The common envelope must not reject that
        // valid pre-activation rewind point as being before the app's own
        // activation height.
        let later_descriptor = ApplicationDescriptor {
            key,
            activation_height: 20,
        };
        let later_snapshot = ApplicationSnapshot {
            format_version: 1,
            descriptor: later_descriptor,
            tip: ApplicationTip {
                height: 15,
                block_hash: [3; 32],
            },
            state_root: [4; 32],
            oldest_rewind_height: 9,
            payload: vec![],
        };
        assert_eq!(
            later_snapshot.validate_for(1, later_descriptor, 10, later_snapshot.tip, [4; 32]),
            Ok(())
        );
    }

    #[test]
    fn envelope_round_trips_exact_payload_bytes() {
        let key = ApplicationKey::new(derive_application_id(b"example.app").unwrap(), 0x0102);
        let payload = vec![0, 1, 2, 0, 0];
        let envelope = ApplicationEnvelopeV1::new(key, payload.clone()).unwrap();
        let encoded = envelope.encode();
        assert_eq!(&encoded[..4], b"CA01");
        assert_eq!(&encoded[36..38], &[0x01, 0x02]);
        assert_eq!(ApplicationEnvelopeV1::decode(&encoded), Ok(envelope));
        assert_eq!(&encoded[38..], payload);
    }

    #[test]
    fn envelope_boundaries_and_magic_are_strict() {
        assert_eq!(MAX_CPV1_PAYLOAD_LEN, 16_093);
        assert_eq!(MAX_APPLICATION_PAYLOAD_LEN, 16_055);
        let key = ApplicationKey::new(derive_application_id(b"example.app").unwrap(), 1);
        let largest = ApplicationEnvelopeV1::new(key, vec![0; MAX_APPLICATION_PAYLOAD_LEN])
            .unwrap()
            .encode();
        assert_eq!(largest.len(), MAX_APPLICATION_ENVELOPE_LEN);
        assert!(ApplicationEnvelopeV1::decode(&largest).is_ok());
        assert_eq!(
            ApplicationEnvelopeV1::new(key, vec![0; MAX_APPLICATION_PAYLOAD_LEN + 1]),
            Err(ApplicationEnvelopeError::TooLong)
        );
        assert_eq!(
            ApplicationEnvelopeV1::decode(&largest[..APPLICATION_ENVELOPE_HEADER_LEN - 1]),
            Err(ApplicationEnvelopeError::TooShort)
        );
        let mut wrong_magic = largest;
        wrong_magic[3] ^= 1;
        assert_eq!(
            ApplicationEnvelopeV1::decode(&wrong_magic),
            Err(ApplicationEnvelopeError::WrongMagic)
        );
    }

    #[test]
    fn empty_payload_is_structurally_canonical() {
        let key = ApplicationKey::new(derive_application_id(b"example.app").unwrap(), 1);
        let encoded = ApplicationEnvelopeV1::new(key, Vec::new())
            .unwrap()
            .encode();
        assert_eq!(encoded.len(), APPLICATION_ENVELOPE_HEADER_LEN);
        assert_eq!(
            ApplicationEnvelopeV1::decode(&encoded).unwrap().payload(),
            b""
        );
    }
}
