use crate::carrier::MAX_CPV1_PAYLOAD_LEN;
use crate::hash;
use crate::replay::CoreBlockContext;

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

/// Canonical application position corresponding to a completed Zcash block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}

/// Minimal lifecycle implemented by deterministic applications hosted by the
/// Coppice runtime. Core supplies ordered, validated Zcash context and remains
/// unaware of the application's payload, state, and transition semantics.
pub trait CoppiceApplication {
    type BlockOutput;
    type ApplyError;
    type RewindError;

    fn descriptor(&self) -> ApplicationDescriptor;
    fn tip(&self) -> ApplicationTip;
    fn state_root(&self) -> [u8; 32];
    fn apply_block(
        &mut self,
        block: &CoreBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError>;
    fn rewind_to(&mut self, height: u32) -> Result<(), Self::RewindError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationActivationError {
    BeforeRuntimeActivation,
}

impl ApplicationDescriptor {
    pub const fn validate_for_runtime(
        &self,
        runtime_activation_height: u32,
    ) -> Result<(), ApplicationActivationError> {
        if self.activation_height < runtime_activation_height {
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
            earlier.validate_for_runtime(10),
            Err(ApplicationActivationError::BeforeRuntimeActivation)
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
