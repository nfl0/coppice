use blake2b_simd::Params;

pub(crate) const HASH_LEN: usize = 32;

pub(crate) fn hash(personalization: &[u8; 16], message: &[u8]) -> [u8; HASH_LEN] {
    let digest = Params::new()
        .hash_length(HASH_LEN)
        .personal(personalization)
        .hash(message);
    digest
        .as_bytes()
        .try_into()
        .expect("fixed BLAKE2b digest length")
}
