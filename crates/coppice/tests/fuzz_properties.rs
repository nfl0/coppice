use coppice::{carrier_v1::reconstruct_frames_v1, envelope::decode_operation};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

/// Deterministic fuzz regression for the two hostile byte-oriented protocol
/// boundaries. Any generated input may be rejected, but parsing must remain
/// total and panic-free.
#[test]
fn arbitrary_operation_and_indexed_frame_bytes_are_panic_free() {
    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    for iteration in 0..10_000usize {
        let mut operation = vec![0; iteration % 9_000];
        rng.fill_bytes(&mut operation);
        let _ = decode_operation(&operation);

        let frame_count = iteration % 34;
        let mut frames = vec![[0u8; 512]; frame_count];
        for frame in &mut frames {
            rng.fill_bytes(frame);
        }
        let _ = reconstruct_frames_v1(&frames, [0x42; 32]);
    }
}
