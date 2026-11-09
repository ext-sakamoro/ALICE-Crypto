//! What a `std-base` build (no module feature) carries: dp with a key from the operating system and
//! the random source, and no module built on the AEAD, KDF, key-exchange or hash dependencies. CI runs
//! this file with `--no-default-features --features std-base`, next to a dependency-tree check that
//! those dependencies are absent; under the default build it runs too (the same items exist there).

use alice_crypto::dp::{DpNoise, SecureRng};

/// Two keys drawn from the OS differ (a 2^-256 chance of a false failure), and each stream is the
/// ChaCha20 keystream of its key: the same key replays the same words
#[test]
fn secure_rng_takes_its_key_from_the_os() {
    let mut a = SecureRng::try_from_entropy().expect("an OS random source");
    let mut b = SecureRng::try_from_entropy().expect("an OS random source");
    let wa: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
    let wb: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
    assert_ne!(wa, wb, "two OS keys gave the same stream");
    let mut k1 = SecureRng::from_key([7; 32]);
    let mut k2 = SecureRng::from_key([7; 32]);
    for _ in 0..64 {
        assert_eq!(k1.next_u64(), k2.next_u64());
    }
}

#[test]
fn dp_noise_with_an_os_key_is_built() {
    let noise =
        DpNoise::try_from_entropy(1.0, 1.0).expect("an OS random source and valid parameters");
    let _ = noise;
    assert!(
        DpNoise::try_from_entropy(1.0, -1.0).is_err(),
        "a negative epsilon is refused"
    );
}

#[test]
fn the_random_source_fills_a_buffer() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    alice_crypto::random::fill(&mut a).expect("an OS random source");
    alice_crypto::random::fill(&mut b).expect("an OS random source");
    assert_ne!(a, b);
}
