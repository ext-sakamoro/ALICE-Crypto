//! The DP noise does the same work for every value it draws.
//!
//! Cost model: every call draws a fixed number of 64-bit keystream words that
//! depends only on the public parameters (ε, Δ), never on the true value or on
//! the noise. Per attempt of the discrete Laplace sampler: 4 words for `U`,
//! 32 Bernoulli steps of 4 words each, 2 words for the geometric part, 1 for
//! the sign = 135 words; the attempt count is 74, 128 or 190 by the band of the
//! public decay rate (see `laplace_attempts` in `src/dp.rs`).
//!
//! The variable-time sampler this replaced drew more words for larger noise
//! (rejection and geometric loops ran until they stopped), so the count told an
//! observer how large the noise was.

use alice_crypto::dp::{dp_count, dp_sum, DpNoise, SecureRng};

const WORDS_PER_ATTEMPT: u64 = 4 + 32 * 4 + 2 + 1;

fn words_per_count(eps: f64, count: u64, rng: &mut SecureRng) -> u64 {
    let before = rng.words_drawn();
    let _ = dp_count(count, eps, rng).expect("valid");
    rng.words_drawn() - before
}

#[test]
fn dp_count_draws_the_same_number_of_words_for_every_value_and_noise() {
    // decay rate ε per unit: ε = 4 → rate > 1 (190 attempts), ε = 1 and 0.1 →
    // rate ≤ 1 (128 attempts)
    for (eps, attempts) in [(4.0, 190u64), (1.0, 128), (0.1, 128)] {
        let mut rng = SecureRng::from_key([9u8; 32]);
        let mut noises = std::collections::BTreeSet::new();
        for i in 0..400u64 {
            let count = i * 1_000_003 % 10_000_000;
            let before = rng.words_drawn();
            let noisy = dp_count(count, eps, &mut rng).expect("valid");
            noises.insert(noisy - i64::try_from(count).expect("fits"));
            assert_eq!(
                rng.words_drawn() - before,
                attempts * WORDS_PER_ATTEMPT,
                "ε = {eps}, call {i}"
            );
        }
        // teeth: the noise itself did vary across these calls
        assert!(
            noises.len() >= 2,
            "ε = {eps}: the noise did not vary ({} distinct)",
            noises.len()
        );
        assert_eq!(
            words_per_count(eps, 0, &mut rng),
            words_per_count(eps, u64::from(u32::MAX), &mut rng)
        );
    }
}

#[test]
fn the_lattice_mechanism_draws_the_same_number_of_words_for_every_value() {
    // Δ = 10, ε = 0.1: rate = ε·Λ/Δ < 2^-10 → 74 attempts
    let mut rng = SecureRng::from_key([10u8; 32]);
    for x in [0.0, 1.5, -2_000.25, 1e6] {
        let before = rng.words_drawn();
        let _ = dp_sum(x, 10.0, 0.1, &mut rng).expect("valid");
        assert_eq!(
            rng.words_drawn() - before,
            74 * WORDS_PER_ATTEMPT,
            "x = {x}"
        );
    }
    let n = DpNoise::with_key(10.0, 0.1, [10u8; 32]);
    assert!(n.lattice() > 0.0);
}
