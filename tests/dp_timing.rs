//! The time a DP draw takes does not depend on the size of the noise.
//!
//! Draws are grouped by the noise they produced (0 versus |z| ≥ 6 at ε = 0.5)
//! and the median duration of a call in each group is compared; a sampler
//! whose loops run until a random stop takes visibly longer for large noise.
//! Medians and a wide band (0.7 … 1.43) keep this stable on a loaded machine;
//! the exact statement (same work per call) is `tests/dp_cost_model.rs`.

use alice_crypto::dp::{dp_count, SecureRng};
use std::time::Instant;

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

#[test]
fn the_duration_of_a_draw_does_not_depend_on_the_noise_it_draws() {
    let (mut small, mut large) = (Vec::new(), Vec::new());
    for round in 0..3u8 {
        for i in 0..=255u8 {
            let mut key = [i; 32];
            key[0] = round;
            let mut rng = SecureRng::from_key(key);
            let start = Instant::now();
            let noisy = dp_count(1_000, 0.5, &mut rng).expect("valid");
            let ns = start.elapsed().as_nanos();
            match (noisy - 1_000).abs() {
                0 => small.push(ns),
                z if z >= 6 => large.push(ns),
                _ => {}
            }
        }
    }
    assert!(
        small.len() >= 40 && large.len() >= 40,
        "groups too small: {} / {}",
        small.len(),
        large.len()
    );
    let (s, l) = (median(small) as f64, median(large) as f64);
    let ratio = l / s;
    assert!(
        (0.7..=1.43).contains(&ratio),
        "median time for |noise| ≥ 6 is {ratio:.2}× that for 0"
    );
}
