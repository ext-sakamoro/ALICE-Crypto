//! Oracles for the 0.4.0 mechanisms: `dp_int`, `randomized_response` and the
//! public `bernoulli_ratio`.
//!
//! Expected values come from closed forms: the discrete Laplace probability
//! mass `(1 − q)/(1 + q) · q^|z|` with `q = e^(−ε/Δ)`, the randomized-response
//! flip probability `1/(1 + e^ε)` and the fraction `num/den`. Frequencies are
//! compared within 6 standard errors of the binomial count. The exact
//! probability of the truncated randomized-response sampler (integer steps,
//! not sampling) is checked separately by `scripts/dp_rr_exact.py`.

use alice_crypto::dp::{
    bernoulli_ratio, dp_int, randomized_response, DpError, SecureRng, RR_MAX_EPSILON_WHOLE,
};

/// 6 binomial standard errors around `p` for `n` draws
fn within(count: usize, n: usize, p: f64, what: &str) {
    let mean = p * n as f64;
    let sd = (n as f64 * p * (1.0 - p)).sqrt();
    assert!(
        (count as f64 - mean).abs() <= 6.0 * sd + 1.0,
        "{what}: {count} of {n}, expected {mean:.1} ± {:.1}",
        6.0 * sd
    );
}

fn pmf(rate: f64, z: i64) -> f64 {
    let q = (-rate).exp();
    (1.0 - q) / (1.0 + q) * q.powi(i32::try_from(z.abs()).expect("small"))
}

#[test]
fn dp_int_noise_is_discrete_laplace_with_decay_epsilon_over_sensitivity() {
    const N: usize = 40_000;
    for (delta, eps, key) in [(1u64, 1.0, 1u8), (3, 1.5, 2), (10, 0.5, 3), (2, 0.25, 4)] {
        let rate = eps / delta as f64;
        let mut rng = SecureRng::from_key([key; 32]);
        let zs: Vec<i64> = (0..N)
            .map(|_| dp_int(-7, delta, eps, &mut rng).expect("valid") + 7)
            .collect();
        for z in -3..=3 {
            let c = zs.iter().filter(|&&x| x == z).count();
            within(c, N, pmf(rate, z), &format!("Δ={delta} ε={eps} z={z}"));
        }
        // symmetry: P(Z > 0) = P(Z < 0)
        let pos = zs.iter().filter(|&&x| x > 0).count();
        let neg = zs.iter().filter(|&&x| x < 0).count();
        let p_side = (1.0 - pmf(rate, 0)) / 2.0;
        within(pos, N, p_side, "Z > 0");
        within(neg, N, p_side, "Z < 0");
    }
}

#[test]
fn dp_int_refuses_rather_than_clamps_an_overflowing_result() {
    // same key ⇒ same noise draw: compute z from 0, then add it at the limits
    for key in 0..64u8 {
        let mut a = SecureRng::from_key([key; 32]);
        let mut b = SecureRng::from_key([key; 32]);
        let mut c = SecureRng::from_key([key; 32]);
        let z = dp_int(0, 1, 0.5, &mut a).expect("valid");
        let at_max = dp_int(i64::MAX, 1, 0.5, &mut b);
        let at_min = dp_int(i64::MIN, 1, 0.5, &mut c);
        if z > 0 {
            assert_eq!(at_max, Err(DpError::CountOutOfRange), "key {key}, z {z}");
        } else {
            assert_eq!(at_max, Ok(i64::MAX + z), "key {key}, z {z}");
        }
        if z < 0 {
            assert_eq!(at_min, Err(DpError::CountOutOfRange), "key {key}, z {z}");
        } else {
            assert_eq!(at_min, Ok(i64::MIN + z), "key {key}, z {z}");
        }
    }
}

#[test]
fn dp_int_rejects_zero_sensitivity_and_bad_epsilon() {
    let mut rng = SecureRng::from_key([5; 32]);
    assert_eq!(dp_int(1, 0, 1.0, &mut rng), Err(DpError::InvalidScale));
    for eps in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert_eq!(
            dp_int(1, 1, eps, &mut rng),
            Err(DpError::InvalidScale),
            "ε = {eps}"
        );
    }
    assert_eq!(
        dp_int(1, 1, 1e30, &mut rng),
        Err(DpError::EpsilonOutOfRange)
    );
    // the largest sensitivity still works (ε / Δ is exact)
    assert!(dp_int(1, u64::MAX, 1.0, &mut rng).is_ok());
}

#[test]
fn randomized_response_flips_with_probability_one_over_one_plus_e_to_epsilon() {
    // ≥ 2·10^5 draws where the work per call is small (⌊ε⌋ = 0); larger ε
    // costs (⌊ε⌋ + 1)× more per call and flips rarely, 4·10^4 draws suffice
    for (eps, key, n) in [
        (0.5, 11u8, 200_000usize),
        (1.0, 12, 200_000),
        (2.75, 13, 40_000),
        (5.0, 14, 40_000),
    ] {
        #[allow(non_snake_case)]
        let N = n;
        let q = 1.0 / (1.0 + f64::exp(eps));
        let mut rng = SecureRng::from_key([key; 32]);
        let flips_true = (0..N / 2)
            .filter(|_| !randomized_response(true, eps, &mut rng).expect("valid"))
            .count();
        let flips_false = (0..N / 2)
            .filter(|_| randomized_response(false, eps, &mut rng).expect("valid"))
            .count();
        within(flips_true, N / 2, q, &format!("ε={eps}, true flipped"));
        within(flips_false, N / 2, q, &format!("ε={eps}, false flipped"));
        // chi-square over the 2×2 table (bit × flipped), 1 degree of freedom
        let exp = [N as f64 / 2.0 * q, N as f64 / 2.0 * (1.0 - q)];
        let obs = [
            [flips_true as f64, (N / 2 - flips_true) as f64],
            [flips_false as f64, (N / 2 - flips_false) as f64],
        ];
        let chi2: f64 = obs
            .iter()
            .flat_map(|row| row.iter().zip(exp).map(|(o, e)| (o - e) * (o - e) / e))
            .sum();
        assert!(
            chi2 < 30.0,
            "ε={eps}: χ² = {chi2:.2} on 2 degrees of freedom"
        );
    }
}

#[test]
fn randomized_response_rejects_bad_and_too_large_epsilon() {
    let mut rng = SecureRng::from_key([15; 32]);
    for eps in [0.0, -0.5, f64::NAN, f64::INFINITY] {
        assert_eq!(
            randomized_response(true, eps, &mut rng),
            Err(DpError::InvalidScale)
        );
    }
    let edge = RR_MAX_EPSILON_WHOLE as f64;
    assert!(randomized_response(true, edge + 0.5, &mut rng).is_ok());
    assert_eq!(
        randomized_response(true, edge + 1.0, &mut rng),
        Err(DpError::EpsilonOutOfRange)
    );
}

#[test]
fn bernoulli_ratio_is_exactly_num_over_den_at_the_bounds() {
    let mut rng = SecureRng::from_key([21; 32]);
    assert_eq!(
        bernoulli_ratio(1, 0, &mut rng),
        Err(DpError::InvalidProbability)
    );
    assert_eq!(
        bernoulli_ratio(0, 0, &mut rng),
        Err(DpError::InvalidProbability)
    );
    assert_eq!(
        bernoulli_ratio(4, 3, &mut rng),
        Err(DpError::InvalidProbability)
    );
    assert_eq!(
        bernoulli_ratio(u64::MAX, u64::MAX - 1, &mut rng),
        Err(DpError::InvalidProbability)
    );
    for _ in 0..2_000 {
        assert_eq!(bernoulli_ratio(0, 7, &mut rng), Ok(false));
        assert_eq!(bernoulli_ratio(7, 7, &mut rng), Ok(true));
        assert_eq!(bernoulli_ratio(u64::MAX, u64::MAX, &mut rng), Ok(true));
        assert_eq!(bernoulli_ratio(0, u64::MAX, &mut rng), Ok(false));
    }
    const N: usize = 120_000;
    for (num, den) in [(1u64, 3u64), (2, 7), (u64::MAX / 3, u64::MAX), (1, 2)] {
        let c = (0..N)
            .filter(|_| bernoulli_ratio(num, den, &mut rng).expect("valid"))
            .count();
        within(c, N, num as f64 / den as f64, &format!("{num}/{den}"));
    }
}

#[test]
fn every_new_mechanism_draws_a_number_of_words_fixed_by_its_public_parameters() {
    let mut rng = SecureRng::from_key([31; 32]);
    let words = |rng: &mut SecureRng, f: &mut dyn FnMut(&mut SecureRng)| {
        let before = rng.words_drawn();
        f(rng);
        rng.words_drawn() - before
    };
    // bernoulli_ratio: one 256-bit draw
    for (num, den) in [(0u64, 5u64), (5, 5), (1, u64::MAX)] {
        assert_eq!(
            words(&mut rng, &mut |r| {
                let _ = bernoulli_ratio(num, den, r);
            }),
            4
        );
    }
    // dp_int: same count for every value and draw
    let base = words(&mut rng, &mut |r| {
        let _ = dp_int(0, 3, 1.5, r);
    });
    for v in [i64::MIN, -1, 1, i64::MAX] {
        for _ in 0..20 {
            assert_eq!(
                words(&mut rng, &mut |r| {
                    let _ = dp_int(v, 3, 1.5, r);
                }),
                base,
                "v = {v}"
            );
        }
    }
    // randomized_response: 105 rounds of (1 coin word + (⌊ε⌋ + 1) · 32 steps · 4 words)
    for (eps, whole) in [(0.5, 0u64), (2.75, 2), (5.0, 5)] {
        let expect = 105 * (1 + (whole + 1) * 32 * 4);
        for bit in [false, true] {
            for _ in 0..10 {
                assert_eq!(
                    words(&mut rng, &mut |r| {
                        let _ = randomized_response(bit, eps, r);
                    }),
                    expect,
                    "ε = {eps}, bit = {bit}"
                );
            }
        }
    }
}

/// Bit-level pins (change detectors, recorded from this implementation): the
/// first outputs for a fixed key. A change here means the sampler's
/// arithmetic or keystream use changed, which a replay or audit would see.
#[test]
fn golden_outputs_for_a_fixed_key() {
    let mut rng = SecureRng::from_key([0x42; 32]);
    let ints: Vec<i64> = (0..8)
        .map(|_| dp_int(100, 2, 1.0, &mut rng).expect("valid"))
        .collect();
    let rr: Vec<bool> = (0..16)
        .map(|i| randomized_response(i % 2 == 0, 1.0, &mut rng).expect("valid"))
        .collect();
    let bern: Vec<bool> = (0..16)
        .map(|_| bernoulli_ratio(1, 3, &mut rng).expect("valid"))
        .collect();
    let got = format!("{ints:?} {rr:?} {bern:?}");
    if std::env::var_os("DP_PRINT_GOLDEN").is_some() {
        println!("{got}");
        return;
    }
    assert_eq!(got, GOLDEN);
}

const GOLDEN: &str = "[104, 100, 103, 101, 100, 102, 105, 101] [true, false, true, false, false, false, true, false, true, false, false, false, true, false, true, false] [true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false]";
