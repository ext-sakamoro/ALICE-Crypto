//! `dp_count` adds discrete Laplace noise sampled with integer arithmetic only.
//!
//! The floating-point inverse transform `-b·ln(u)` leaks the low bits of `u`
//! through the low bits of its result (Mironov 2012), however good the
//! uniform source is. A count is an integer, so its noise can be an integer:
//! the discrete Laplace distribution
//!
//! ```text
//! P(Z = z) = (1 − e^−ε) / (1 + e^−ε) · e^(−ε·|z|)
//! ```
//!
//! sampled exactly with the Bernoulli(e^−γ) construction of Canonne, Kamath and
//! Steinke ("The Discrete Gaussian for Differential Privacy", NeurIPS 2020,
//! Algorithms 1 and 2), with ε converted exactly from its `f64` value to a
//! rational. No floating-point `ln` or `exp` is involved, and the output is an
//! integer, so nothing below the integer grid can carry information.
//!
//! Expected values come from the closed form above. Frequencies are compared
//! within 6 standard errors of the binomial count, so a correct sampler fails
//! with probability far below 1e-8 per comparison.

use alice_crypto::dp::{dp_count, DpError, SecureRng};

const N: usize = 30_000;

/// P(Z = z) for the discrete Laplace distribution with parameter ε
fn pmf(eps: f64, z: i64) -> f64 {
    let q = (-eps).exp();
    (1.0 - q) / (1.0 + q) * q.powi(i32::try_from(z.abs()).expect("small"))
}

/// Draw N noises (output − true count) with a fixed key
fn noises(eps: f64, key: u8) -> Vec<i64> {
    let mut rng = SecureRng::from_key([key; 32]);
    (0..N)
        .map(|_| dp_count(1_000, eps, &mut rng).expect("valid ε") - 1_000)
        .collect()
}

fn count_of(xs: &[i64], z: i64) -> usize {
    xs.iter().filter(|&&x| x == z).count()
}

/// |observed − expected| within 6 binomial standard errors
fn assert_frequency(xs: &[i64], z: i64, p: f64, what: &str) {
    let n = xs.len() as f64;
    let observed = count_of(xs, z) as f64;
    let expected = n * p;
    let sd = (n * p * (1.0 - p)).sqrt();
    assert!(
        (observed - expected).abs() <= 6.0 * sd.max(1.0),
        "{what}: P(Z = {z}) observed {observed} of {n}, expected {expected:.1} (sd {sd:.1})"
    );
}

#[test]
fn dp_count_returns_an_integer_count() {
    let mut rng = SecureRng::from_key([3u8; 32]);
    let c: i64 = dp_count(1_000, 1.0, &mut rng).expect("ε = 1 is valid");
    // the noise is an integer by type: there are no low bits below the integer
    // grid for a floating-point transform to leak through
    let _ = c;
}

#[test]
fn the_noise_follows_the_discrete_laplace_pmf_at_epsilon_one() {
    let xs = noises(1.0, 7);
    for z in -6..=6 {
        assert_frequency(&xs, z, pmf(1.0, z), "ε = 1");
    }
}

#[test]
fn the_noise_follows_the_pmf_for_a_non_dyadic_epsilon() {
    // 0.1 is not a dyadic rational; its f64 value is converted exactly
    let eps = 0.1;
    let xs = noises(eps, 11);
    for z in [-20, -5, -1, 0, 1, 5, 20] {
        assert_frequency(&xs, z, pmf(eps, z), "ε = 0.1");
    }
    // variance 2q / (1 − q)² with q = e^−ε
    let q = (-eps).exp();
    let var_expected = 2.0 * q / (1.0 - q).powi(2);
    let n = xs.len() as f64;
    let mean = xs.iter().map(|&x| x as f64).sum::<f64>() / n;
    let var = xs.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n;
    assert!(mean.abs() < 0.2, "mean {mean} is not 0");
    assert!(
        (var - var_expected).abs() / var_expected < 0.08, // 6σ of the variance estimate at N = 30k
        "variance {var} vs 2q/(1−q)² = {var_expected}"
    );
}

#[test]
fn the_noise_is_symmetric_and_the_ratio_of_neighbours_is_e_to_minus_epsilon() {
    let eps = 0.5;
    let xs = noises(eps, 13);
    for z in 1..=4 {
        let plus = count_of(&xs, z) as f64;
        let minus = count_of(&xs, -z) as f64;
        let sd = (plus + minus).sqrt();
        assert!(
            (plus - minus).abs() <= 6.0 * sd,
            "P(Z = {z}) {plus} vs P(Z = −{z}) {minus}"
        );
    }
    let c0 = count_of(&xs, 0) as f64;
    let c1 = count_of(&xs, 1) as f64;
    let ratio = c1 / c0;
    // standard error of a ratio of counts ≈ ratio · sqrt(1/c1 + 1/c0)
    let se = ratio * (1.0 / c1 + 1.0 / c0).sqrt();
    assert!(
        (ratio - (-eps).exp()).abs() <= 6.0 * se,
        "P(1)/P(0) = {ratio}, expected e^−ε = {}",
        (-eps).exp()
    );
}

#[test]
fn the_same_key_reproduces_the_same_counts_and_another_key_does_not() {
    assert_eq!(noises(1.0, 5)[..256], noises(1.0, 5)[..256]);
    assert_ne!(noises(1.0, 5)[..256], noises(1.0, 6)[..256]);
}

/// Degenerate inputs are refused with an explicit error, not turned into noise
/// of 0, NaN or a saturated count.
#[test]
fn unusable_epsilons_and_counts_are_refused() {
    let mut rng = SecureRng::from_key([1u8; 32]);
    for eps in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            dp_count(1, eps, &mut rng),
            Err(DpError::InvalidScale),
            "ε = {eps}"
        );
    }
    // ε outside the range whose exact rational the sampler can hold
    for eps in [1e-300, f64::MIN_POSITIVE, 1e300] {
        assert_eq!(
            dp_count(1, eps, &mut rng),
            Err(DpError::EpsilonOutOfRange),
            "ε = {eps}"
        );
    }
    // a true count that does not fit the signed result
    assert_eq!(
        dp_count(u64::MAX, 1.0, &mut rng),
        Err(DpError::CountOutOfRange)
    );
}
