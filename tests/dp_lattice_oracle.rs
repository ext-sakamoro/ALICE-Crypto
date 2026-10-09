//! Continuous values are privatized on a lattice with exact integer noise.
//!
//! `DpNoise::privatize(x)` and `dp_sum` round `x` to the nearest multiple of
//! `Λ = 2^(⌊log2 Δ⌋ − 20)` and add `Λ · Z`, `Z` discrete Laplace with decay
//! `ε·Λ/Δ` per lattice step, drawn by the same integer sampler as `dp_count`.
//! Values within Δ of each other round at most `⌊Δ/Λ⌋ + 1` steps apart, so the
//! guarantee is `ε_eff = ε·Λ·(⌊Δ/Λ⌋ + 1)/Δ ≤ ε·(1 + 2^-20)`.
//!
//! Reference values for Λ and ε_eff were computed with Python's
//! `fractions.Fraction` on the exact `f64` inputs, independently of this crate.

use alice_crypto::dp::{dp_sum, DpError, DpNoise, SecureRng};

/// (Δ, ε, Λ, ε_eff) from `fractions.Fraction`
const REFERENCE: [(f64, f64, f64, f64); 4] = [
    (1.0, 1.0, 9.536_743_164_062_5e-7, 1.000_000_953_674_316_4),
    (3.0, 0.5, 1.907_348_632_812_5e-6, 0.500_000_317_891_438_8),
    (10.0, 0.1, 7.629_394_531_25e-6, 0.100_000_076_293_945_32),
    (0.25, 2.0, 2.384_185_791_015_625e-7, 2.000_001_907_348_633),
];

#[test]
fn the_lattice_and_the_effective_epsilon_match_the_exact_reference() {
    for (delta, eps, lattice, eff) in REFERENCE {
        let n = DpNoise::with_key(delta, eps, [1u8; 32]);
        assert_eq!(
            n.lattice().to_bits(),
            lattice.to_bits(),
            "Λ for Δ = {delta}"
        );
        let got = n.effective_epsilon();
        assert!(
            (got - eff).abs() <= eff * 1e-15,
            "ε_eff for Δ = {delta}, ε = {eps}: {got} vs {eff}"
        );
        assert!(
            got <= eps * (1.0 + 1.0 / 1_048_576.0),
            "ε_eff exceeds ε·(1 + 2^-20)"
        );
    }
}

#[test]
fn every_output_is_an_exact_multiple_of_the_lattice() {
    for (delta, eps, lattice, _) in REFERENCE {
        let mut n = DpNoise::with_key(delta, eps, [2u8; 32]);
        for i in 0..2_000 {
            let x = 123.456 + f64::from(i) * 0.789;
            let y = n.privatize(x).expect("in range");
            let steps = y / lattice;
            assert_eq!(
                steps,
                steps.trunc(),
                "Δ = {delta}: {y} is not a multiple of Λ = {lattice}"
            );
        }
    }
}

#[test]
fn the_value_is_rounded_to_the_nearest_lattice_point_before_the_noise() {
    let lattice = REFERENCE[0].2;
    let base = 5.0 * lattice;
    // the same key gives the same noise, so the outputs differ by the rounding only
    let out = |x: f64| {
        DpNoise::with_key(1.0, 1.0, [3u8; 32])
            .privatize(x)
            .expect("in range")
    };
    assert_eq!(out(base + 0.4 * lattice), out(base), "0.4 Λ rounds down");
    assert_eq!(out(base - 0.4 * lattice), out(base), "−0.4 Λ rounds up");
    assert_eq!(
        out(base + 0.6 * lattice) - out(base),
        lattice,
        "0.6 Λ rounds up one step"
    );
}

#[test]
fn the_noise_has_the_laplace_variance_of_the_declared_scale() {
    // in real units the lattice noise has variance ≈ 2·(Δ/ε)² (Λ is 2^-20 Δ)
    for (delta, eps) in [(1.0, 1.0), (3.0, 0.5)] {
        let mut n = DpNoise::with_key(delta, eps, [4u8; 32]);
        let xs: Vec<f64> = (0..30_000)
            .map(|_| n.privatize(0.0).expect("in range"))
            .collect();
        let len = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / len;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / len;
        let b = delta / eps;
        assert!(mean.abs() < 0.05 * b, "Δ = {delta}: mean {mean}");
        assert!(
            (var - 2.0 * b * b).abs() / (2.0 * b * b) < 0.08,
            "Δ = {delta}: variance {var} vs {}",
            2.0 * b * b
        );
    }
}

#[test]
fn dp_sum_is_the_same_mechanism_as_dp_noise() {
    let mut rng = SecureRng::from_key([5u8; 32]);
    let mut noise = DpNoise::with_key(10.0, 0.1, [5u8; 32]);
    for x in [0.0, 500.25, -73.5] {
        assert_eq!(
            dp_sum(x, 10.0, 0.1, &mut rng).expect("valid").to_bits(),
            noise.privatize(x).expect("valid").to_bits()
        );
    }
}

/// The noise is `Λ · Z` with `Z` an integer: there is no sub-lattice part, so
/// the floating-point inverse transform's low bits (Mironov 2012) are gone.
/// The implementation this replaced returned `x + (−b·ln u)`, whose distance to
/// the lattice carried the low bits of `u`.
#[test]
fn no_part_of_the_output_lies_below_the_lattice() {
    let mut rng = SecureRng::from_key([6u8; 32]);
    let lattice = REFERENCE[2].2;
    let x = 500.0; // a multiple of Λ = 2^-17
    for _ in 0..1_000 {
        let y = dp_sum(x, 10.0, 0.1, &mut rng).expect("valid");
        let noise_steps = (y - x) / lattice;
        assert_eq!(
            noise_steps,
            noise_steps.trunc(),
            "noise {} has a sub-lattice part",
            y - x
        );
    }
}

#[test]
fn unusable_parameters_and_values_are_refused() {
    for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert_eq!(
            DpNoise::try_with_key(bad, 1.0, [0; 32]).err(),
            Some(DpError::InvalidScale),
            "Δ = {bad}"
        );
        assert_eq!(
            DpNoise::try_with_key(1.0, bad, [0; 32]).err(),
            Some(DpError::InvalidScale),
            "ε = {bad}"
        );
    }
    assert_eq!(
        DpNoise::try_with_key(1.0, 1e-300, [0; 32]).err(),
        Some(DpError::EpsilonOutOfRange)
    );
    let mut n = DpNoise::with_key(1.0, 1.0, [0; 32]);
    for x in [f64::NAN, f64::INFINITY, 1e300, 5e9] {
        // 5e9 / 2^-20 ≈ 5.2e15 ≥ 2^52
        assert_eq!(n.privatize(x), Err(DpError::ValueOutOfRange), "x = {x}");
    }
    let mut rng = SecureRng::from_key([0; 32]);
    assert_eq!(dp_sum(1.0, 0.0, 1.0, &mut rng), Err(DpError::InvalidScale));
    assert_eq!(
        dp_sum(f64::NAN, 1.0, 1.0, &mut rng),
        Err(DpError::ValueOutOfRange)
    );
}
