//! ALICE-Law G4: signed zeros and exact cancellations of the real-valued
//! mechanisms against fixed bit patterns
//!
//! CI runs this file in the debug and the release profile on x86_64 (ubuntu)
//! and aarch64 (macOS); every pattern must hold on all four.

use alice_crypto::dp::{dp_sum, DpNoise, SecureRng};

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A sum of +0 and of -0 rounds to the same lattice point (index 0), so with
/// the same key the two results are the same bits, and they are the recorded
/// ones
#[test]
fn dp_sum_of_signed_zeros_is_the_same_bits() {
    let mut a = SecureRng::from_key(key(1));
    let mut b = SecureRng::from_key(key(1));
    let mut pos = Vec::new();
    let mut neg = Vec::new();
    for _ in 0..64 {
        pos.extend_from_slice(
            &dp_sum(0.0, 1.0, 1.0, &mut a)
                .unwrap()
                .to_bits()
                .to_le_bytes(),
        );
        neg.extend_from_slice(
            &dp_sum(-0.0, 1.0, 1.0, &mut b)
                .unwrap()
                .to_bits()
                .to_le_bytes(),
        );
    }
    assert_eq!(pos, neg);
    let first: Vec<u64> = pos
        .as_chunks::<8>()
        .0
        .iter()
        .take(8)
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    assert_eq!(first, RECORDED_ZERO_SUMS);
}

const RECORDED_ZERO_SUMS: [u64; 8] = [
    0x3fe2586a00000000,
    0xbfd4a72000000000,
    0xbfe4872a00000000,
    0x3f8a268000000000,
    0xbfd42be800000000,
    0xc00a9e1680000000,
    0xbfb29cf000000000,
    0xbfdd356000000000,
];

/// A value on the lattice comes back as that value plus a whole number of
/// lattice steps: (privatize(x) - x) / step is an exact integer, so the
/// subtraction cancels exactly (no rounding residue)
#[test]
fn privatize_of_a_lattice_point_cancels_exactly() {
    let mut noise = DpNoise::with_key(1.0, 1.0, key(2));
    let step = 1.0 / 1_048_576.0; // 2^-20, a power of two below the sensitivity
    for k in -64_i32..64 {
        let x = f64::from(k) * 0.5;
        let y = noise.privatize(x).unwrap();
        let steps = (y - x) / step;
        assert_eq!(steps, steps.trunc(), "x = {x}: {y} - {x} is {steps} steps");
    }
}

/// The guaranteed epsilon, `epsilon * lattice * (floor(sensitivity / lattice) + 1) / sensitivity`,
/// for a few (sensitivity, epsilon): the recorded bits
#[test]
fn effective_epsilon_is_the_recorded_bits() {
    let got: Vec<u64> = [
        (1.0_f64, 1.0_f64),
        (1.0, 0.5),
        (0.3, 2.0),
        (7.0, 0.1),
        (1e-3, 3.0),
    ]
    .into_iter()
    .map(|(s, e)| {
        DpNoise::with_key(s, e, key(3))
            .effective_epsilon()
            .to_bits()
    })
    .collect();
    assert_eq!(got, RECORDED_EPSILONS);
}

// (1, 1) is 1 + 2^-20 (measured): the lattice rounding of a sensitivity that is itself a
// power of two still adds one lattice step, as the formula says
const RECORDED_EPSILONS: [u64; 5] = [
    0x3ff0000100000000,
    0x3fe0000100000000,
    0x40000000aaaaaaab,
    0x3fb9999a83a83a85,
    0x4008000042000000,
];
