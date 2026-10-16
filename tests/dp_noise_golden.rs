//! Pins the differential-privacy noise stream of [`DpNoise::with_key`] bit for
//! bit (ALICE-Law G10: no run-varying artifacts).
//!
//! The other dp tests check properties: that a key reproduces a stream within
//! one run, and that the noise has the declared distribution. Neither notices a
//! change that keeps those properties but changes the values: a different
//! keystream layout (nonce or counter placement), a different order of draws,
//! or a sampler that consumes words differently. Any of those changes the
//! noise a stored key reproduces, so an audit that replays an old key would no
//! longer match. This test fixes the stream itself: a fixed key, 64 calls of
//! `privatize`, and a BLAKE3 digest of the output bits, run on every OS of the
//! CI test matrix.
//!
//! The expected digest was recorded from this implementation (there is no
//! independent closed form for a keyed stream). Changing it is a change of the
//! noise every existing key reproduces: it needs a version bump and a
//! CHANGELOG entry saying so.

use alice_crypto::dp::DpNoise;
use alice_crypto::hash::hash;

const KEY: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
const SENSITIVITY: f64 = 10.0;
const EPSILON: f64 = 0.5;
const CALLS: usize = 64;
const EXPECTED: &str = "010d2210f7a5595a67533309ce8040759e019f6583c52c63999d76d7da40910c";

fn outputs() -> Vec<f64> {
    let mut noise = DpNoise::with_key(SENSITIVITY, EPSILON, KEY);
    (0..CALLS)
        .map(|i| {
            // inputs on and off the lattice, positive and negative
            #[allow(clippy::cast_precision_loss)]
            let x = (i as f64) * 1.375 - 40.0;
            noise.privatize(x).expect("in range")
        })
        .collect()
}

fn digest(values: &[f64]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for v in values {
        bytes.extend_from_slice(&v.to_bits().to_le_bytes());
    }
    hash(&bytes)
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn the_noise_stream_of_a_fixed_key_is_pinned() {
    let values = outputs();
    // compared something: 64 outputs, and noise was actually added (an
    // identity `privatize` would return the rounded inputs)
    assert_eq!(values.len(), CALLS);
    let noisy = values
        .iter()
        .enumerate()
        .filter(|&(i, &v)| {
            #[allow(clippy::cast_precision_loss)]
            let x = (i as f64) * 1.375 - 40.0;
            (v - x).abs() > 1e-3
        })
        .count();
    assert!(noisy >= CALLS / 2, "only {noisy} of {CALLS} outputs moved");
    assert_eq!(digest(&values), EXPECTED);
}
