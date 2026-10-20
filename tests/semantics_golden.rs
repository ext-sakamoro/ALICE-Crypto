//! Recorded bits of the outputs this crate computes for a fixed key
//!
//! Each scenario runs the public differential-privacy entry points with a
//! fixed key and hashes the output bits with SHA-256. The digests are the
//! entries `CRYPTO_SEMANTICS_PINS` (src/semantics.rs) folds;
//! `tests/crypto_semantics_id.rs` reads them from this file. These are change
//! detectors: the distribution checks of the same functions are in the
//! `dp_*_oracle` tests.

use alice_crypto::dp::{
    bernoulli_ratio, dp_count, dp_int, dp_sum, randomized_response, DpNoise, SecureRng,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The SHA-256 of `bytes` when it is not `expected`
fn golden_mismatch(bytes: &[u8], expected: &str) -> Option<String> {
    let got = hex(&Sha256::digest(bytes));
    (got != expected).then_some(got)
}

fn assert_golden(name: &str, bytes: &[u8], expected: &str) {
    if let Some(got) = golden_mismatch(bytes, expected) {
        panic!("scenario {name:?} moved to {got}: re-record only for an intended change");
    }
}

#[test]
fn checker_rejects_a_wrong_digest() {
    let recorded = hex(&Sha256::digest(b"recorded bits"));
    assert_eq!(golden_mismatch(b"recorded bits", &recorded), None);
    assert!(
        golden_mismatch(b"moved bits", &recorded).is_some(),
        "a scenario whose bits moved must not match its recorded digest"
    );
}

fn key(n: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = n.wrapping_mul(31).wrapping_add(u8::try_from(i).unwrap());
    }
    k
}

#[test]
fn keystream_is_the_recorded_bits() {
    let mut rng = SecureRng::from_key(key(1));
    let mut out = Vec::new();
    for _ in 0..4096 {
        out.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    assert_golden(
        "keystream",
        &out,
        "a6440bde6bb939a6a8e949d28601a1f853ab3016b50b7d6f96111a1caa1e72e7",
    );
}

#[test]
fn open_interval_draws_are_the_recorded_bits() {
    let mut rng = SecureRng::from_key(key(2));
    let mut out = Vec::new();
    for _ in 0..4096 {
        out.extend_from_slice(&rng.next_f64_open01().to_bits().to_le_bytes());
    }
    assert_golden(
        "open interval draws",
        &out,
        "2ce199356fb0dd23f8167eac3816ca619de1453bc1c58709ee69c32dc104a746",
    );
}

#[test]
fn integer_mechanisms_are_the_recorded_bits() {
    let mut out = Vec::new();
    for (i, eps) in [0.25_f64, 0.5, 1.0, 2.0].into_iter().enumerate() {
        let mut rng = SecureRng::from_key(key(3 + u8::try_from(i).unwrap()));
        for c in 0..256_u64 {
            out.extend_from_slice(&dp_count(c * 7, eps, &mut rng).unwrap().to_le_bytes());
            let v = i64::try_from(c).unwrap() - 128;
            out.extend_from_slice(&dp_int(v, 3, eps, &mut rng).unwrap().to_le_bytes());
        }
    }
    assert_golden(
        "integer mechanisms",
        &out,
        "54474a9cfb7d67eea2e136c533a0d362ac4271a950cc4b9b62c6bd71bb6098aa",
    );
}

#[test]
fn real_valued_mechanisms_are_the_recorded_bits() {
    let mut out = Vec::new();
    let mut rng = SecureRng::from_key(key(9));
    for c in 0..256_u32 {
        let x = f64::from(c) * 0.75 - 96.0;
        out.extend_from_slice(
            &dp_sum(x, 1.0, 0.5, &mut rng)
                .unwrap()
                .to_bits()
                .to_le_bytes(),
        );
    }
    let mut noise = DpNoise::with_key(2.0, 1.0, key(10));
    for c in 0..256_u32 {
        let x = f64::from(c) / 8.0 - 16.0;
        out.extend_from_slice(&noise.privatize(x).unwrap().to_bits().to_le_bytes());
    }
    assert_golden(
        "real-valued mechanisms",
        &out,
        "4898f0d307a200ff351e94123f047f787d565bbeb15f5d0eb84d5a30ee3eb563",
    );
}

#[test]
fn boolean_mechanisms_are_the_recorded_bits() {
    let mut out = Vec::new();
    let mut rng = SecureRng::from_key(key(11));
    for c in 0..512_u32 {
        let bit = c % 3 == 0;
        out.extend_from_slice(&[u8::from(randomized_response(bit, 1.5, &mut rng).unwrap())]);
        out.extend_from_slice(&[u8::from(bernoulli_ratio(3, 7, &mut rng).unwrap())]);
    }
    assert_golden(
        "boolean mechanisms",
        &out,
        "8a52c5ca878a2837e0069e09c34c4373e16e8801cdeaf1a208463044476bffd1",
    );
}
