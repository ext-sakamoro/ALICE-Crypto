//! Fixes the differential-privacy noise source as a law.
//!
//! Three properties, and the ε claim collapses if any one of them is missing:
//!
//! 1. **Unpredictability** — without the key the noise cannot be reproduced,
//!    so it cannot be subtracted back out.
//! 2. **Reproducibility** — with the key it can, which is what makes replay,
//!    audit and testing possible.
//! 3. **Distribution** — the noise has mean 0 and the variance 2b² of
//!    `Laplace(0, b)` with `b = Δ/ε` (it is discrete Laplace on a lattice of
//!    `2^-20 Δ`, see `tests/dp_lattice_oracle.rs`), so the ε that was
//!    calculated matches the noise that was added.
//!
//! The implementations this replaced satisfied neither 1 nor 3:
//! `xorshift64` seeded from the clock, with its state handed to the caller (the
//! state is recoverable from 64 output bits — xorshift is F2-linear, so no
//! brute force is needed), and a 20-term series for `ln` that returned a magic
//! `-100.0` outside its domain.
//!
//! Expected values come from the definition of the Laplace distribution (mean
//! 0, variance 2b²) and from RFC 8439's published keystream. ⚠️ **Not one value
//! here was read off the implementation's output.**

use alice_crypto::dp::{dp_count, dp_sum, DpNoise, SecureRng};

/// A test key. In production this comes from OS entropy or a key store — never
/// from a clock.
fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

// ---------------------------------------------------------------------------
// The keystream is RFC 8439's, not "whatever the dependency does"
// ---------------------------------------------------------------------------

/// RFC 8439 § 2.3.2 key (0x00..0x1f ascending)
fn rfc_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::try_from(i).expect("0..32 fits in u8");
    }
    k
}

/// RFC 8439 § 2.3.2 keystream for block counter 1, transcribed from the RFC
/// (`https://www.rfc-editor.org/rfc/rfc8439.txt`), never from an implementation
const RFC_KEYSTREAM_BLOCK_1: [u8; 64] = [
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
];

#[test]
fn the_keystream_is_the_one_rfc_8439_publishes() {
    // The RFC's vector uses nonce 00:00:00:09:00:00:00:4a:00:00:00:00 and block
    // counter 1. `SecureRng` lays the 64-bit block index out as counter in the
    // low 32 bits and nonce bytes 4..8 in the high 32, so that exact pair is
    // not reachable through its constructor — the vector is checked against the
    // dependency directly, which is what pins the arithmetic the noise rests
    // on. Without this the suite would only say "the noise is self-consistent".
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut cipher = chacha20::ChaCha20::new(&rfc_key().into(), &nonce.into());
    cipher.seek(64u64); // block counter 1
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);
    assert_eq!(
        block, RFC_KEYSTREAM_BLOCK_1,
        "the keystream does not match RFC 8439 § 2.3.2"
    );
}

#[test]
fn the_stream_is_the_keystream_and_not_something_derived_from_it() {
    // `SecureRng::from_key` must hand out the raw keystream of block 0 with
    // nonce 0 — if it post-processed the bytes, the RFC vector above would stop
    // saying anything about the noise.
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let k = key(0x5a);
    let mut cipher = chacha20::ChaCha20::new(&k.into(), &[0u8; 12].into());
    let mut expected = [0u8; 64];
    cipher.apply_keystream(&mut expected);

    let mut rng = SecureRng::from_key(k);
    // Indexed rather than `chunks_exact(8)` / `as_chunks::<8>()`: MSRV-aware
    // clippy asks for the opposite one depending on whether `rust-version` is
    // declared, so neither form travels between sibling crates.
    for i in 0..8 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&expected[i * 8..i * 8 + 8]);
        let want = u64::from_le_bytes(word);
        assert_eq!(rng.next_u64(), want, "word {i} is not the raw keystream");
    }
}

// ---------------------------------------------------------------------------
// 1 + 2: unpredictable without the key, reproducible with it
// ---------------------------------------------------------------------------

#[test]
fn the_same_key_reproduces_the_same_noise() {
    let mut a = DpNoise::with_key(1.0, 1.0, key(7));
    let mut b = DpNoise::with_key(1.0, 1.0, key(7));
    let xs: Vec<u64> = (0..256)
        .map(|_| a.privatize(0.0).expect("in range").to_bits())
        .collect();
    let ys: Vec<u64> = (0..256)
        .map(|_| b.privatize(0.0).expect("in range").to_bits())
        .collect();
    assert_eq!(xs, ys, "the same key must give the same sequence");
    // Teeth: it is not simply returning a constant.
    let distinct = xs.iter().collect::<std::collections::BTreeSet<_>>().len();
    assert!(distinct > 240, "only {distinct} distinct values out of 256");
}

#[test]
fn a_different_key_gives_a_different_noise_sequence() {
    let mut a = DpNoise::with_key(1.0, 1.0, key(7));
    let mut b = DpNoise::with_key(1.0, 1.0, key(8));
    let xs: Vec<u64> = (0..64)
        .map(|_| a.privatize(0.0).expect("in range").to_bits())
        .collect();
    let ys: Vec<u64> = (0..64)
        .map(|_| b.privatize(0.0).expect("in range").to_bits())
        .collect();
    let shared = xs.iter().zip(ys.iter()).filter(|(x, y)| x == y).count();
    assert_eq!(shared, 0, "{shared} values coincided across different keys");
}

// ---------------------------------------------------------------------------
// 3: the distribution is the one ε was calculated from
// ---------------------------------------------------------------------------

#[test]
fn the_distribution_is_laplace_with_mean_zero_and_variance_two_b_squared() {
    // Expected values from the definition: E[X] = 0, Var[X] = 2b².
    for b in [0.5f64, 1.0, 4.0] {
        let mut n = DpNoise::with_key(b, 1.0, key(42));
        let count = 30_000;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..count {
            let x = n.privatize(0.0).expect("in range");
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / f64::from(count);
        let var = sum_sq / f64::from(count) - mean * mean;
        assert!(
            mean.abs() < 0.05 * b,
            "b = {b}: mean {mean} is too far from 0"
        );
        let want = 2.0 * b * b;
        assert!(
            ((var - want) / want).abs() < 0.08, // 6σ of the variance estimate at 30k draws
            "b = {b}: variance {var} does not match 2b² = {want}"
        );
    }
}

#[test]
fn both_tails_are_produced() {
    // Catches a sign taken from the wrong place in the inverse transform.
    let mut n = DpNoise::with_key(1.0, 1.0, key(3));
    let (mut neg, mut pos) = (0u32, 0u32);
    for _ in 0..10_000 {
        if n.privatize(0.0).expect("in range") < 0.0 {
            neg += 1;
        } else {
            pos += 1;
        }
    }
    assert!(
        neg > 4_500 && pos > 4_500,
        "sign skew: {neg} negative / {pos} positive"
    );
}

#[test]
fn the_noise_never_returns_a_magic_constant() {
    // The implementation this replaced returned -100.0 outside its `ln` domain,
    // which was not a probability-zero event but a path `u → 0` reached.
    let mut n = DpNoise::with_key(1.0, 1.0, key(5));
    for _ in 0..20_000 {
        let x = n.privatize(0.0).expect("in range");
        assert!(x.is_finite(), "non-finite noise {x}");
        assert!(
            (x - -100.0).abs() > 1e-12 || x.abs() < 1e-9,
            "the magic -100.0 appeared"
        );
    }
}

// ---------------------------------------------------------------------------
// The public API must actually use its ε
// ---------------------------------------------------------------------------

#[test]
fn dp_count_and_dp_sum_add_noise_of_the_declared_scale() {
    let spread = |eps: f64| -> f64 {
        let mut n = DpNoise::with_key(1.0 / eps, 1.0, key(11));
        let xs: Vec<f64> = (0..20_000)
            .map(|_| n.privatize(0.0).expect("in range"))
            .collect();
        let len = f64::from(u32::try_from(xs.len()).expect("count fits in u32"));
        let mean = xs.iter().sum::<f64>() / len;
        (xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / len).sqrt()
    };
    let (tight, loose) = (spread(4.0), spread(0.25));
    assert!(
        loose > tight * 8.0,
        "spread at ε = 0.25 ({loose}) is too small next to ε = 4 ({tight})"
    );

    // The public functions add noise at all (they are not pass-throughs).
    let mut r1 = SecureRng::from_key(key(13));
    let mut r2 = SecureRng::from_key(key(13));
    let c = dp_count(1_000, 1.0, &mut r1).expect("ε = 1 is valid");
    let s = dp_sum(500.0, 10.0, 1.0, &mut r2).expect("valid arguments");
    // discrete Laplace puts mass (1 − e^−ε)/(1 + e^−ε) ≈ 0.46 on 0 at ε = 1, so
    // one call may legitimately add nothing; 20 calls all adding 0 has
    // probability ≈ 0.46^20 < 2^-22
    let mut r4 = SecureRng::from_key(key(13));
    let moved = (0..20)
        .filter(|_| dp_count(1_000, 1.0, &mut r4).expect("valid") != 1_000)
        .count();
    assert!(moved > 0, "dp_count added no noise in 20 calls");
    assert!((s - 500.0).abs() > 0.0, "dp_sum added no noise");

    // Same key, same call order, same answer.
    let mut r3 = SecureRng::from_key(key(13));
    assert_eq!(dp_count(1_000, 1.0, &mut r3).expect("valid"), c);

    // ⚠️ ε has to take effect — this is the assertion that kills a wiring
    // mutation where the parameter is accepted and dropped.
    let widths: Vec<f64> = [4.0f64, 0.25]
        .iter()
        .map(|&eps| {
            let mut r = SecureRng::from_key(key(17));
            let xs: Vec<f64> = (0..4_000)
                .map(|_| dp_count(0, eps, &mut r).expect("valid") as f64)
                .collect();
            let len = f64::from(u32::try_from(xs.len()).expect("count fits in u32"));
            let m = xs.iter().sum::<f64>() / len;
            (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / len).sqrt()
        })
        .collect();
    assert!(
        widths[1] > widths[0] * 8.0,
        "spread at ε = 0.25 ({}) is too small next to ε = 4 ({}) — ε is being ignored",
        widths[1],
        widths[0]
    );

    // Invalid arguments are refused rather than silently producing garbage.
    let mut r = SecureRng::from_key(key(19));
    assert!(dp_count(1, 0.0, &mut r).is_err());
    assert!(dp_count(1, f64::NAN, &mut r).is_err());
    assert!(dp_sum(1.0, 0.0, 1.0, &mut r).is_err());
    assert!(dp_sum(1.0, 1.0, f64::INFINITY, &mut r).is_err());
}

#[test]
fn an_invalid_scale_is_refused_instead_of_silently_producing_garbage() {
    assert!(
        DpNoise::try_with_key(0.0, 1.0, key(1)).is_err(),
        "accepted scale = 0"
    );
    assert!(
        DpNoise::try_with_key(-1.0, 1.0, key(1)).is_err(),
        "accepted a negative scale"
    );
    assert!(
        DpNoise::try_with_key(f64::NAN, 1.0, key(1)).is_err(),
        "accepted NaN"
    );
    assert!(
        DpNoise::try_with_key(f64::INFINITY, 1.0, key(1)).is_err(),
        "accepted an infinite scale"
    );
    assert!(DpNoise::try_with_key(1e-6, 1.0, key(1)).is_ok());
}

#[test]
fn the_uniform_draw_never_returns_zero() {
    // `ln(0)` is -inf, so a 0 here would make the noise infinite. The draw is
    // specified as (0, 1].
    let mut rng = SecureRng::from_key(key(23));
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for _ in 0..200_000 {
        let u = rng.next_f64_open01();
        assert!(u > 0.0, "the uniform draw returned {u}");
        assert!(u <= 1.0, "the uniform draw returned {u}");
        min = min.min(u);
        max = max.max(u);
    }
    // Teeth: it covers the range rather than sitting in one spot.
    assert!(
        min < 0.001,
        "smallest draw was {min} — the range is not covered"
    );
    assert!(
        max > 0.999,
        "largest draw was {max} — the range is not covered"
    );
}
