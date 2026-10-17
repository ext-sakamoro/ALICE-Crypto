//! Content hash of the outputs this crate computes for a key:
//! [`CRYPTO_SEMANTICS_ID`] (ALICE-Law G6)
//!
//! The recorded-bit tests in `tests/semantics_golden.rs` pin what the
//! differential-privacy entry points return for fixed keys: the keystream,
//! the open-interval draws, the integer mechanisms (`dp_count`, `dp_int`),
//! the real-valued ones (`dp_sum`, `DpNoise::privatize`) and the boolean ones
//! (`randomized_response`, `bernoulli_ratio`). [`CRYPTO_SEMANTICS_ID`] folds
//! those digests. Two builds with the same identifier return the same bits
//! for every pinned scenario. The crate depends on no other Law-bearing crate
//! (its noise is integer arithmetic on a ChaCha20 keystream, with no
//! floating-point transcendental), so no upstream identifier is folded.
//!
//! # Hex form
//!
//! ```text
//! 65285bfd28e836408ac51c4989a6430b2508f25cf51e4ca30db9f3d36e26acef
//! ```
//!
//! # Fold
//!
//! The procedure of the `SEMANTICS_ID` fold of `alice-det-math`: sort the
//! entries by name (ascending byte order), then SHA-256 over, for each entry
//! in that order, the name length as 4 bytes big-endian (`u32`), the name
//! bytes and the 32 digest bytes.
//!
//! # Independent of cargo features
//!
//! The table and the identifier are constants that no `cfg` gates, so a
//! build with any feature set reports the same identifier.
//!
//! # Staleness
//!
//! [`CRYPTO_SEMANTICS_CHECKED_AT`] names the crate version and toolchain the
//! pins were last checked on; a different version or toolchain fails
//! `tests/crypto_semantics_id.rs` until they are checked again.

/// Decodes 64 hex digits into 32 bytes at compile time; anything else is a
/// compile error.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lower-case hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a digest is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) * 16 + nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// The entries [`CRYPTO_SEMANTICS_ID`] folds: one per recorded-bit scenario of
/// `tests/semantics_golden.rs`, named as that file names it
pub const CRYPTO_SEMANTICS_PINS: &[(&str, [u8; 32])] = &[
    (
        "keystream",
        hex32("a6440bde6bb939a6a8e949d28601a1f853ab3016b50b7d6f96111a1caa1e72e7"),
    ),
    (
        "open interval draws",
        hex32("2ce199356fb0dd23f8167eac3816ca619de1453bc1c58709ee69c32dc104a746"),
    ),
    (
        "integer mechanisms",
        hex32("54474a9cfb7d67eea2e136c533a0d362ac4271a950cc4b9b62c6bd71bb6098aa"),
    ),
    (
        "real-valued mechanisms",
        hex32("4898f0d307a200ff351e94123f047f787d565bbeb15f5d0eb84d5a30ee3eb563"),
    ),
    (
        "boolean mechanisms",
        hex32("8a52c5ca878a2837e0069e09c34c4373e16e8801cdeaf1a208463044476bffd1"),
    ),
];

/// The crate version and toolchain the pins were last checked against
pub const CRYPTO_SEMANTICS_CHECKED_AT: (&str, &str) = ("0.4.1", "1.98.1");

/// Content hash of this crate's outputs for a key: the fold of
/// [`CRYPTO_SEMANTICS_PINS`] described in the [module documentation](self)
pub const CRYPTO_SEMANTICS_ID: [u8; 32] =
    hex32("65285bfd28e836408ac51c4989a6430b2508f25cf51e4ca30db9f3d36e26acef");
