//! Calls into alice-crypto from a `no_std` crate, so the build links what a
//! downstream user would link
#![no_std]

use alice_crypto::{dp_int, hash, DpError, SecureRng};

/// BLAKE3 of the input, first byte (keeps the call from being optimised away)
#[must_use]
pub fn digest_first_byte(data: &[u8]) -> u8 {
    hash(data).as_bytes()[0]
}

/// A count with discrete Laplace noise from a keyed stream
///
/// # Errors
///
/// Whatever `dp_int` refuses (a non-positive ε, a zero sensitivity)
pub fn noisy_count(value: i64, epsilon: f64, key: [u8; 32]) -> Result<i64, DpError> {
    let mut rng = SecureRng::from_key(key);
    dp_int(value, 1, epsilon, &mut rng)
}
