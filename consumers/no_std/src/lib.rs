//! Calls into alice-crypto from a `no_std` crate, so the build links what a
//! downstream user would link
#![no_std]

use alice_crypto::keystore::{KeyProvider, KeyStore};
use alice_crypto::mac::{mac, MacKey};
use alice_crypto::sss::Shard;
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

/// The first byte of the MAC tag of `data`
#[must_use]
pub fn tag_first_byte(key: [u8; 32], data: &[u8]) -> u8 {
    mac(&MacKey::from_bytes(key), data).as_bytes()[0]
}

/// The generation of the current key of a one-key store, through the key provider
#[must_use]
pub fn current_generation(key: [u8; 32]) -> Option<u32> {
    let mut store = KeyStore::new();
    store.insert(key, 0);
    store.provider_at(0).current().ok().map(|(g, _)| g)
}

/// Whether `bytes` is a shard byte form
#[must_use]
pub fn is_shard(bytes: &[u8]) -> bool {
    Shard::from_bytes(bytes).is_ok()
}
