//! ChaCha20-Poly1305 authenticated encryption as RFC 8439 defines it (`AEAD_CHACHA20_POLY1305`), with a
//! 96-bit nonce and a 128-bit tag.
//!
//! The AEAD of protocols that fix this exact construction, such as the Noise protocol framework's
//! `ChaChaPoly` cipher. The crate's own AEAD ([`crate::stream`]) is XChaCha20-Poly1305 with a 192-bit nonce;
//! this module is here only because those standards fix the 96-bit form.
//!
//! A (key, nonce) pair must never encrypt two messages: the keystream then repeats and the one-time Poly1305
//! key is reused, which leaks the XOR of the plaintexts and lets the tag be forged. Callers derive each nonce
//! from a counter.
//!
//! The computation is the RustCrypto `chacha20poly1305` crate; this module only gives it the crate's shape.

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// The size of a ChaCha20-Poly1305 key, in bytes.
pub const KEY_SIZE: usize = 32;
/// The size of a nonce, in bytes.
pub const NONCE_SIZE: usize = 12;
/// The size of the tag appended to the ciphertext, in bytes.
pub const TAG_SIZE: usize = 16;

/// The ciphertext of `plaintext` with the tag over it and `aad` appended (length `plaintext.len() + TAG_SIZE`).
#[must_use]
pub fn seal(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // encryption fails only for a plaintext longer than 2^38 - 64 bytes (RFC 8439 section 2.8), which no
        // slice in memory reaches
        .expect("ChaCha20-Poly1305 plaintext within the RFC 8439 limit")
}

/// The plaintext of `ciphertext` (with its tag appended) when the tag verifies over it and `aad`.
///
/// # Errors
///
/// [`AeadError::Authentication`] when the tag does not verify (wrong key, nonce or `aad`, a changed
/// ciphertext, or input shorter than a tag); no plaintext is returned then.
pub fn open(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // (input shorter than a tag is refused by `aead` before any decryption)
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::Authentication)
}

pub use crate::aead::AeadError;
