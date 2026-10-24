//! AES-128-GCM authenticated encryption (NIST SP 800-38D), with a 96-bit nonce and a 128-bit tag.
//!
//! The AEAD of HPKE suite 0x0001 (RFC 9180) and of the MLS cipher suite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420). The crate's own AEAD ([`crate::stream`]) is
//! XChaCha20-Poly1305; AES-128-GCM is here only because those standards fix it.
//!
//! A (key, nonce) pair must never encrypt two messages: GCM then leaks the XOR of the plaintexts and lets the
//! tag be forged. The callers in this crate ([`crate::hpke`]) derive each nonce from a sequence number.
//!
//! The computation is the RustCrypto `aes-gcm` crate; this module only gives it the crate's shape.

use ::aes_gcm::aead::{Aead, KeyInit, Payload};
use ::aes_gcm::{Aes128Gcm, Nonce};
use alloc::vec::Vec;

/// The size of an AES-128-GCM key, in bytes.
pub const KEY_SIZE: usize = 16;
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
    Aes128Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // encryption fails only for a plaintext longer than 2^36 - 32 bytes, which no slice in memory reaches
        .expect("AES-128-GCM plaintext within the SP 800-38D limit")
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
    Aes128Gcm::new(key.into())
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
