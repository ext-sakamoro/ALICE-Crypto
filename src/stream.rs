//! XChaCha20-Poly1305 stream cipher
//!
//! Extended nonce (192-bit), nonce-misuse resistant.
//! Optimal for P2P environments.
//!
//! **Deep Fried**: Zero-allocation in-place APIs only.
//! Convenience functions (seal/open) wrap in-place core.

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce, Tag,
};

/// Encryption/decryption error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (authentication tag mismatch)
    DecryptionFailed,
    /// Random generation failed
    RandomFailed,
    /// Buffer too small
    BufferTooSmall,
}

/// 32-byte symmetric key
#[derive(Clone)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub const SIZE: usize = 32;

    #[inline]
    pub fn generate() -> Result<Self, CipherError> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|_| CipherError::RandomFailed)?;
        Ok(Key(k))
    }

    #[inline(always)]
    pub const fn from_bytes(b: [u8; 32]) -> Self { Key(b) }

    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// 24-byte nonce (extended nonce for XChaCha20)
#[derive(Clone, Copy)]
pub struct Nonce(pub [u8; 24]);

impl Nonce {
    pub const SIZE: usize = 24;

    #[inline]
    pub fn generate() -> Result<Self, CipherError> {
        let mut n = [0u8; 24];
        getrandom::getrandom(&mut n).map_err(|_| CipherError::RandomFailed)?;
        Ok(Nonce(n))
    }

    #[inline(always)]
    pub const fn from_bytes(b: [u8; 24]) -> Self { Nonce(b) }

    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; 24] { &self.0 }
}

/// Auth tag size (16 bytes for Poly1305)
pub const TAG_SIZE: usize = 16;

// ============================================================================
// Core: Zero-Allocation In-Place APIs
// ============================================================================

/// Encrypt in-place (zero allocation)
///
/// Buffer must have `TAG_SIZE` (16) extra bytes at the end for the auth tag.
/// Returns the total size (plaintext_len + TAG_SIZE) on success.
///
/// # Layout
/// Before: `[plaintext.............][16 bytes free]`
/// After:  `[ciphertext............][auth tag 16B]`
#[inline]
pub fn encrypt_in_place(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize, CipherError> {
    if buffer.len() < plaintext_len + TAG_SIZE {
        return Err(CipherError::BufferTooSmall);
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(&nonce.0);

    let tag = cipher
        .encrypt_in_place_detached(xnonce, b"", &mut buffer[..plaintext_len])
        .map_err(|_| CipherError::EncryptionFailed)?;

    buffer[plaintext_len..plaintext_len + TAG_SIZE].copy_from_slice(&tag);
    Ok(plaintext_len + TAG_SIZE)
}

/// Decrypt in-place (zero allocation)
///
/// Buffer contains ciphertext + auth tag.
/// Returns the plaintext size on success.
///
/// # Layout
/// Before: `[ciphertext............][auth tag 16B]`
/// After:  `[plaintext.............][garbage 16B]`
#[inline]
pub fn decrypt_in_place(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
) -> Result<usize, CipherError> {
    if buffer.len() < TAG_SIZE {
        return Err(CipherError::BufferTooSmall);
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(&nonce.0);
    let ct_len = buffer.len() - TAG_SIZE;

    let mut tag_bytes = [0u8; TAG_SIZE];
    tag_bytes.copy_from_slice(&buffer[ct_len..]);
    let tag = Tag::from_slice(&tag_bytes);

    cipher
        .decrypt_in_place_detached(xnonce, b"", &mut buffer[..ct_len], tag)
        .map_err(|_| CipherError::DecryptionFailed)?;

    Ok(ct_len)
}

/// Encrypt in-place with associated data (zero allocation)
#[inline]
pub fn encrypt_in_place_aead(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
    plaintext_len: usize,
    aad: &[u8],
) -> Result<usize, CipherError> {
    if buffer.len() < plaintext_len + TAG_SIZE {
        return Err(CipherError::BufferTooSmall);
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(&nonce.0);

    let tag = cipher
        .encrypt_in_place_detached(xnonce, aad, &mut buffer[..plaintext_len])
        .map_err(|_| CipherError::EncryptionFailed)?;

    buffer[plaintext_len..plaintext_len + TAG_SIZE].copy_from_slice(&tag);
    Ok(plaintext_len + TAG_SIZE)
}

/// Decrypt in-place with associated data (zero allocation)
#[inline]
pub fn decrypt_in_place_aead(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<usize, CipherError> {
    if buffer.len() < TAG_SIZE {
        return Err(CipherError::BufferTooSmall);
    }
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from_slice(&nonce.0);
    let ct_len = buffer.len() - TAG_SIZE;

    let mut tag_bytes = [0u8; TAG_SIZE];
    tag_bytes.copy_from_slice(&buffer[ct_len..]);
    let tag = Tag::from_slice(&tag_bytes);

    cipher
        .decrypt_in_place_detached(xnonce, aad, &mut buffer[..ct_len], tag)
        .map_err(|_| CipherError::DecryptionFailed)?;

    Ok(ct_len)
}

// ============================================================================
// Convenience: Allocating wrappers (use in-place core)
// ============================================================================

/// Convenience: encrypt with random nonce, prepend nonce to output
///
/// Output format: `[nonce 24B][ciphertext][tag 16B]`
#[inline]
pub fn seal(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let nonce = Nonce::generate()?;
    let total_len = Nonce::SIZE + plaintext.len() + TAG_SIZE;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(plaintext);
    out.resize(total_len, 0);

    // Encrypt in-place (skip nonce prefix)
    encrypt_in_place(key, &nonce, &mut out[Nonce::SIZE..], plaintext.len())?;

    Ok(out)
}

/// Convenience: extract nonce from input and decrypt
///
/// Input format: `[nonce 24B][ciphertext][tag 16B]`
#[inline]
pub fn open(key: &Key, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
    if sealed.len() < Nonce::SIZE + TAG_SIZE {
        return Err(CipherError::BufferTooSmall);
    }

    let mut nonce_bytes = [0u8; Nonce::SIZE];
    nonce_bytes.copy_from_slice(&sealed[..Nonce::SIZE]);
    let nonce = Nonce(nonce_bytes);

    let ct_with_tag = &sealed[Nonce::SIZE..];
    let mut buffer = ct_with_tag.to_vec();

    let pt_len = decrypt_in_place(key, &nonce, &mut buffer)?;
    buffer.truncate(pt_len);

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_in_place() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"Hello, ALICE!";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], plaintext_len).unwrap();
        assert_eq!(ct_len, plaintext_len + TAG_SIZE);

        let pt_len = decrypt_in_place(&key, &nonce, &mut buffer[..ct_len]).unwrap();
        assert_eq!(pt_len, plaintext_len);
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    #[test]
    fn test_wrong_key() {
        let key1 = Key::generate().unwrap();
        let key2 = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"secret";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key1, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], plaintext_len).unwrap();
        assert!(decrypt_in_place(&key2, &nonce, &mut buffer[..ct_len]).is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"secret";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], plaintext_len).unwrap();
        buffer[0] ^= 0xFF; // Tamper

        assert!(decrypt_in_place(&key, &nonce, &mut buffer[..ct_len]).is_err());
    }

    #[test]
    fn test_seal_open() {
        let key = Key::generate().unwrap();
        let plaintext = b"Sealed secret";

        let sealed = seal(&key, plaintext).unwrap();
        let opened = open(&key, &sealed).unwrap();

        assert_eq!(&opened, plaintext);
    }

    #[test]
    fn test_in_place_aead() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let aad = b"associated data";
        let plaintext = b"secret message";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place_aead(&key, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], plaintext_len, aad).unwrap();

        let pt_len = decrypt_in_place_aead(&key, &nonce, &mut buffer[..ct_len], aad).unwrap();
        assert_eq!(&buffer[..pt_len], plaintext);

        // Wrong AAD should fail
        buffer[..plaintext_len].copy_from_slice(plaintext);
        encrypt_in_place_aead(&key, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], plaintext_len, aad).unwrap();
        assert!(decrypt_in_place_aead(&key, &nonce, &mut buffer[..plaintext_len + TAG_SIZE], b"wrong").is_err());
    }
}
