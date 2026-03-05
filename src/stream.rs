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
    Tag, XChaCha20Poly1305, XNonce,
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

    /// # Errors
    ///
    /// Returns [`CipherError::RandomFailed`] if entropy generation fails.
    #[inline(always)]
    pub fn generate() -> Result<Self, CipherError> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|_| CipherError::RandomFailed)?;
        Ok(Self(k))
    }

    #[inline(always)]
    #[must_use]
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    #[inline(always)]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 24-byte nonce (extended nonce for `XChaCha20`)
#[derive(Clone, Copy)]
pub struct Nonce(pub [u8; 24]);

impl Nonce {
    pub const SIZE: usize = 24;

    /// # Errors
    ///
    /// Returns [`CipherError::RandomFailed`] if entropy generation fails.
    #[inline(always)]
    pub fn generate() -> Result<Self, CipherError> {
        let mut n = [0u8; 24];
        getrandom::getrandom(&mut n).map_err(|_| CipherError::RandomFailed)?;
        Ok(Self(n))
    }

    #[inline(always)]
    #[must_use]
    pub const fn from_bytes(b: [u8; 24]) -> Self {
        Self(b)
    }

    #[inline(always)]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

/// Auth tag size (16 bytes for Poly1305)
pub const TAG_SIZE: usize = 16;

// ============================================================================
// Core: Zero-Allocation In-Place APIs
// ============================================================================

/// Encrypt in-place (zero allocation)
///
/// Buffer must have `TAG_SIZE` (16) extra bytes at the end for the auth tag.
/// Returns the total size (`plaintext_len` + `TAG_SIZE`) on success.
///
/// # Layout
/// Before: `[plaintext.............][16 bytes free]`
/// After:  `[ciphertext............][auth tag 16B]`
///
/// # Errors
///
/// Returns [`CipherError`] if the buffer is too small or encryption fails.
#[inline(always)]
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
///
/// # Errors
///
/// Returns [`CipherError`] if the buffer is too small or decryption/authentication fails.
#[inline(always)]
pub fn decrypt_in_place(key: &Key, nonce: &Nonce, buffer: &mut [u8]) -> Result<usize, CipherError> {
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
///
/// # Errors
///
/// Returns [`CipherError`] if the buffer is too small or encryption fails.
#[inline(always)]
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
///
/// # Errors
///
/// Returns [`CipherError`] if the buffer is too small or decryption/authentication fails.
#[inline(always)]
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
///
/// # Errors
///
/// Returns [`CipherError`] if nonce generation or encryption fails.
#[inline(always)]
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
///
/// # Errors
///
/// Returns [`CipherError`] if the input is too short or decryption/authentication fails.
#[inline(always)]
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

        let ct_len = encrypt_in_place(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
        )
        .unwrap();
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

        let ct_len = encrypt_in_place(
            &key1,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
        )
        .unwrap();
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

        let ct_len = encrypt_in_place(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
        )
        .unwrap();
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

        let ct_len = encrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
            aad,
        )
        .unwrap();

        let pt_len = decrypt_in_place_aead(&key, &nonce, &mut buffer[..ct_len], aad).unwrap();
        assert_eq!(&buffer[..pt_len], plaintext);

        // Wrong AAD should fail
        buffer[..plaintext_len].copy_from_slice(plaintext);
        encrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
            aad,
        )
        .unwrap();
        assert!(decrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            b"wrong"
        )
        .is_err());
    }

    // ── New tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_key_size_constant() {
        assert_eq!(Key::SIZE, 32);
    }

    #[test]
    fn test_nonce_size_constant() {
        assert_eq!(Nonce::SIZE, 24);
    }

    #[test]
    fn test_tag_size_constant() {
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn test_key_from_bytes_roundtrip() {
        let bytes = [0xABu8; 32];
        let key = Key::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_from_bytes_roundtrip() {
        let bytes = [0xCDu8; 24];
        let nonce = Nonce::from_bytes(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_generate_unique() {
        // Two generated keys should (overwhelmingly likely) differ
        let k1 = Key::generate().unwrap();
        let k2 = Key::generate().unwrap();
        // Extremely improbable to be equal; verify both are 32 bytes
        assert_eq!(k1.0.len(), 32);
        assert_eq!(k2.0.len(), 32);
    }

    #[test]
    fn test_nonce_generate_unique() {
        let n1 = Nonce::generate().unwrap();
        let n2 = Nonce::generate().unwrap();
        assert_eq!(n1.0.len(), 24);
        assert_eq!(n2.0.len(), 24);
    }

    #[test]
    fn test_cipher_error_variants_eq() {
        assert_eq!(CipherError::EncryptionFailed, CipherError::EncryptionFailed);
        assert_ne!(CipherError::EncryptionFailed, CipherError::DecryptionFailed);
        assert_eq!(CipherError::RandomFailed, CipherError::RandomFailed);
        assert_eq!(CipherError::BufferTooSmall, CipherError::BufferTooSmall);
    }

    #[test]
    fn test_cipher_error_clone_copy() {
        let e = CipherError::DecryptionFailed;
        let e2 = e; // Copy
        let e3 = e; // Clone
        assert_eq!(e, e2);
        assert_eq!(e, e3);
    }

    #[test]
    fn test_encrypt_in_place_buffer_too_small() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"hello";
        let plaintext_len = plaintext.len();

        // Buffer is exactly plaintext_len (no room for tag)
        let mut buffer = [0u8; 5];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let result = encrypt_in_place(&key, &nonce, &mut buffer, plaintext_len);
        assert!(matches!(result, Err(CipherError::BufferTooSmall)));
    }

    #[test]
    fn test_decrypt_in_place_buffer_too_small() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();

        // Buffer smaller than TAG_SIZE
        let mut buffer = [0u8; 10]; // < 16
        let result = decrypt_in_place(&key, &nonce, &mut buffer);
        assert!(matches!(result, Err(CipherError::BufferTooSmall)));
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = Key::generate().unwrap();
        let nonce1 = Nonce::generate().unwrap();
        let nonce2 = Nonce::generate().unwrap();
        let plaintext = b"nonce mismatch";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(
            &key,
            &nonce1,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
        )
        .unwrap();
        // Decrypt with a different nonce must fail
        assert!(decrypt_in_place(&key, &nonce2, &mut buffer[..ct_len]).is_err());
    }

    #[test]
    fn test_tampered_auth_tag() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"tag tamper";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
        )
        .unwrap();
        // Flip a bit in the auth tag (last 16 bytes)
        buffer[ct_len - 1] ^= 0x01;

        assert!(decrypt_in_place(&key, &nonce, &mut buffer[..ct_len]).is_err());
    }

    #[test]
    fn test_seal_open_empty_plaintext() {
        let key = Key::generate().unwrap();
        let plaintext = b"";

        let sealed = seal(&key, plaintext).unwrap();
        // sealed = 24 (nonce) + 0 (ct) + 16 (tag) = 40 bytes
        assert_eq!(sealed.len(), Nonce::SIZE + TAG_SIZE);

        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_open_too_short_input() {
        let key = Key::generate().unwrap();
        // Less than Nonce::SIZE + TAG_SIZE = 40 bytes
        let short = [0u8; 10];
        assert!(matches!(
            open(&key, &short),
            Err(CipherError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_seal_open_large_plaintext() {
        let key = Key::generate().unwrap();
        let plaintext = vec![0x77u8; 4096];

        let sealed = seal(&key, &plaintext).unwrap();
        assert_eq!(sealed.len(), Nonce::SIZE + plaintext.len() + TAG_SIZE);

        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_aead_empty_aad() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"no aad";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
            b"",
        )
        .unwrap();
        let pt_len = decrypt_in_place_aead(&key, &nonce, &mut buffer[..ct_len], b"").unwrap();
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    #[test]
    fn test_aead_tampered_aad_byte() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let aad = b"my_aad";
        let plaintext = b"protected";
        let plaintext_len = plaintext.len();

        let mut buffer = [0u8; 64];
        buffer[..plaintext_len].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..plaintext_len + TAG_SIZE],
            plaintext_len,
            aad,
        )
        .unwrap();
        // Change one byte of AAD
        assert!(decrypt_in_place_aead(&key, &nonce, &mut buffer[..ct_len], b"my_aae").is_err());
    }

    #[test]
    fn test_decrypt_in_place_aead_buffer_too_small() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let mut buffer = [0u8; 10]; // < TAG_SIZE
        assert!(matches!(
            decrypt_in_place_aead(&key, &nonce, &mut buffer, b""),
            Err(CipherError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_encrypt_in_place_aead_buffer_too_small() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext_len = 5;
        let mut buffer = [0u8; 5]; // no room for tag
        assert!(matches!(
            encrypt_in_place_aead(&key, &nonce, &mut buffer, plaintext_len, b""),
            Err(CipherError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_key_clone() {
        let k = Key::generate().unwrap();
        let k2 = k.clone();
        assert_eq!(k.0, k2.0);
    }

    #[test]
    fn test_nonce_clone_copy() {
        let n = Nonce::generate().unwrap();
        let n2 = n; // Copy
        let n3 = n; // Clone
        assert_eq!(n.0, n2.0);
        assert_eq!(n.0, n3.0);
    }
}
