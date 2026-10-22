//! Sealed envelope: a versioned, key-labelled form of [`seal_with_aad`]
//!
//! A value sealed for storage outlives the key that sealed it: keys are
//! rotated and the format may change. The envelope puts a version and the id
//! of the sealing key in front of the sealed bytes, so that a reader can pick
//! the key and reject a format it does not know, and authenticates both as
//! part of the associated data, so that relabelling a blob does not open it.
//!
//! # Layout
//!
//! `[version u8][key id u32 big-endian][nonce 24B][ciphertext][tag 16B]`
//!
//! The AEAD associated data is the 5-byte header followed by the caller's
//! associated data. The header has a fixed length, so the concatenation is
//! unambiguous.
//!
//! The key id is chosen by the caller (for example the generation of a data
//! key); the envelope does not interpret it.
//!
//! # Example
//!
//! ```
//! use alice_crypto::envelope::{envelope_key_id, open_envelope, reseal_envelope, seal_envelope};
//! use alice_crypto::Key;
//!
//! # fn main() -> Result<(), alice_crypto::envelope::EnvelopeError> {
//! let k1 = Key::from_bytes([1; 32]);
//! let blob = seal_envelope(&k1, 1, b"record-7", b"secret")?;
//! assert_eq!(envelope_key_id(&blob)?, 1);
//! assert_eq!(open_envelope(&k1, 1, b"record-7", &blob)?, b"secret");
//!
//! let k2 = Key::from_bytes([2; 32]);
//! let blob = reseal_envelope(&k1, 1, &k2, 2, b"record-7", &blob)?;
//! assert_eq!(open_envelope(&k2, 2, b"record-7", &blob)?, b"secret");
//! # Ok(())
//! # }
//! ```
//!
//! [`seal_with_aad`]: crate::stream::seal_with_aad

extern crate alloc;
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::stream::{
    decrypt_in_place_aead, encrypt_in_place_aead, CipherError, Key, Nonce, TAG_SIZE,
};

/// Envelope format version written by [`seal_envelope`]
pub const ENVELOPE_VERSION: u8 = 1;

/// Header size: version (1) + key id (4)
pub const ENVELOPE_HEADER_SIZE: usize = 5;

/// Bytes an envelope adds to the plaintext: header + nonce + tag
pub const ENVELOPE_OVERHEAD: usize = ENVELOPE_HEADER_SIZE + Nonce::SIZE + TAG_SIZE;

/// Envelope error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Input shorter than the part of the layout that was needed
    TooShort,
    /// The version byte is not one this crate reads
    UnsupportedVersion(u8),
    /// The header names a different key than the one supplied
    KeyIdMismatch {
        /// The key id the caller supplied
        expected: u32,
        /// The key id in the header
        found: u32,
    },
    /// Encryption, decryption or authentication failed
    Cipher(CipherError),
}

impl From<CipherError> for EnvelopeError {
    fn from(e: CipherError) -> Self {
        Self::Cipher(e)
    }
}

fn header(key_id: u32) -> [u8; ENVELOPE_HEADER_SIZE] {
    let id = key_id.to_be_bytes();
    [ENVELOPE_VERSION, id[0], id[1], id[2], id[3]]
}

fn full_aad(head: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(head.len() + aad.len());
    v.extend_from_slice(head);
    v.extend_from_slice(aad);
    v
}

/// Seal `plaintext` under `key`, labelled with `key_id`, bound to `aad`
///
/// A fresh random nonce is drawn for every call.
///
/// # Errors
///
/// Returns [`EnvelopeError::Cipher`] if nonce generation or encryption fails.
pub fn seal_envelope(
    key: &Key,
    key_id: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let head = header(key_id);
    let nonce = Nonce::generate()?;
    let body = ENVELOPE_HEADER_SIZE + Nonce::SIZE;
    let total_len = body + plaintext.len() + TAG_SIZE;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&head);
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(plaintext);
    out.resize(total_len, 0);

    encrypt_in_place_aead(
        key,
        &nonce,
        &mut out[body..],
        plaintext.len(),
        &full_aad(&head, aad),
    )?;

    Ok(out)
}

/// Read the key id of an envelope, to choose the key that opens it
///
/// ⚠️ The id is **not authenticated** by this call: it only says which key to
/// try. [`open_envelope`] authenticates it.
///
/// # Errors
///
/// [`EnvelopeError::TooShort`] if the header is incomplete,
/// [`EnvelopeError::UnsupportedVersion`] if the version is unknown.
pub fn envelope_key_id(sealed: &[u8]) -> Result<u32, EnvelopeError> {
    if sealed.len() < ENVELOPE_HEADER_SIZE {
        return Err(EnvelopeError::TooShort);
    }
    if sealed[0] != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(sealed[0]));
    }
    Ok(u32::from_be_bytes([
        sealed[1], sealed[2], sealed[3], sealed[4],
    ]))
}

/// Open an envelope sealed by [`seal_envelope`] with `key` labelled `key_id`
///
/// # Errors
///
/// [`EnvelopeError::TooShort`] / [`EnvelopeError::UnsupportedVersion`] for a
/// malformed header, [`EnvelopeError::KeyIdMismatch`] if the header names
/// another key, and [`EnvelopeError::Cipher`] if the key, the associated data,
/// the header or any other byte differs from the sealing side.
pub fn open_envelope(
    key: &Key,
    key_id: u32,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if sealed.len() < ENVELOPE_OVERHEAD {
        return Err(EnvelopeError::TooShort);
    }
    let found = envelope_key_id(sealed)?;
    if found != key_id {
        return Err(EnvelopeError::KeyIdMismatch {
            expected: key_id,
            found,
        });
    }

    let body = ENVELOPE_HEADER_SIZE + Nonce::SIZE;
    let mut nonce_bytes = [0u8; Nonce::SIZE];
    nonce_bytes.copy_from_slice(&sealed[ENVELOPE_HEADER_SIZE..body]);
    let nonce = Nonce(nonce_bytes);

    let mut buffer = sealed[body..].to_vec();
    let pt_len = decrypt_in_place_aead(
        key,
        &nonce,
        &mut buffer,
        &full_aad(&sealed[..ENVELOPE_HEADER_SIZE], aad),
    )?;
    buffer.truncate(pt_len);

    Ok(buffer)
}

/// Re-seal an envelope under a new key and key id (key rotation)
///
/// The intermediate plaintext is zeroed before return.
///
/// # Errors
///
/// Any error of [`open_envelope`] for the old key, or of [`seal_envelope`].
pub fn reseal_envelope(
    old_key: &Key,
    old_key_id: u32,
    new_key: &Key,
    new_key_id: u32,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let mut plaintext = open_envelope(old_key, old_key_id, aad, sealed)?;
    let out = seal_envelope(new_key, new_key_id, aad, &plaintext);
    plaintext.zeroize();
    out
}
