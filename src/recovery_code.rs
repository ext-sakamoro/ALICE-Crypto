//! Recovery code: a secret that a person writes down, and a secret sealed under it.
//!
//! A recovery code is 128 random bits that no person chose, written as 28 characters of base32 with a 10-bit
//! check, so a mistyped character is caught before anything is opened. A secret sealed under the code opens only
//! with that code and the same associated data.
//!
//! # Code
//!
//! ```text
//! bits  = entropy (128) || check (10) || 00
//! check = the first 10 bits of SHA-256(RECOVERY_CODE_CHECK_CONTEXT || entropy)
//! text  = 28 characters of the alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ (5 bits each, most significant first),
//!         shown in 7 groups of 4 joined by `-`
//! ```
//!
//! Reading ([`RecoveryCode::parse`]) ignores case, `-` and spaces, and reads `O` as `0` and `I` / `L` as `1`; the two
//! padding bits must be zero and the check must match.
//!
//! # Sealed secret
//!
//! ```text
//! blob = version (1) || salt (16) || nonce (24) || ciphertext || tag (16)
//! key  = HKDF-SHA256(salt, entropy, RECOVERY_CODE_KEY_INFO) (32 bytes)
//! AEAD = XChaCha20-Poly1305, associated data = version || salt || caller's associated data
//! ```
//!
//! The code is not stretched (no Argon2): it has 128 bits that no person chose, so guessing it is as hard as
//! guessing the key. A person's own PIN or password is not a recovery code and has no constructor here.

use zeroize::Zeroizing;

/// Characters of a recovery code.
pub const RECOVERY_CODE_LEN: usize = 28;

/// Random bytes in a recovery code.
pub const RECOVERY_CODE_ENTROPY: usize = 16;

/// The version byte of a sealed secret.
pub const RECOVERY_BLOB_VERSION: u8 = 1;

/// Bytes a sealed secret adds to the secret: version, salt, nonce and tag.
pub const RECOVERY_BLOB_OVERHEAD: usize = 1 + 16 + 24 + 16;

/// The prefix hashed before the entropy to make the check.
pub const RECOVERY_CODE_CHECK_CONTEXT: &[u8] = b"alice-crypto recovery-code v1 check";

/// The HKDF info of the key a code seals with.
pub const RECOVERY_CODE_KEY_INFO: &[u8] = b"alice-crypto recovery-code v1 key";

/// A recovery code: 16 random bytes, zeroed on drop. `Debug` never shows them.
#[derive(Clone)]
pub struct RecoveryCode {
    entropy: Zeroizing<[u8; RECOVERY_CODE_ENTROPY]>,
}

/// Why a code was not read or a secret not sealed or opened (made by this crate only).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCodeError {
    /// Not 28 code characters once `-` and spaces are left out.
    Length,
    /// A character outside the alphabet, at this position among the code characters.
    Character { position: usize },
    /// The padding bits are not zero or the check does not match (a mistyped character).
    Check,
    /// The secret to seal is empty.
    EmptySecret,
    /// Bytes shorter than a sealed secret of one byte.
    Malformed,
    /// A sealed secret of another version.
    UnsupportedVersion(u8),
    /// The code or the associated data is not the one it was sealed with, or the bytes were changed.
    Open,
    /// The operating system's random source is unavailable.
    RandomFailed,
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

impl RecoveryCode {
    /// A new code from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`RecoveryCodeError::RandomFailed`] when the random source is unavailable.
    #[cfg(feature = "rng")]
    pub fn generate() -> Result<Self, RecoveryCodeError> {
        todo!("STUB: recovery code generation (device-loss recovery step 2)")
    }

    /// The code of these 16 bytes (for codes derived elsewhere and for tests).
    #[must_use]
    pub fn from_entropy(entropy: [u8; RECOVERY_CODE_ENTROPY]) -> Self {
        Self {
            entropy: Zeroizing::new(entropy),
        }
    }

    /// Read a code a person typed (see the module docs for what is ignored).
    ///
    /// # Errors
    ///
    /// [`RecoveryCodeError::Length`], [`RecoveryCodeError::Character`] or [`RecoveryCodeError::Check`].
    pub fn parse(text: &str) -> Result<Self, RecoveryCodeError> {
        let _ = text;
        todo!("STUB: recovery code parsing (device-loss recovery step 2)")
    }

    /// The code as a person writes it down: 7 groups of 4 characters joined by `-`.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let _ = &self.entropy;
        todo!("STUB: recovery code text (device-loss recovery step 2)")
    }
}

/// Seal `secret` under `code`, bound to `aad`.
///
/// # Errors
///
/// [`RecoveryCodeError::EmptySecret`] or [`RecoveryCodeError::RandomFailed`].
#[cfg(feature = "rng")]
pub fn seal_secret(
    code: &RecoveryCode,
    secret: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RecoveryCodeError> {
    let _ = (code, secret, aad);
    todo!("STUB: sealing under a recovery code (device-loss recovery step 2)")
}

/// Open a secret sealed by [`seal_secret`] with the same code and associated data.
///
/// # Errors
///
/// [`RecoveryCodeError::Malformed`], [`RecoveryCodeError::UnsupportedVersion`] or [`RecoveryCodeError::Open`].
pub fn open_secret(
    code: &RecoveryCode,
    blob: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RecoveryCodeError> {
    let _ = (code, blob, aad);
    todo!("STUB: opening under a recovery code (device-loss recovery step 2)")
}
