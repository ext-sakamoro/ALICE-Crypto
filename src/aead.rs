//! The failure of an AEAD: the one error type of [`crate::aes_gcm`] and [`crate::chacha20poly1305_ietf`].
//!
//! Each AEAD module re-exports it, so a caller handling both meets one type for one failure.

/// Why an AEAD ciphertext was refused.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// The tag does not verify; the ciphertext is not opened.
    Authentication,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Authentication => f.write_str("AEAD authentication failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AeadError {}
