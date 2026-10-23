//! Message authentication: a BLAKE3 keyed hash tag.
//!
//! This is symmetric authentication. Whoever holds the key can make a valid tag, so a tag shows that the message
//! comes from a key holder and was not changed; it is not a public-key signature and gives no non-repudiation
//! (for that, use an Ed25519 signature).
//!
//! - [`mac`] is BLAKE3 keyed_hash(key, message), 32 bytes.
//! - [`mac_with_context`] binds a context to the message: BLAKE3 keyed_hash(key, u64-LE len(context) || context ||
//!   message). The length prefix keeps (context, message) splits apart, so ("ab", "c") and ("a", "bc") give
//!   different tags.
//! - [`verify`] and [`verify_with_context`] compare all 32 bytes in constant time.

use crate::hash;
use zeroize::Zeroize;

/// The size of a tag, in bytes.
pub const TAG_SIZE: usize = 32;

/// A MAC key (32 bytes, zeroed on drop). `Debug` does not show it.
#[derive(Clone)]
pub struct MacKey([u8; 32]);

impl MacKey {
    /// A key from its 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A key from a slice of exactly 32 bytes, copied into the key (which is zeroed on drop).
    ///
    /// # Errors
    ///
    /// [`MacError::InvalidLength`] when `bytes` is not 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MacError> {
        if bytes.len() != 32 {
            return Err(MacError::InvalidLength(bytes.len()));
        }
        let mut key = Self([0u8; 32]);
        key.0.copy_from_slice(bytes);
        Ok(key)
    }

    /// A new random key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`MacError::RngFailed`] when the random source is unavailable.
    #[expect(
        clippy::disallowed_methods,
        reason = "secret material generation, not Law output: a MAC key must be unpredictable, and no Law-bearing result is computed from it"
    )]
    pub fn generate() -> Result<Self, MacError> {
        let mut key = Self([0u8; 32]);
        getrandom::getrandom(&mut key.0).map_err(|_| MacError::RngFailed)?;
        Ok(key)
    }

    /// The key's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MacKey(..)")
    }
}

/// A tag (32 bytes). `==` compares all 32 bytes in constant time; it is not derived, because a derived comparison
/// stops at the first differing byte and so tells, by its time, how many leading bytes of a forged tag were right.
#[derive(Clone)]
pub struct Tag([u8; TAG_SIZE]);

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for Tag {}

impl Tag {
    /// A tag from its 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TAG_SIZE]) -> Self {
        Self(bytes)
    }

    /// A tag from a slice of exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// [`MacError::InvalidLength`] when `bytes` is not 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MacError> {
        let arr: [u8; TAG_SIZE] = bytes
            .try_into()
            .map_err(|_| MacError::InvalidLength(bytes.len()))?;
        Ok(Self(arr))
    }

    /// The tag's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Tag({:02x}{:02x}...)", self.0[0], self.0[1])
    }
}

/// The tag of `message` under `key`: BLAKE3 keyed_hash(key, message).
#[must_use]
pub fn mac(key: &MacKey, message: &[u8]) -> Tag {
    Tag(*hash::keyed_hash(&key.0, message).as_bytes())
}

/// The tag of `message` bound to `context` under `key`: BLAKE3 keyed_hash(key, u64-LE len(context) || context ||
/// message).
#[must_use]
pub fn mac_with_context(key: &MacKey, context: &[u8], message: &[u8]) -> Tag {
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    hasher.update(&(context.len() as u64).to_le_bytes());
    hasher.update(context);
    hasher.update(message);
    Tag(*hasher.finalize().as_bytes())
}

/// Whether `tag` is the tag of `message` under `key` (all 32 bytes compared in constant time).
#[must_use]
pub fn verify(key: &MacKey, message: &[u8], tag: &Tag) -> bool {
    mac(key, message) == *tag
}

/// Whether `tag` is the tag of `message` bound to `context` under `key` (constant-time comparison).
#[must_use]
pub fn verify_with_context(key: &MacKey, context: &[u8], message: &[u8], tag: &Tag) -> bool {
    mac_with_context(key, context, message) == *tag
}

/// Compares every byte before answering, so the time does not depend on where the first difference is.
fn constant_time_eq(a: &[u8; TAG_SIZE], b: &[u8; TAG_SIZE]) -> bool {
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Why a MAC key or tag could not be made.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacError {
    /// A key or tag was given as a slice that is not 32 bytes long (its length).
    InvalidLength(usize),
    /// The operating system's random source is unavailable.
    RngFailed,
}

impl core::fmt::Display for MacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "expected 32 bytes, got {n}"),
            Self::RngFailed => f.write_str("random number generation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacError {}
