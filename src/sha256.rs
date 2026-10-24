//! SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869).
//!
//! These are the hash and key-derivation primitives of the MLS cipher suite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420) and of HPKE's `HKDF-SHA256` (RFC 9180).
//! The crate's own hash ([`crate::hash()`]) is BLAKE3; SHA-256 is here only because those standards fix it.
//!
//! The computation is the RustCrypto `sha2` / `hmac` / `hkdf` crates; this module only gives them the
//! crate's fixed-size, allocation-free shape.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The size of a SHA-256 digest (and of an HMAC-SHA256 tag and an HKDF-SHA256 PRK), in bytes.
pub const DIGEST_SIZE: usize = 32;

/// The longest output HKDF-SHA256 can expand to: 255 blocks of 32 bytes (RFC 5869 section 2.3).
pub const HKDF_MAX_OUTPUT: usize = 255 * DIGEST_SIZE;

/// SHA-256 of `data`.
#[must_use]
pub fn digest(data: &[u8]) -> [u8; DIGEST_SIZE] {
    Sha256::digest(data).into()
}

/// Incremental SHA-256, for input read in parts (a file streamed from disk or the network).
///
/// Feeding the parts of a message in order gives the same digest as [`digest`] of the whole.
/// [`Hasher::finalize`] consumes the hasher, so no input can follow a digest by mistake;
/// [`Hasher::finalize_reset`] gives the digest and leaves the hasher as if newly made.
#[derive(Clone, Default)]
pub struct Hasher(Sha256);

impl Hasher {
    /// A hasher that has seen no input.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Feeds the next part of the message.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The SHA-256 of everything fed.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_SIZE] {
        self.0.finalize().into()
    }

    /// The SHA-256 of everything fed so far; the hasher then starts over, as if newly made.
    #[must_use]
    pub fn finalize_reset(&mut self) -> [u8; DIGEST_SIZE] {
        self.0.finalize_reset().into()
    }

    /// Forgets all input, as if newly made.
    pub fn reset(&mut self) {
        self.0 = Sha256::new();
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // the state is derived from the input, which may be secret
        f.write_str("sha256::Hasher")
    }
}

/// HMAC-SHA256 of `data` under `key` (any length; RFC 2104 hashes a key longer than the block).
#[must_use]
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; DIGEST_SIZE] {
    // new_from_slice accepts every key length for HMAC (only fixed-key MACs refuse one)
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// HKDF-Extract (RFC 5869 section 2.2): the pseudorandom key HMAC-SHA256(`salt`, `ikm`).
///
/// An empty `salt` is the same as 32 zero bytes, as the RFC specifies.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; DIGEST_SIZE] {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Expand (RFC 5869 section 2.3): fills `out` with output keying material from `prk` and `info`.
///
/// # Errors
///
/// [`HkdfError::OutputTooLong`] when `out` is longer than [`HKDF_MAX_OUTPUT`]; `out` is then left unchanged
/// (`hkdf` checks the length before it writes a block).
pub fn hkdf_expand(prk: &[u8; DIGEST_SIZE], info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
    let h = hkdf::Hkdf::<Sha256>::from_prk(prk).expect("a 32-byte PRK is never too short");
    h.expand(info, out)
        .map_err(|_| HkdfError::OutputTooLong(out.len()))
}

/// Why HKDF-SHA256 could not expand.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// The requested output is longer than 255 blocks (its length).
    OutputTooLong(usize),
}

impl core::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutputTooLong(n) => write!(
                f,
                "HKDF-SHA256 output of {n} bytes is longer than {HKDF_MAX_OUTPUT}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HkdfError {}
