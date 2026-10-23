//! X25519 Diffie-Hellman (RFC 7748).
//!
//! The key-agreement primitive of HPKE's `DHKEM(X25519, HKDF-SHA256)` (RFC 9180) and so of the MLS cipher suite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420).
//!
//! - [`x25519`] is the RFC 7748 function itself (scalar clamped, any u-coordinate, no checks): it is what the
//!   RFC's test vectors pin.
//! - [`diffie_hellman`] is what a protocol calls: the same function, refusing an all-zero shared secret
//!   (a peer key of small order), as RFC 9180 section 7.1.4 requires.
//!
//! The computation is the RustCrypto / dalek `x25519-dalek` crate; this module only gives it the crate's shape.

use zeroize::Zeroize;

/// The size of an X25519 private key, public key and shared secret, in bytes.
pub const KEY_SIZE: usize = 32;

/// The RFC 7748 X25519 function of `scalar` (clamped as the RFC specifies) and the u-coordinate `u`.
///
/// This does not refuse a small-order `u`; use [`diffie_hellman`] in a protocol.
#[must_use]
pub fn x25519(scalar: &[u8; KEY_SIZE], u: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    x25519_dalek::x25519(*scalar, *u)
}

/// The public key of the private key `secret`: X25519(`secret`, 9).
#[must_use]
pub fn public_key(secret: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    x25519(secret, &x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// The shared secret of our private key `secret` and the peer's public key `peer`.
///
/// # Errors
///
/// [`X25519Error::ZeroSharedSecret`] when the result is all zero (the peer key has small order); nothing about
/// the result is returned then.
pub fn diffie_hellman(
    secret: &[u8; KEY_SIZE],
    peer: &[u8; KEY_SIZE],
) -> Result<[u8; KEY_SIZE], X25519Error> {
    let mut shared = x25519(secret, peer);
    // constant time over the 32 bytes: OR them together, then test once
    let acc = shared.iter().fold(0u8, |a, &b| a | b);
    if core::hint::black_box(acc) == 0 {
        shared.zeroize();
        return Err(X25519Error::ZeroSharedSecret);
    }
    Ok(shared)
}

/// Why an X25519 key agreement was refused.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X25519Error {
    /// The shared secret is all zero: the peer's public key has small order.
    ZeroSharedSecret,
}

impl core::fmt::Display for X25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroSharedSecret => {
                f.write_str("X25519 shared secret is all zero (peer key of small order)")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for X25519Error {}
