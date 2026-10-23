//! Random bytes from the operating system, on every call.
//!
//! [`fill`] reads the OS entropy source each time it is called and keeps nothing between calls, so no state in
//! this process predicts past or future output. That is what a protocol with forward secrecy needs from its
//! random source (MLS, RFC 9420 section 16.1: ephemeral HPKE keys and path secrets): a seeded generator
//! ([`crate::dp::SecureRng`]) keeps its key in memory, and one read of that key gives every draw.
//!
//! When the OS source fails, [`fill`] returns [`RngError::Unavailable`]. It never falls back to a seeded stream,
//! a clock or a constant; the caller must stop.

/// Fills `buf` with bytes from the operating system's random source.
///
/// # Errors
///
/// [`RngError::Unavailable`] when the source fails; `buf` must then not be used.
#[expect(
    clippy::disallowed_methods,
    reason = "secret material generation, not Law output: protocol keys and nonces must be unpredictable, and no Law-bearing result is computed from them"
)]
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    getrandom::getrandom(buf).map_err(|_| RngError::Unavailable)
}

/// Why random bytes could not be produced.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// The operating system's random source is unavailable.
    Unavailable,
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("the operating system's random source is unavailable"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RngError {}
