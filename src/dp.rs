//! Differential-privacy noise with a keyed CSPRNG
//!
//! # Why reproducibility and privacy are not in conflict
//!
//! They look like they are: a privacy mechanism wants noise an attacker cannot
//! predict, and an auditable pipeline wants the same noise twice. Both hold at
//! once as soon as the question "what is the determinism anchored to" is
//! answered correctly:
//!
//! - **Anchored to a public value (a clock, a counter) they are in conflict.**
//!   The attacker can guess that value too, regenerate the noise and subtract
//!   it, which leaves the ε claim with nothing behind it.
//! - **Anchored to a secret key they are not.** The same key yields the same
//!   sequence, and without the key the sequence is neither predictable nor
//!   reproducible.
//!
//! So every constructor here takes a key, and the only one that does not —
//! [`DpNoise::try_from_entropy`] — takes it from the OS and **fails** rather
//! than falling back to anything guessable.
//!
//! ⚠️ This module exists because the same defect was found in two ALICE crates
//! on 2026-10-09: a `xorshift64` generator seeded from the system clock, with
//! its state handed back to the caller. Two things were wrong with it. The
//! clock is guessable, so the key could be brute-forced from an approximate
//! time — and worse, **xorshift is F2-linear**, so 64 output bits are enough to
//! solve for the state by linear algebra and reconstruct every past and future
//! value. No brute force needed at all.
//!
//! # What is still not guaranteed
//!
//! ⚠️ Inverse-transform sampling in floating point is subject to **Mironov's
//! 2012 attack**: even with a perfect CSPRNG, the low bits of
//! `scale * ln(u)` carry information about `u`, so the ε that holds for real
//! arithmetic is weaker than the ε that holds for `f64`. The published fix is a
//! snapping mechanism (round the output onto a power-of-two lattice) or a
//! discrete Laplace distribution. Neither is implemented here yet, so the ε
//! below is **the value for ideal real arithmetic**, not a machine-level
//! guarantee.
//!
//! # Example
//!
//! ```
//! use alice_crypto::dp::{dp_count, SecureRng};
//!
//! // The key is the secret the determinism is anchored to. In production it
//! // comes from `SecureRng::try_from_entropy()` or from a key store — never
//! // from a clock.
//! let mut rng = SecureRng::from_key([7u8; 32]);
//! let noisy = dp_count(1_000, 1.0, &mut rng).expect("epsilon > 0");
//! assert!(noisy.is_finite());
//!
//! // Same key, same call order, same answer — which is what makes an audit
//! // possible.
//! let mut again = SecureRng::from_key([7u8; 32]);
//! assert_eq!(dp_count(1_000, 1.0, &mut again).unwrap().to_bits(), noisy.to_bits());
//! ```

use alice_det_math::ln64;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use zeroize::Zeroize;

/// The OS entropy source was unavailable
///
/// ⚠️ Do not paper over this with a clock or a constant. A guessable key lets
/// an attacker regenerate the noise and subtract it, which is exactly the
/// failure this module was written to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "entropy source unavailable; pass a 32-byte key explicitly (never a time-derived seed)",
        )
    }
}

/// A ChaCha20 keystream, handed out 8 bytes at a time
///
/// The stream is RFC 8439 ChaCha20 over the `chacha20` crate, which this crate
/// already depends on through `chacha20poly1305`. Keeping one implementation
/// rather than a second hand-written block function is deliberate: a second
/// copy of a law is a second thing that can drift.
#[derive(Clone)]
pub struct SecureRng {
    key: [u8; 32],
    /// Index of the next 64-byte block. The low 32 bits become the RFC
    /// counter and the high 32 bits select the nonce, so within one key the
    /// `(counter, nonce)` pair never repeats.
    block: u64,
    buf: [u8; 64],
    pos: usize,
}

impl core::fmt::Debug for SecureRng {
    /// Never prints the key
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureRng")
            .field("block", &self.block)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl Drop for SecureRng {
    fn drop(&mut self) {
        self.key.zeroize();
        self.buf.zeroize();
    }
}

impl SecureRng {
    /// Build from a key — the same key yields the same sequence
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        let mut rng = Self {
            key,
            block: 0,
            buf: [0u8; 64],
            pos: 64,
        };
        rng.refill();
        rng
    }

    /// Take a key from the OS entropy source
    ///
    /// # Errors
    ///
    /// [`EntropyError`] when the entropy source is unavailable. ⚠️ Callers must
    /// not fill that in with a clock or a constant — if no key can be obtained,
    /// add no noise and stop.
    pub fn try_from_entropy() -> Result<Self, EntropyError> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| EntropyError)?;
        let rng = Self::from_key(key);
        key.zeroize();
        Ok(rng)
    }

    fn refill(&mut self) {
        let counter = (self.block & 0xffff_ffff) as u32;
        let stream = (self.block >> 32) as u32;
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&stream.to_le_bytes());
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce.into());
        cipher.seek(u64::from(counter) * 64);
        self.buf = [0u8; 64];
        cipher.apply_keystream(&mut self.buf);
        self.pos = 0;
        self.block = self.block.wrapping_add(1);
    }

    /// The next 8 bytes of the keystream
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > 64 {
            self.refill();
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(b)
    }

    /// A uniform `f64` on the 53-bit grid, strictly inside `(0, 1)`
    ///
    /// ⚠️ **Never returns 0.** `ln(0)` is `-inf`, so a 0 fed to the inverse
    /// transform would produce infinite noise; the single zero outcome is moved
    /// to the smallest positive grid point.
    ///
    /// ⚠️ It never returns 1 either, which is why the name says `open01` and
    /// not `(0, 1]`: the 53 bits give `0 … 2^53-1`, so the largest value is
    /// `1 - 2^-53`. The range is `[2^-53, 1 - 2^-53]`. (The doc on the
    /// implementation this was lifted from said `(0, 1]`, which was wrong — the
    /// upper end was never attainable.)
    #[inline]
    pub fn next_f64_open01(&mut self) -> f64 {
        open01_from_bits(self.next_u64())
    }
}

/// 2^-53 — the spacing of the 53-bit grid this draws on
const OPEN01_STEP: f64 = 1.0 / 9_007_199_254_740_992.0;

/// Map a keystream word onto `(0, 1]`
///
/// Split out of [`SecureRng::next_f64_open01`] so the zero case can be checked
/// directly. ⚠️ **It cannot be reached by sampling**: `bits == 0` needs the top
/// 53 bits of a word to be zero, which is a 2⁻⁵³ event — 200,000 draws never
/// produce one, so a test that only draws cannot tell whether the guard is
/// there. Removing the guard survived the destructive run until this function
/// existed to be called with `0` on purpose.
#[inline]
fn open01_from_bits(word: u64) -> f64 {
    let bits = word >> 11; // 53 bits
    #[allow(clippy::cast_precision_loss)]
    let u = (bits as f64) * OPEN01_STEP;
    if u <= 0.0 {
        OPEN01_STEP
    } else {
        u
    }
}

#[cfg(test)]
mod tests {
    use super::{open01_from_bits, OPEN01_STEP};

    #[test]
    fn the_uniform_map_never_returns_zero_even_for_an_all_zero_word() {
        // The 2⁻⁵³ case the sampling tests cannot reach.
        assert_eq!(open01_from_bits(0).to_bits(), OPEN01_STEP.to_bits());
        // Every word whose top 53 bits are zero maps to the same floor.
        for low in [0u64, 1, 0x7ff] {
            assert!(open01_from_bits(low) > 0.0, "word {low} mapped to zero");
        }
    }

    #[test]
    fn the_uniform_map_stays_strictly_inside_zero_and_one() {
        // 53 bits give 0 … 2^53-1, so the top of the range is 1 - 2^-53 and
        // **1.0 is not attainable**. Asserted rather than described, because
        // the doc this code was lifted from claimed `(0, 1]`.
        let top = open01_from_bits(u64::MAX);
        assert_eq!(top.to_bits(), (1.0f64 - OPEN01_STEP).to_bits());
        assert!(top < 1.0, "the map returned {top}, which is not below 1");

        let one_step = open01_from_bits(1u64 << 11);
        assert_eq!(one_step.to_bits(), OPEN01_STEP.to_bits());
        let two_steps = open01_from_bits(2u64 << 11);
        assert_eq!(two_steps.to_bits(), (2.0 * OPEN01_STEP).to_bits());
    }
}

/// The scale (= sensitivity / ε) was not a usable value
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpError {
    /// Not a finite positive number (0, negative, NaN or infinite)
    ///
    /// ⚠️ The implementation this replaced accepted all of these and produced
    /// noise of 0 or NaN without anyone noticing.
    InvalidScale,
    /// The OS entropy source was unavailable
    Entropy(EntropyError),
}

impl core::fmt::Display for DpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidScale => {
                f.write_str("scale must be finite and > 0 (scale = sensitivity / epsilon)")
            }
            Self::Entropy(e) => write!(f, "{e}"),
        }
    }
}

/// Laplace noise generator
///
/// Determinism is anchored to the **32-byte secret key**: the same key yields
/// the same sequence (replay, audit, tests), and without it the sequence is
/// neither predictable nor reproducible.
///
/// ⚠️ Do not derive the key from a clock, a counter or a constant. On `no_std`
/// the caller passes a secret key to [`Self::with_key`].
#[derive(Clone, Debug)]
pub struct DpNoise {
    /// Laplace scale b (= sensitivity / ε)
    scale: f64,
    rng: SecureRng,
}

impl DpNoise {
    /// Build from a key
    ///
    /// # Panics
    ///
    /// When `scale` is not finite and positive. Use [`Self::try_with_key`] to
    /// handle that as an error.
    #[must_use]
    pub fn with_key(scale: f64, key: [u8; 32]) -> Self {
        Self::try_with_key(scale, key).expect("scale must be finite and > 0")
    }

    /// Build from a key, reporting an unusable scale
    ///
    /// # Errors
    ///
    /// [`DpError::InvalidScale`] when `scale` is not finite and positive
    pub fn try_with_key(scale: f64, key: [u8; 32]) -> Result<Self, DpError> {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(DpError::InvalidScale);
        }
        Ok(Self {
            scale,
            rng: SecureRng::from_key(key),
        })
    }

    /// Take the key from the OS entropy source
    ///
    /// # Errors
    ///
    /// [`DpError::InvalidScale`] for an unusable scale, [`DpError::Entropy`]
    /// when no key can be obtained. ⚠️ **Never falls back to a clock.**
    pub fn try_from_entropy(scale: f64) -> Result<Self, DpError> {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(DpError::InvalidScale);
        }
        Ok(Self {
            scale,
            rng: SecureRng::try_from_entropy().map_err(DpError::Entropy)?,
        })
    }

    /// Draw one `Laplace(0, scale)` sample
    ///
    /// Inverse transform: one keystream bit for the sign, `-b·ln(u)` with
    /// `u ∈ (0, 1]` for the magnitude.
    #[inline]
    pub fn laplace(&mut self) -> f64 {
        laplace_from(self.scale, &mut self.rng)
    }

    /// The scale in use
    #[inline]
    #[must_use]
    pub const fn scale(&self) -> f64 {
        self.scale
    }
}

/// One Laplace draw from a borrowed stream
///
/// ⚠️ The sign comes from a **separate** keystream bit rather than from `u`.
/// Reusing `u` for both would correlate the sign with the magnitude and thin
/// out one tail.
#[inline]
fn laplace_from(scale: f64, rng: &mut SecureRng) -> f64 {
    let sign_bit = rng.next_u64() & 1;
    let u = rng.next_f64_open01();
    let magnitude = -scale * ln64(u);
    if sign_bit == 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// Differentially private count: `count + Lap(1/ε)`
///
/// Sensitivity 1 (one person entering or leaving changes the count by 1) is
/// assumed, so `scale = 1/ε` is derived **here**.
///
/// ⚠️ **An ε that is accepted and ignored is worse than no ε at all.** Taking
/// the scale as a parameter would let the caller's ε and the actual noise
/// disagree with nothing to detect it — the wiring mutation becomes the
/// identity. This takes the stream only and derives the scale from ε.
///
/// # Errors
///
/// [`DpError::InvalidScale`] when `epsilon` is not finite and positive
pub fn dp_count(true_count: u64, epsilon: f64, rng: &mut SecureRng) -> Result<f64, DpError> {
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(DpError::InvalidScale);
    }
    #[allow(clippy::cast_precision_loss)]
    let base = true_count as f64;
    Ok(base + laplace_from(1.0 / epsilon, rng))
}

/// Differentially private sum: `sum + Lap(sensitivity/ε)`
///
/// # Errors
///
/// [`DpError::InvalidScale`] when `sensitivity` or `epsilon` is not finite and
/// positive
pub fn dp_sum(
    true_sum: f64,
    sensitivity: f64,
    epsilon: f64,
    rng: &mut SecureRng,
) -> Result<f64, DpError> {
    if !sensitivity.is_finite() || sensitivity <= 0.0 || !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(DpError::InvalidScale);
    }
    Ok(true_sum + laplace_from(sensitivity / epsilon, rng))
}
