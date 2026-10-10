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
//! # What the mechanisms guarantee, and why they sample with integers
//!
//! Inverse-transform sampling in floating point (`-b · ln(u)`) is subject to
//! **Mironov's 2012 attack**: even with a perfect CSPRNG, the low bits of the
//! result carry information about `u`, so the ε that holds for real
//! arithmetic does not hold for `f64`. A better random source does not help;
//! the leak is in the transform. This module therefore uses **no
//! floating-point `ln` or `exp` at all**:
//!
//! - [`dp_count`] adds discrete Laplace noise,
//!   `P(Z = z) = (1 − e^−ε) / (1 + e^−ε) · e^(−ε·|z|)`, sampled exactly with
//!   the Bernoulli(`e^−γ`) construction of Canonne, Kamath and Steinke ("The
//!   Discrete Gaussian for Differential Privacy", NeurIPS 2020, Algorithms 1
//!   and 2) from uniform integers drawn by rejection. ε is converted exactly
//!   from its `f64` value to a rational. The count is an integer and so is the
//!   noise: there is no rounding loss, so ε_eff = ε (with the δ below).
//! - [`DpNoise::privatize`] and [`dp_sum`] round the value to the nearest
//!   multiple of the lattice `Λ = 2^(⌊log2 Δ⌋ − 20)` and add `Λ · Z`, `Z`
//!   discrete Laplace with decay `ε · Λ / Δ` per lattice step from the same
//!   sampler. Two values within the sensitivity Δ round to lattice points at
//!   most `⌊Δ/Λ⌋ + 1` steps apart, so the mechanism is `ε_eff`-differentially
//!   private with
//!
//!   ```text
//!   ε_eff = ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ  ≤  ε · (1 + Λ/Δ)  ≤  ε · (1 + 2^-20)
//!   ```
//!
//!   ([`DpNoise::effective_epsilon`]): the rounding costs at most `2^-20 · ε`.
//!   Every output is an exact multiple of Λ (`|value| / Λ < 2^52`, otherwise
//!   [`DpError::ValueOutOfRange`]), so no part of it lies below the lattice.
//!
//! Mironov's own fix, the snapping mechanism, was not used: its ε bound
//! assumes a correctly rounded `ln`, and the deterministic `ln64` of
//! `alice-det-math` (fdlibm) is accurate to within 1 ulp but not correctly
//! rounded, so the bound would not have been established.
//!
//! # Constant time, and the δ that buys it
//!
//! A sampler whose loops run until a random stop takes longer for larger
//! noise, and the noisy output is published: an observer who can time the
//! call learns roughly how large the noise was and so where the true value
//! lies. Every sampling function here therefore does **the same work for
//! every value it draws**: loops have fixed trip counts, choices are made with
//! masks, uniform draws use a 256 × 128-bit multiply (no division with a
//! secret dividend), and `⌊X/s⌋` is a multiply by the public reciprocal plus
//! two masked corrections. Each call draws a fixed number of keystream words
//! that depends on ε and Δ only ([`SecureRng::words_drawn`],
//! `tests/dp_cost_model.rs`); the functions carry a `// CONSTANT-TIME:` marker
//! that `scripts/constant_time_guard.py` checks for value-dependent control
//! flow. The release build for aarch64 was read at the instruction level:
//! in `discrete_laplace` and `uniform_below` the value comparisons compile to
//! conditional selects, and the only conditional branches are loop counters,
//! keystream buffer refills (which depend on the fixed word count), slice
//! bounds checks and the division-by-zero check of the public divisor. ⚠️ Other
//! targets (x86_64 and the rest) and other compiler versions have not been
//! read; a compiler is free to turn a select into a branch.
//!
//! Every random component of a draw takes its own fresh keystream words, in a
//! fixed order, and no word is read twice: per attempt, 4 words for `U`
//! (`uniform_below`), 4 for each of the 32 Bernoulli steps (each a separate
//! `uniform_below`), 2 for the geometric part and 1 for the sign. The words
//! are consecutive outputs of ChaCha20, so the components are independent
//! exactly as the algorithm requires (the same assumption as for any
//! stream-cipher-based generator). A uniform draw uses both of its 128-bit
//! halves; using one would still be uniform but would raise its bias from
//! `n / 2^256` to `n / 2^128`, which the δ below does not allow (pinned by an
//! exact test against an independent 256-bit multiplication).
//!
//! An attempt that is not the first accepted one is still run but its result
//! is dropped. Attempts are independent and identically distributed, and the
//! choice of which accepted attempt to keep depends only on the acceptance
//! flags, not on the values: keeping the first (as here) or the last accepted
//! attempt gives the same output distribution, the target one conditioned on
//! acceptance.
//!
//! Fixing the trip counts truncates tails of the ideal algorithm. Summed per
//! draw (up to 190 attempts, each with one Bernoulli run, one geometric part
//! and 33 uniform draws), the output differs from the exact discrete Laplace
//! distribution by at most `η < 2^-103` in statistical distance. Each bound
//! below is computed exactly with rationals by `scripts/dp_delta_budget.py`,
//! which also checks these numbers and the constants they come from:
//!
//! | truncation | probability per draw |
//! |---|---|
//! | all attempts of CKS20 Algorithm 2 rejected (then 0 is returned) | `< 2^-104` |
//! | a Bernoulli(`e^−γ`) run with no zero in 32 steps, `γ^32/32! ≤ 1/32!` per attempt | `≤ 190/32! < 2^-110` |
//! | the geometric part above 88 (`⌊e^−m · 2^128⌋` = 0 beyond), per attempt | `≤ 190 · e^−89 < 2^-120` |
//! | the 88 rounded thresholds `⌊e^−m · 2^128⌋`, per attempt | `≤ 190 · 88 · 2^-128 < 2^-113` |
//! | uniform draws without rejection (bias `n / 2^256` each, 33 per attempt) | `< 2^-141` |
//!
//! The mechanisms are therefore `(ε_eff, δ)`-differentially private with
//! `δ = (1 + e^ε_eff) · η` (ε_eff = ε for [`dp_count`]), not purely
//! ε-differentially private.
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
//! let noisy: i64 = dp_count(1_000, 1.0, &mut rng).expect("epsilon > 0");
//!
//! // Same key, same call order, same answer — which is what makes an audit
//! // possible.
//! let mut again = SecureRng::from_key([7u8; 32]);
//! assert_eq!(dp_count(1_000, 1.0, &mut again).unwrap(), noisy);
//! ```

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

/// Keystream blocks generated per cipher setup
const BUF_BLOCKS: usize = 64;

/// The last ChaCha20 block counter a stream uses (`2^32 − 2`); see `refill`
const LAST_COUNTER: u32 = u32::MAX - 1;

/// A ChaCha20 keystream, handed out 8 bytes at a time
///
/// The stream is RFC 8439 ChaCha20 over the `chacha20` crate, which this crate
/// already depends on through `chacha20poly1305`. Keeping one implementation
/// rather than a second hand-written block function is deliberate: a second
/// copy of a law is a second thing that can drift.
///
/// Keystream definition: block `i` of nonce stream `n` (the 96-bit nonce is
/// `[0, 0, 0, 0] ‖ n as u32 LE ‖ [0, 0, 0, 0]`) is the RFC 8439 block with
/// counter `i`, for `i = 0 ..= 2^32 − 2`; after the last one the stream
/// continues at counter 0 of nonce stream `n + 1`. Counter `2^32 − 1` is never
/// used. Before 0.4.0 the generator asked for that block and panicked after
/// `2^32 − 1` blocks (about 256 GiB, a few million noise draws); everything
/// before it is unchanged. After nonce stream `2^32 − 1` the 64-bit block index
/// wraps to stream 0, counter 0, so one key's keystream repeats after `2^64`
/// blocks (`2^70` bytes): unreachable in practice, and a key must be rotated
/// long before.
#[derive(Clone)]
pub struct SecureRng {
    key: [u8; 32],
    /// Index of the next 64-byte block. The low 32 bits become the RFC
    /// counter (at most `2^32 − 2`, see the keystream definition) and the high
    /// 32 bits select the nonce, so within one key the `(counter, nonce)` pair
    /// never repeats.
    block: u64,
    /// Up to [`BUF_BLOCKS`] consecutive keystream blocks
    buf: [u8; 64 * BUF_BLOCKS],
    /// Bytes of `buf` filled by the last refill
    len: usize,
    pos: usize,
    /// 64-bit words handed out so far
    words: u64,
}

impl core::fmt::Debug for SecureRng {
    /// Never prints the key
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureRng")
            .field("block", &self.block)
            .field("pos", &self.pos)
            .field("words", &self.words)
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
            buf: [0u8; 64 * BUF_BLOCKS],
            len: 0,
            pos: 0,
            words: 0,
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

    /// Fill the buffer with the next blocks of the keystream: up to
    /// [`BUF_BLOCKS`] blocks, never crossing a counter wrap (the nonce changes
    /// there), so the stream is the same as one block at a time
    fn refill(&mut self) {
        // A stream yields counters 0 ..= 2^32 − 2: the `chacha20` crate
        // refuses the block at counter 2^32 − 1 (its 32-bit counter would wrap
        // after it), and asking for it panicked after 2^32 − 1 blocks (≈ 256 GiB
        // of keystream). At that point the next block is counter 0 of the next
        // stream (the 32-bit value in nonce bytes 4..8)
        if self.block & 0xffff_ffff == u64::from(LAST_COUNTER) + 1 {
            self.block = (self.block | 0xffff_ffff).wrapping_add(1);
        }
        let counter = (self.block & 0xffff_ffff) as u32;
        let stream = (self.block >> 32) as u32;
        let left_in_nonce = u64::from(LAST_COUNTER) + 1 - u64::from(counter);
        #[allow(clippy::cast_possible_truncation)]
        let blocks = left_in_nonce.min(BUF_BLOCKS as u64) as usize;
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&stream.to_le_bytes());
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce.into());
        cipher.seek(u64::from(counter) * 64);
        self.buf = [0u8; 64 * BUF_BLOCKS];
        self.len = blocks * 64;
        cipher.apply_keystream(&mut self.buf[..self.len]);
        self.pos = 0;
        self.block = self.block.wrapping_add(blocks as u64);
    }

    /// The next 8 bytes of the keystream
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > self.len {
            self.refill();
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        self.words += 1;
        u64::from_le_bytes(b)
    }

    /// The number of 64-bit words this stream has handed out
    ///
    /// The noise functions of this module draw a fixed number of words per
    /// call whatever values they draw (the work does not depend on the noise),
    /// which this count lets a caller or a test check.
    #[must_use]
    pub const fn words_drawn(&self) -> u64 {
        self.words
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

/// A differential-privacy parameter or value was not usable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpError {
    /// ε or the sensitivity is not a finite positive number (0, negative, NaN
    /// or infinite)
    ///
    /// ⚠️ The implementation this replaced accepted all of these and produced
    /// noise of 0 or NaN without anyone noticing.
    InvalidScale,
    /// ε (or ε scaled to the lattice, `ε·Λ/Δ`) is so small or so large that
    /// its exact rational does not fit the sampler's 96-bit integers
    EpsilonOutOfRange,
    /// The true count does not fit an `i64`, or count (or integer value) +
    /// noise overflows it. The result is refused, never saturated: a clamped
    /// output would tell the observer the noise ran past the limit
    CountOutOfRange,
    /// The value is too large for its lattice: `|x| / Λ` must stay below
    /// 2^52 so that rounding and `Λ · k` are exact in `f64`
    ValueOutOfRange,
    /// A probability `num / den` with `den = 0` or `num > den`
    InvalidProbability,
    /// The OS entropy source was unavailable
    Entropy(EntropyError),
}

impl core::fmt::Display for DpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidScale => f.write_str("epsilon and sensitivity must be finite and > 0"),
            Self::EpsilonOutOfRange => {
                f.write_str("epsilon is outside the range the exact sampler supports")
            }
            Self::CountOutOfRange => f.write_str("count or count + noise does not fit an i64"),
            Self::ValueOutOfRange => f.write_str("|value| / lattice must stay below 2^52"),
            Self::InvalidProbability => {
                f.write_str("probability num / den needs den > 0 and num <= den")
            }
            Self::Entropy(e) => write!(f, "{e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Exact sampling (Canonne, Kamath, Steinke, NeurIPS 2020, Algorithms 1 and 2)
// ---------------------------------------------------------------------------

/// Numerators and denominators of the rationals the sampler works with stay
/// below this, so `U + t·V` and `y·K` cannot overflow `u128` in practice
const RATIONAL_LIMIT: u128 = 1 << 96;

/// A positive dyadic rational `num / den` (both below [`RATIONAL_LIMIT`])
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ratio {
    num: u128,
    den: u128,
}

/// The exact value of a finite positive `f64` as `m · 2^e` with `m` odd
fn dyadic(x: f64) -> Option<(u64, i32)> {
    if !x.is_finite() || x <= 0.0 {
        return None;
    }
    let bits = x.to_bits();
    let exp_field = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    let (mut m, mut e) = if exp_field == 0 {
        (frac, -1074)
    } else {
        (frac | (1u64 << 52), exp_field - 1075)
    };
    let tz = m.trailing_zeros();
    m >>= tz;
    e += i32::try_from(tz).ok()?;
    Some((m, e))
}

/// `a · 2^shift / b` as a [`Ratio`], or `None` when it does not fit
fn ratio_from_parts(a: u64, b: u64, shift: i32) -> Option<Ratio> {
    let (mut num, mut den) = (u128::from(a), u128::from(b));
    if shift >= 0 {
        num = num.checked_shl(u32::try_from(shift).ok()?)?;
    } else {
        den = den.checked_shl(u32::try_from(-shift).ok()?)?;
    }
    if num == 0 || num >= RATIONAL_LIMIT || den >= RATIONAL_LIMIT {
        return None;
    }
    Some(Ratio { num, den })
}

// Every function from here to `discrete_laplace` runs the same instructions
// and draws the same number of keystream words whatever values it draws: loops
// have fixed trip counts, choices are made with masks, and the only division
// is a fixed 128-step shift-and-subtract. A loop that would stop early in the
// textbook algorithm runs to its bound and keeps the first result with a mask.
// Each bound truncates a tail; the probabilities are summed in the module doc
// (δ).

/// Fixed iterations of CKS20 Algorithm 1 (`γ < 1`): a run with no zero in
/// these steps has probability `γ^K/K! ≤ 1/K!`; with up to 190 runs per draw,
/// `190/32! < 2^-110` (the smallest K meeting that bound, checked by
/// `scripts/dp_delta_budget.py`)
const BERNOULLI_STEPS: u128 = 32;

/// Fixed attempts of CKS20 Algorithm 2 for decay `rate = s/t`. An attempt is
/// accepted with probability `p = P(accept step 2) · (1 − P(Y = 0)/2)` with
/// `P(accept step 2) ≥ 1 − e^−1` and `P(Y = 0) = 1 − e^(−rate)`, so
/// `p ≥ (1 − e^−1)(1 + e^(−rate))/2`; the count makes `(1 − p)^attempts`
/// `< 2^-104` for every rate in its band:
///
/// | rate | p ≥ | attempts |
/// |---|---|---|
/// | ≤ 2^-10 | 0.6316 | 74 |
/// | ≤ 1 | 0.4322 | 128 |
/// | any | 0.3160 | 190 |
///
/// The band is chosen from the public rate only.
const fn laplace_attempts(rate: Ratio) -> usize {
    if rate.num.saturating_mul(1 << 10) <= rate.den {
        74
    } else if rate.num <= rate.den {
        128
    } else {
        190
    }
}

/// `⌊e^(−m) · 2^128⌋` for `m = 1 … 88` (every `m` with a non-zero value):
/// `P(V ≥ m) = e^(−m)` for the geometric part of the discrete Laplace sampler,
/// read off one uniform 128-bit draw `r` as `V = #{m : r < GEOMETRIC_TAIL[m − 1]}`.
/// Generated with Python `decimal` at 120 significant digits
/// (`int(Decimal(-m).exp() * 2**128)`); `V` is capped at 88, a tail of
/// `e^(−89) < 2^-128`.
const GEOMETRIC_TAIL: [u128; 88] = [
    125182886983370532117250726298150828301,
    46052210507670172419625860892627118819,
    16941661466271327126146327822211253888,
    6232488952727653950957829210887653621,
    2292804553036637136093891217529878877,
    843475657686456657683449904934172134,
    310297353591408453462393329342695979,
    114152017036184782947077973323212574,
    41994180235864621538772677139808694,
    15448795557622704876497742989562085,
    5683294276510101335127414470015661,
    2090767122455392675095471286328463,
    769150240628514374138961856925096,
    282954560699298259527814398449860,
    104093165666968799599694528310220,
    38293735615330848145349245349512,
    14087478058534870382224480725095,
    5182493555688763339001418388911,
    1906532833141383353974257736699,
    701374233231058797338605168651,
    258021160973090761055471434334,
    94920680509187392077350434437,
    34919366901332874995585576426,
    12846117181722897538509298435,
    4725822410035083116489797150,
    1738532907279185132707372377,
    639570514388029575350057932,
    235284843422800231081973820,
    86556456714490055457751527,
    31842340925906738090071267,
    11714142585413118080082436,
    4309392228124372433711936,
    1585336804670950817645106,
    583212817770869398037391,
    214552005485569659696907,
    78929271880243593899280,
    29036456431372849880491,
    10681915365572376378113,
    3929657055327408836382,
    1445640041509262763346,
    531821250605488266609,
    195646104475844604930,
    71974179581943333627,
    26477820963378347710,
    9740645979445127124,
    3583383399567129817,
    1318253082535778928,
    484958207325793583,
    178406154302517409,
    65631956346356214,
    24144647423686021,
    8882319401507118,
    3267622697732698,
    1202091212001025,
    442224643308039,
    162685354652401,
    59848597356303,
    22017068550331,
    8099626874529,
    2979686208299,
    1096165297175,
    403256676956,
    148349840967,
    54574856592,
    20076967745,
    7385903674,
    2717122116,
    999573365,
    367722491,
    135277544,
    49765827,
    18307824,
    6735072,
    2477694,
    911492,
    335319,
    123357,
    45380,
    16694,
    6141,
    2259,
    831,
    305,
    112,
    41,
    15,
    5,
    2,
];

/// All-ones when `bit` is 1, zero when it is 0
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn mask(bit: u128) -> u128 {
    0u128.wrapping_sub(bit & 1)
}

/// `a` where `m` is all-ones, `b` where it is zero
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn select(m: u128, a: u128, b: u128) -> u128 {
    (a & m) | (b & !m)
}

/// 1 when `a < b`, else 0, from the borrow of `a − b`
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn lt(a: u128, b: u128) -> u128 {
    u128::from(a.overflowing_sub(b).1)
}

/// The full 256-bit product of two `u128` as `(high, low)`, from four 64-bit
/// products (fixed-time multiplications)
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    let (a1, a0) = (a >> 64, a & u128::from(u64::MAX));
    let (b1, b0) = (b >> 64, b & u128::from(u64::MAX));
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & u128::from(u64::MAX)) + (p10 & u128::from(u64::MAX));
    let low = (p00 & u128::from(u64::MAX)) | (mid << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

/// A uniform 128-bit draw from the keystream
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn draw128(rng: &mut SecureRng) -> u128 {
    (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())
}

/// `⌊(r1 · 2^128 + r0) · n / 2^256⌋`, the top 128 bits of a 256 × 128-bit
/// product (`n < 2^128`)
// CONSTANT-TIME: fixed work and keystream draws for every value
fn lemire_top(r1: u128, r0: u128, n: u128) -> u128 {
    let (h0, _) = mul_wide(r0, n);
    let (h1, l1) = mul_wide(r1, n);
    // r·n = h1·2^256 + (l1 + h0)·2^128 + low: the carry of l1 + h0 reaches 2^256
    let (_, carry) = l1.overflowing_add(h0);
    h1 + u128::from(carry)
}

/// A uniform integer in `[0, n)` for a public `n < 2^128`: the top 128 bits
/// of `r · n` for one uniform 256-bit `r` (Lemire's multiply, without the
/// rejection step). The result is off uniform by at most `n / 2^256 ≤ 2^-154`
/// in statistical distance (`n < 2^102` here), and the work is the same for
/// every draw.
// CONSTANT-TIME: fixed work and keystream draws for every value
fn uniform_below(n: u128, rng: &mut SecureRng) -> u128 {
    let (r1, r0) = (draw128(rng), draw128(rng));
    lemire_top(r1, r0, n)
}

/// 1 with probability `x / den` (`x ≤ den`, `den` public), else 0
// CONSTANT-TIME: fixed work and keystream draws for every value
#[inline(always)]
fn bernoulli_ct(x: u128, den: u128, rng: &mut SecureRng) -> u128 {
    lt(uniform_below(den, rng), x)
}

/// 1 with probability `exp(−x/y)` for `0 ≤ x ≤ y` (CKS20 Algorithm 1): draw
/// `A_k ~ Bernoulli(γ/k)` for `k = 1, 2, …` until one is 0; the index of that
/// zero is odd with probability `exp(−γ)`. All [`BERNOULLI_STEPS`] draws are
/// made; a run with no zero (probability `γ^32/32! ≤ 1/32!`) returns 0.
// CONSTANT-TIME: fixed work and keystream draws for every value
fn bernoulli_exp_neg(x: u128, y: u128, rng: &mut SecureRng) -> u128 {
    let mut alive = u128::MAX; // all-ones while no zero has been drawn
    let mut stopped_at = 0u128;
    for k in 1..=BERNOULLI_STEPS {
        let a = bernoulli_ct(x, y * k, rng);
        stopped_at = select(alive & mask(1 - a), k, stopped_at);
        alive &= mask(a);
    }
    stopped_at & 1
}

/// `V ≥ 0` with `P(V ≥ m) = e^(−m)`, read off one uniform draw against
/// [`GEOMETRIC_TAIL`]
// CONSTANT-TIME: fixed work and keystream draws for every value
fn geometric(rng: &mut SecureRng) -> u128 {
    let r = draw128(rng);
    GEOMETRIC_TAIL.iter().map(|&t| lt(r, t)).sum()
}

/// `⌊n / d⌋` for `n < 2^104` and a public `d > 0`, with a fixed sequence of
/// operations. With `m = ⌊(2^128 − 1)/d⌋ > 2^128/d − 2`, the high half of `n·m`
/// is at least `⌊n/d − 2n/2^128⌋ ≥ ⌊n/d − 2^-23⌋ ≥ ⌊n/d⌋ − 1` (`n < 2^104`)
/// and at most `⌊n/d⌋`, so one masked correction step gives the quotient.
// CONSTANT-TIME: fixed work and keystream draws for every value
fn div_floor(n: u128, d: u128) -> u128 {
    let reciprocal = u128::MAX / d; // public
    let (q, _) = mul_wide(n, reciprocal);
    let r = n.wrapping_sub(q.wrapping_mul(d));
    q + (1 - lt(r, d))
}

/// One draw of the discrete Laplace distribution with decay `rate = s/t`
/// per unit, `P(Z = z) ∝ exp(−(s/t)·|z|)` (CKS20 Algorithm 2, scale `t/s`).
/// All [`laplace_attempts`] attempts run; the first accepted one is returned
/// and, if none is (probability `< 2^-104`), 0.
// CONSTANT-TIME: fixed work and keystream draws for every value
fn discrete_laplace(rate: Ratio, rng: &mut SecureRng) -> i128 {
    let (s, t) = (rate.num, rate.den);
    let mut result = 0u128; // two's complement of the signed draw
    let mut found = 0u128;
    for _ in 0..laplace_attempts(rate) {
        let u = uniform_below(t, rng);
        let d = bernoulli_exp_neg(u, t, rng);
        let v = geometric(rng);
        // x = u + t·v < 2^96 · 89 + 2^96: no overflow
        let y = div_floor(u + t * v, s);
        let negative = u128::from(rng.next_u64() & 1);
        let is_zero = lt(y, 1);
        let accept = mask(d & (1 - (negative & is_zero)));
        let signed = select(mask(negative), y.wrapping_neg(), y);
        result = select(!found & accept, signed, result);
        found |= accept;
    }
    #[allow(clippy::cast_possible_wrap)]
    let z = result as i128;
    z
}

/// `⌊rate⌋`: how many `e^−1` factors [`bernoulli_exp_neg_any`] draws, read
/// off the public rate only
const fn exp_neg_whole_steps(rate: Ratio) -> u128 {
    rate.num / rate.den
}

/// 1 with probability `exp(−rate)` for any public `rate = s/t`: `e^−1` drawn
/// `⌊rate⌋` times and `exp(−(rate − ⌊rate⌋))` once, all with
/// [`bernoulli_exp_neg`]; the product of independent draws is their AND
// CONSTANT-TIME: fixed work and keystream draws for every value
fn bernoulli_exp_neg_any(rate: Ratio, rng: &mut SecureRng) -> u128 {
    let mut all = 1u128;
    for _ in 0..exp_neg_whole_steps(rate) {
        all &= bernoulli_exp_neg(1, 1, rng);
    }
    all & bernoulli_exp_neg(rate.num % rate.den, rate.den, rng)
}

/// Fixed rounds of the randomized-response flip: a round is accepted with
/// probability `(1 + e^−ε)/2 ≥ 1/2`, so no acceptance in all rounds has
/// probability `≤ 2^-105` (`scripts/dp_rr_exact.py`)
const RR_ROUNDS: usize = 105;

/// The largest `⌊ε⌋` randomized response accepts: the flip probability
/// `1/(1 + e^ε)` is below `2^-91` there, and the work grows with `⌊ε⌋`
pub const RR_MAX_EPSILON_WHOLE: u64 = 63;

/// 1 with probability `e^−ε / (1 + e^−ε) = 1/(1 + e^ε)` for `ε = rate`:
/// each round draws a fair coin and `B ~ Bernoulli(e^−ε)`; heads
/// accepts "keep", tails accepts "flip" when `B = 1`, and anything else
/// rejects the round. Given acceptance, "flip" has probability
/// `(e^−ε/2) / (1/2 + e^−ε/2)`. All [`RR_ROUNDS`] rounds run; the first
/// accepted one decides and, if none is, the bit is kept.
// CONSTANT-TIME: fixed work and keystream draws for every value
fn rr_flip(rate: Ratio, rng: &mut SecureRng) -> u128 {
    let mut result = 0u128;
    let mut found = 0u128;
    for _ in 0..RR_ROUNDS {
        let heads = u128::from(rng.next_u64() & 1);
        let b = bernoulli_exp_neg_any(rate, rng);
        let accept = mask(heads | b);
        result = select(!found & accept, 1 - heads, result);
        found |= accept;
    }
    result
}

// ---------------------------------------------------------------------------
// Public mechanisms
// ---------------------------------------------------------------------------

/// The lattice and the per-lattice-step decay for sensitivity Δ and ε
///
/// `Λ = 2^(⌊log2 Δ⌋ − 20)` and `rate = ε · Λ / Δ`, both exact.
fn lattice_and_rate(sensitivity: f64, epsilon: f64) -> Result<(f64, Ratio), DpError> {
    let (eps_m, eps_e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    let (d_m, d_e) = dyadic(sensitivity).ok_or(DpError::InvalidScale)?;
    // ⌊log2 Δ⌋ = d_e + bitlen(d_m) − 1, read off the representation exactly
    let d_bits = 64 - i32::try_from(d_m.leading_zeros()).map_err(|_| DpError::InvalidScale)?;
    let lattice_exp = d_e + d_bits - 1 - 20;
    let lattice = pow2(lattice_exp).ok_or(DpError::ValueOutOfRange)?;
    // rate = (eps_m · 2^eps_e) · 2^lattice_exp / (d_m · 2^d_e)
    let rate = ratio_from_parts(eps_m, d_m, eps_e + lattice_exp - d_e)
        .ok_or(DpError::EpsilonOutOfRange)?;
    Ok((lattice, rate))
}

/// `2^e` as a normal `f64`, or `None` outside the normal range
fn pow2(e: i32) -> Option<f64> {
    if !(-1022..=1023).contains(&e) {
        return None;
    }
    Some(f64::from_bits(u64::try_from(e + 1023).ok()? << 52))
}

/// 2^52: adding and subtracting it rounds a value below 2^52 in magnitude to
/// the nearest integer (ties to even) in IEEE 754 binary64
const TWO_52: f64 = 4_503_599_627_370_496.0;

/// `x` rounded to the nearest multiple of `lattice` (a power of two), as the
/// integer `k` with `round(x) = k · lattice`
fn round_to_lattice(x: f64, lattice: f64) -> Result<i64, DpError> {
    if !x.is_finite() {
        return Err(DpError::ValueOutOfRange);
    }
    let scaled = x / lattice; // exact: lattice is a power of two
    if scaled.abs() >= TWO_52 {
        return Err(DpError::ValueOutOfRange);
    }
    // ±2^52 with the sign of `scaled`, by bit transfer rather than a branch
    let shift = f64::from_bits(TWO_52.to_bits() | (scaled.to_bits() & (1u64 << 63)));
    let rounded = (scaled + shift) - shift;
    #[allow(clippy::cast_possible_truncation)]
    Ok(rounded as i64)
}

/// Differential-privacy noise on a lattice, for values of sensitivity Δ
///
/// `privatize(x)` rounds `x` to the nearest multiple of the lattice
/// `Λ = 2^(⌊log2 Δ⌋ − 20)` and adds `Λ · Z` with `Z` discrete Laplace of decay
/// `ε · Λ / Δ` per lattice step, sampled with integer arithmetic only. Two
/// values within Δ of each other round to lattice points at most
/// `⌊Δ/Λ⌋ + 1` steps apart, so the mechanism is `ε_eff`-differentially private
/// with `ε_eff = ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ ≤ ε · (1 + Λ/Δ) ≤ ε · (1 + 2^-20)`
/// ([`Self::effective_epsilon`]).
///
/// Determinism is anchored to the **32-byte secret key**: the same key yields
/// the same sequence (replay, audit, tests), and without it the sequence is
/// neither predictable nor reproducible. ⚠️ Do not derive the key from a
/// clock, a counter or a constant.
#[derive(Clone, Debug)]
pub struct DpNoise {
    sensitivity: f64,
    epsilon: f64,
    lattice: f64,
    rate: Ratio,
    rng: SecureRng,
}

impl DpNoise {
    /// Build from a key
    ///
    /// # Panics
    ///
    /// When the parameters are refused by [`Self::try_with_key`].
    #[must_use]
    pub fn with_key(sensitivity: f64, epsilon: f64, key: [u8; 32]) -> Self {
        Self::try_with_key(sensitivity, epsilon, key)
            .expect("sensitivity and epsilon must be finite, > 0 and in range")
    }

    /// Build from a key, reporting unusable parameters
    ///
    /// # Errors
    ///
    /// [`DpError::InvalidScale`] when `sensitivity` or `epsilon` is not finite
    /// and positive, [`DpError::EpsilonOutOfRange`] when `ε · Λ / Δ` does not
    /// fit the sampler, [`DpError::ValueOutOfRange`] when the lattice is not a
    /// normal `f64`.
    pub fn try_with_key(sensitivity: f64, epsilon: f64, key: [u8; 32]) -> Result<Self, DpError> {
        Self::build(sensitivity, epsilon, SecureRng::from_key(key))
    }

    /// Take the key from the OS entropy source
    ///
    /// # Errors
    ///
    /// As [`Self::try_with_key`], and [`DpError::Entropy`] when no key can be
    /// obtained. ⚠️ **Never falls back to a clock.**
    pub fn try_from_entropy(sensitivity: f64, epsilon: f64) -> Result<Self, DpError> {
        let (lattice, rate) = lattice_and_rate(sensitivity, epsilon)?;
        let rng = SecureRng::try_from_entropy().map_err(DpError::Entropy)?;
        Ok(Self {
            sensitivity,
            epsilon,
            lattice,
            rate,
            rng,
        })
    }

    fn build(sensitivity: f64, epsilon: f64, rng: SecureRng) -> Result<Self, DpError> {
        let (lattice, rate) = lattice_and_rate(sensitivity, epsilon)?;
        Ok(Self {
            sensitivity,
            epsilon,
            lattice,
            rate,
            rng,
        })
    }

    /// `x` rounded to the lattice plus `Λ · Z`, an exact multiple of the lattice
    ///
    /// # Errors
    ///
    /// [`DpError::ValueOutOfRange`] when `x` is not finite or `|x| / Λ`, or the
    /// noisy result over Λ, reaches 2^52.
    pub fn privatize(&mut self, x: f64) -> Result<f64, DpError> {
        let k = round_to_lattice(x, self.lattice)?;
        let z = discrete_laplace(self.rate, &mut self.rng);
        let total = i128::from(k) + z;
        if total.unsigned_abs() >= 1u128 << 52 {
            return Err(DpError::ValueOutOfRange);
        }
        #[allow(clippy::cast_precision_loss)]
        Ok(total as f64 * self.lattice) // exact: |total| < 2^52, lattice a power of two
    }

    /// The lattice `Λ = 2^(⌊log2 Δ⌋ − 20)` every output is a multiple of
    #[must_use]
    pub const fn lattice(&self) -> f64 {
        self.lattice
    }

    /// The ε the mechanism actually guarantees,
    /// `ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ` (at most `ε · (1 + 2^-20)`)
    #[must_use]
    pub fn effective_epsilon(&self) -> f64 {
        // ⌊Δ/Λ⌋ is exact: Δ/Λ is a power-of-two scaling of Δ
        let steps = (self.sensitivity / self.lattice) as u64 + 1;
        #[allow(clippy::cast_precision_loss)]
        let steps = steps as f64;
        self.epsilon * self.lattice * steps / self.sensitivity
    }

    /// The sensitivity Δ in use
    #[must_use]
    pub const fn sensitivity(&self) -> f64 {
        self.sensitivity
    }

    /// The ε requested
    #[must_use]
    pub const fn epsilon(&self) -> f64 {
        self.epsilon
    }
}

/// Differentially private count: `count + Z`, `Z` discrete Laplace with
/// `P(Z = z) = (1 − e^−ε) / (1 + e^−ε) · e^(−ε·|z|)`
///
/// Sensitivity 1 (one person entering or leaving changes the count by 1), so
/// the lattice is the integers themselves and there is no rounding loss: the
/// mechanism is (ε, δ)-differentially private with the δ of the module doc.
/// ε is converted exactly from its `f64` value to a rational and the noise is
/// sampled with integer arithmetic only (no floating-point `ln` or `exp`).
///
/// ⚠️ **An ε that is accepted and ignored is worse than no ε at all.** This
/// takes ε, not a scale, so the caller's ε and the noise cannot disagree.
///
/// # Errors
///
/// [`DpError::InvalidScale`] when `epsilon` is not finite and positive,
/// [`DpError::EpsilonOutOfRange`] when its exact rational does not fit the
/// sampler (roughly ε outside `[2^-43, 2^43]`), [`DpError::CountOutOfRange`]
/// when `true_count` or the noisy count does not fit an `i64`.
pub fn dp_count(true_count: u64, epsilon: f64, rng: &mut SecureRng) -> Result<i64, DpError> {
    let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    let rate = ratio_from_parts(m, 1, e).ok_or(DpError::EpsilonOutOfRange)?;
    let base = i64::try_from(true_count).map_err(|_| DpError::CountOutOfRange)?;
    let z = discrete_laplace(rate, rng);
    i64::try_from(i128::from(base) + z).map_err(|_| DpError::CountOutOfRange)
}

/// Differentially private sum of values with sensitivity Δ, on the lattice of
/// [`DpNoise`]: `round_Λ(true_sum) + Λ · Z`
///
/// # Errors
///
/// As [`DpNoise::try_with_key`] and [`DpNoise::privatize`].
pub fn dp_sum(
    true_sum: f64,
    sensitivity: f64,
    epsilon: f64,
    rng: &mut SecureRng,
) -> Result<f64, DpError> {
    let (lattice, rate) = lattice_and_rate(sensitivity, epsilon)?;
    let k = round_to_lattice(true_sum, lattice)?;
    let total = i128::from(k) + discrete_laplace(rate, rng);
    if total.unsigned_abs() >= 1u128 << 52 {
        return Err(DpError::ValueOutOfRange);
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(total as f64 * lattice)
}

/// Differentially private integer: `value + Z`, `Z` discrete Laplace with
/// decay `ε / Δ` per unit, `P(Z = z) = (1 − e^−ε/Δ) / (1 + e^−ε/Δ) ·
/// e^(−(ε/Δ)·|z|)`
///
/// For integer-valued queries whose sensitivity is a whole number `Δ`: the
/// lattice is the integers (`Λ = 1`), so nothing is rounded, and the output is
/// (ε, δ)-differentially private with the δ of the module doc. [`dp_count`]
/// is the case `Δ = 1` for a non-negative count. The noise is sampled with
/// integer arithmetic only and draws a number of keystream words fixed by ε
/// and Δ (`tests/dp_cost_model.rs`).
///
/// An overflowing `value + Z` is refused with [`DpError::CountOutOfRange`], not
/// clamped: a clamped output would reveal that the noise ran past the limit.
///
/// # Errors
///
/// [`DpError::InvalidScale`] when `sensitivity` is 0 or `epsilon` is not
/// finite and positive, [`DpError::EpsilonOutOfRange`] when `ε / Δ` does not
/// fit the sampler's exact rationals, [`DpError::CountOutOfRange`] when
/// `value + Z` does not fit an `i64`.
pub fn dp_int(
    value: i64,
    sensitivity: u64,
    epsilon: f64,
    rng: &mut SecureRng,
) -> Result<i64, DpError> {
    let rate = int_rate(sensitivity, epsilon)?;
    let z = discrete_laplace(rate, rng);
    i64::try_from(i128::from(value) + z).map_err(|_| DpError::CountOutOfRange)
}

/// The exact decay `ε / Δ` of [`dp_int`]: ε's `f64` value as a dyadic rational
/// over the integer Δ, nothing rounded
fn int_rate(sensitivity: u64, epsilon: f64) -> Result<Ratio, DpError> {
    if sensitivity == 0 {
        return Err(DpError::InvalidScale);
    }
    let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    ratio_from_parts(m, sensitivity, e).ok_or(DpError::EpsilonOutOfRange)
}

/// Randomized response: the true bit with probability `e^ε / (1 + e^ε)`, the
/// flipped bit otherwise, which is ε-differentially private for one bit (up to
/// the δ of `scripts/dp_rr_exact.py`)
///
/// ε is converted exactly from its `f64` value; the flip is drawn with the
/// integer Bernoulli steps of the discrete Laplace sampler, so no
/// floating-point `exp` decides it. The work and the keystream words drawn
/// depend only on ε, not on the bit or the outcome.
///
/// # Errors
///
/// [`DpError::InvalidScale`] when `epsilon` is not finite and positive,
/// [`DpError::EpsilonOutOfRange`] when its exact rational does not fit the
/// sampler or `⌊ε⌋ >` [`RR_MAX_EPSILON_WHOLE`].
pub fn randomized_response(bit: bool, epsilon: f64, rng: &mut SecureRng) -> Result<bool, DpError> {
    let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    let rate = ratio_from_parts(m, 1, e).ok_or(DpError::EpsilonOutOfRange)?;
    if exp_neg_whole_steps(rate) > u128::from(RR_MAX_EPSILON_WHOLE) {
        return Err(DpError::EpsilonOutOfRange);
    }
    let flip = rr_flip(rate, rng);
    Ok(u128::from(bit) ^ flip == 1)
}

/// `true` with probability exactly `num / den` (up to the `den / 2^256`
/// statistical distance of the uniform draw), with fixed work: one uniform
/// 256-bit draw (4 keystream words) compared against `num`
///
/// Takes the probability as an exact fraction, not an `f64`, so there is no
/// rounded entry point. Internally `num` and `den` are widened to 128 bits, so
/// no arithmetic overflows for any `u64` pair.
///
/// # Errors
///
/// [`DpError::InvalidProbability`] when `den == 0` or `num > den`.
pub fn bernoulli_ratio(num: u64, den: u64, rng: &mut SecureRng) -> Result<bool, DpError> {
    if den == 0 || num > den {
        return Err(DpError::InvalidProbability);
    }
    Ok(bernoulli_ct(u128::from(num), u128::from(den), rng) == 1)
}

#[cfg(test)]
mod int_rate_tests {
    use super::{int_rate, Ratio};

    /// ε = 0.1 is not an `f32` value; its `f64` value is exactly
    /// 0x1999999999999a · 2^-56 (from the IEEE 754 bits, independent of the
    /// code under test). The decay of `dp_int` with Δ = 3 must be exactly that
    /// over 3: an implementation rounding ε through `f32` gets a different
    /// numerator (the draws hardly ever show it, the rate always does)
    #[test]
    fn a_non_f32_epsilon_becomes_its_exact_rational() {
        let eps = 0.1_f64;
        assert_ne!(f64::from(eps as f32), eps);
        assert_eq!(eps.to_bits(), 0x3fb9_9999_9999_999a);
        // 0x1999999999999a has one trailing zero: odd mantissa 0xccccccccccccd
        // and exponent −55
        let want = Ratio {
            num: 0xc_cccc_cccc_cccd,
            den: 3 << 55,
        };
        assert_eq!(int_rate(3, eps), Ok(want));
        assert_ne!(int_rate(3, f64::from(eps as f32)), Ok(want));
    }
}

#[cfg(test)]
impl SecureRng {
    /// A generator positioned at keystream block `block` (the boundary tests
    /// cannot draw 256 GiB to get there)
    fn at_block(key: [u8; 32], block: u64) -> Self {
        let mut rng = Self {
            key,
            block,
            buf: [0u8; 64 * BUF_BLOCKS],
            len: 0,
            pos: 0,
            words: 0,
        };
        rng.refill();
        rng
    }
}

#[cfg(test)]
mod keystream_boundary_tests {
    use super::{SecureRng, LAST_COUNTER};
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::ChaCha20;

    const KEY: [u8; 32] = [7; 32];

    /// The RFC 8439 block with `counter` under nonce stream `stream`, from the
    /// cipher directly (one block, no buffering, no generator logic)
    fn block(stream: u32, counter: u32) -> [u8; 64] {
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&stream.to_le_bytes());
        let mut c = ChaCha20::new(&KEY.into(), &nonce.into());
        c.seek(u64::from(counter) * 64);
        let mut out = [0u8; 64];
        c.apply_keystream(&mut out);
        out
    }

    fn words(b: &[u8; 64]) -> Vec<u64> {
        (0..8)
            .map(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn the_crate_refuses_the_block_at_counter_two_to_the_32_minus_one() {
        // why the generator stops one block early: this is the panic 0.3.0 hit
        let mut c = ChaCha20::new(&KEY.into(), &[0u8; 12].into());
        c.seek(u64::from(u32::MAX) * 64);
        let mut out = [0u8; 64];
        assert!(c.try_apply_keystream(&mut out).is_err());
        // and the block before it is fine
        let mut c = ChaCha20::new(&KEY.into(), &[0u8; 12].into());
        c.seek(u64::from(LAST_COUNTER) * 64);
        assert!(c.try_apply_keystream(&mut out).is_ok());
    }

    #[test]
    fn the_stream_crosses_the_last_counter_into_the_next_nonce_without_panicking() {
        // start 2 blocks before the end of stream 0: words come from counters
        // 2^32 − 3, 2^32 − 2, then counter 0 of stream 1, then counter 1
        let mut rng = SecureRng::at_block(KEY, u64::from(LAST_COUNTER) - 1);
        let mut want = Vec::new();
        for (s, c) in [(0, LAST_COUNTER - 1), (0, LAST_COUNTER), (1, 0), (1, 1)] {
            want.extend(words(&block(s, c)));
        }
        let got: Vec<u64> = (0..want.len()).map(|_| rng.next_u64()).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_boundary_is_crossed_the_same_way_from_any_buffer_alignment() {
        // a refill that would have reached counter 2^32 − 1 is cut there,
        // whatever block the buffer started on
        for back in 1..=70u64 {
            let mut rng = SecureRng::at_block(KEY, u64::from(LAST_COUNTER) + 1 - back);
            for _ in 0..back * 8 {
                let _ = rng.next_u64();
            }
            assert_eq!(rng.next_u64(), words(&block(1, 0))[0], "back = {back}");
        }
    }

    #[test]
    fn the_first_words_after_the_boundary_are_pinned() {
        // golden: the first two words of stream 1 under key [7; 32]; the value
        // was also computed with an independent pure-Python RFC 8439 block
        // function (checked against RFC 8439 §2.3.2 first). A change means the
        // keystream definition changed
        let w = words(&block(1, 0));
        let mut rng = SecureRng::at_block(KEY, u64::from(LAST_COUNTER) + 1);
        assert_eq!([rng.next_u64(), rng.next_u64()], [w[0], w[1]]);
        assert_eq!(format!("{:016x} {:016x}", w[0], w[1]), BOUNDARY_GOLDEN);
    }

    const BOUNDARY_GOLDEN: &str = "ef65ba9909737c6d a5f18c19346a3cdf";
}

#[cfg(test)]
mod sampler_tests {
    use super::{div_floor, lemire_top, uniform_below, SecureRng};

    /// `⌊(r1·2^128 + r0) · n / 2^256⌋` by schoolbook multiplication on 64-bit
    /// limbs, written independently of `mul_wide`
    fn reference(r1: u128, r0: u128, n: u128) -> u128 {
        let r = [r0 as u64, (r0 >> 64) as u64, r1 as u64, (r1 >> 64) as u64];
        let m = [n as u64, (n >> 64) as u64];
        let mut acc = [0u64; 6];
        for (i, &ri) in r.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &mj) in m.iter().enumerate() {
                let t = u128::from(acc[i + j]) + u128::from(ri) * u128::from(mj) + carry;
                acc[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + m.len();
            while carry != 0 {
                let t = u128::from(acc[k]) + carry;
                acc[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        u128::from(acc[4]) | (u128::from(acc[5]) << 64)
    }

    /// The uniform draw is the top 128 bits of a full 256-bit draw times `n`.
    /// Using only one 128-bit word would still be uniform but off by up to
    /// `n / 2^128` (≈ 2^-27 for the largest `n` here) instead of `n / 2^256`,
    /// which the δ budget of the module doc does not allow; the distribution
    /// tests cannot see a bias that small, so this compares exactly.
    #[test]
    fn the_uniform_draw_is_the_top_half_of_a_full_256_bit_product() {
        for n in [
            1u128,
            3,
            1_000_003,
            (1u128 << 96) - 7,
            (1u128 << 101) + 12_345,
        ] {
            let mut rng = SecureRng::from_key([42u8; 32]);
            let mut words = rng.clone();
            for _ in 0..64 {
                let r1 = (u128::from(words.next_u64()) << 64) | u128::from(words.next_u64());
                let r0 = (u128::from(words.next_u64()) << 64) | u128::from(words.next_u64());
                let got = uniform_below(n, &mut rng);
                assert_eq!(got, reference(r1, r0, n), "n = {n}");
                assert!(got < n, "n = {n}: {got} out of range");
            }
        }
    }

    /// A draw whose two partial products carry into bit 256: `r1 · n ≡ −1
    /// (mod 2^128)` for odd `n`, so the low half of `r1 · n` is all ones.
    /// Vector computed with Python integers.
    #[test]
    fn the_carry_between_the_partial_products_is_kept() {
        let n = (1u128 << 101) + 12_345;
        let r1 = 98_259_569_061_750_236_662_618_709_415_131_038_199u128;
        let r0 = u128::MAX;
        assert_eq!(
            lemire_top(r1, r0, n),
            732_090_838_713_573_192_526_539_488_834
        );
        assert_eq!(lemire_top(r1, r0, n), reference(r1, r0, n));
    }

    /// Quotients where the reciprocal estimate is one below (found with
    /// Python integers), and agreement with `/` on boundaries and random input
    #[test]
    fn the_division_is_exact_including_when_the_estimate_is_one_low() {
        let cases = [
            (20_276_454_186_610_201_359_376_473_754_995u128, 3u128),
            (14_218_366_236_952_146_301_957_537_187_610, 7),
        ];
        for (n, d) in cases {
            assert_eq!(div_floor(n, d), n / d, "n = {n}, d = {d}");
        }
        let mut rng = SecureRng::from_key([5u8; 32]);
        for d in [
            1u128,
            2,
            3,
            7,
            1_000_003,
            3_602_879_701_896_397,
            (1 << 64) - 59,
            (1 << 96) - 7,
        ] {
            for n in [0u128, 1, d - 1, d, d + 1, (1 << 104) - 1, (1 << 104) - d] {
                assert_eq!(div_floor(n, d), n / d, "n = {n}, d = {d}");
            }
            for _ in 0..2_000 {
                let n = ((u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())) >> 24;
                assert_eq!(div_floor(n, d), n / d, "n = {n}, d = {d}");
            }
        }
    }
}
