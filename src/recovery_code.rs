//! Recovery code: a secret that a person writes down, and a secret sealed under it.
//!
//! A recovery code is 128 random bits that no person chose, written as 28 characters of base32 with two check
//! characters, so a mistyped character or two swapped neighbours are caught before anything is opened. A secret sealed under the code opens only
//! with that code and the same associated data.
//!
//! # Code
//!
//! ```text
//! data   = entropy (128 bits) || 00, cut into 26 symbols of 5 bits (most significant first)
//! c0     = v_0 + v_1 + … + v_25                    in GF(32) = GF(2)[x] / (x⁵ + x² + 1)
//! c1     = α¹·v_0 + α²·v_1 + … + α²⁶·v_25           (α = x)
//! text   = the 26 data symbols, then c0, then c1, as characters of 0123456789ABCDEFGHJKMNPQRSTVWXYZ,
//!          shown in 7 groups of 4 joined by `-`
//! ```
//!
//! Any one changed character is caught for certain: a changed data symbol changes `c0` (addition in GF(32) is
//! XOR), and a changed check symbol no longer matches. Two different neighbouring data symbols swapped are caught
//! too: `c0` is unchanged but `c1` changes by `(αⁱ + αⁱ⁺¹)(a + b) ≠ 0` (α has order 31 > 26, so the weights are
//! distinct). Reading ([`RecoveryCode::parse`]) ignores case, `-` and spaces, and reads `O` as `0` and `I` / `L` as
//! `1`; the two padding bits must be zero and both checks must match.
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

extern crate alloc;
use alloc::{string::String, vec::Vec};
use zeroize::Zeroizing;

/// Characters of a recovery code.
pub const RECOVERY_CODE_LEN: usize = 28;

/// Random bytes in a recovery code.
pub const RECOVERY_CODE_ENTROPY: usize = 16;

/// The version byte of a sealed secret.
pub const RECOVERY_BLOB_VERSION: u8 = 1;

/// Bytes a sealed secret adds to the secret: version, salt, nonce and tag.
pub const RECOVERY_BLOB_OVERHEAD: usize = 1 + 16 + 24 + 16;

/// The HKDF info of the key a code seals with.
pub const RECOVERY_CODE_KEY_INFO: &[u8] = b"alice-crypto recovery-code v1 key";

/// The code alphabet: Crockford base32 (no I, L, O, U).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Bytes before the sealed part: version and salt.
const HEADER: usize = 1 + 16;

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

impl core::fmt::Display for RecoveryCodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length => write!(f, "a recovery code has {RECOVERY_CODE_LEN} characters"),
            Self::Character { position } => {
                write!(
                    f,
                    "character {position} of the recovery code is not in its alphabet"
                )
            }
            Self::Check => {
                f.write_str("the recovery code check does not match (a mistyped character)")
            }
            Self::EmptySecret => f.write_str("the secret to seal is empty"),
            Self::Malformed => f.write_str("not a sealed secret"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported sealed secret version {v}"),
            Self::Open => {
                f.write_str("the recovery code or the associated data does not open this secret")
            }
            Self::RandomFailed => {
                f.write_str("the operating system's random source is unavailable")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoveryCodeError {}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

/// Data symbols in a code (128 bits and 2 padding bits).
const DATA_SYMBOLS: usize = 26;

/// Product in GF(32) = GF(2)[x] / (x⁵ + x² + 1)
fn gf32_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0b10_0000 != 0 {
            a ^= 0b10_0101;
        }
    }
    p
}

/// The two check symbols of the data symbols: their sum, and their sum weighted by α¹, α², …
fn check_symbols(data: &[u8; DATA_SYMBOLS]) -> [u8; 2] {
    let (mut c0, mut c1, mut w) = (0u8, 0u8, 1u8);
    for &v in data {
        w = gf32_mul(w, 2);
        c0 ^= v;
        c1 ^= gf32_mul(w, v);
    }
    [c0, c1]
}

/// The 26 data symbols of `entropy` (and two zero padding bits)
fn data_symbols(entropy: &[u8; RECOVERY_CODE_ENTROPY]) -> Zeroizing<[u8; DATA_SYMBOLS]> {
    let mut d = Zeroizing::new([0u8; DATA_SYMBOLS]);
    for bit in 0..128 {
        let b = entropy[bit / 8] >> (7 - bit % 8) & 1;
        d[bit / 5] |= b << (4 - bit % 5);
    }
    d
}

/// The key `entropy` seals with under `salt`
fn derive_key(entropy: &[u8; RECOVERY_CODE_ENTROPY], salt: &[u8]) -> crate::stream::Key {
    let mut prk = crate::sha256::hkdf_extract(salt, entropy);
    let mut key = crate::stream::Key([0u8; 32]);
    crate::sha256::hkdf_expand(&prk, RECOVERY_CODE_KEY_INFO, &mut key.0)
        .expect("32 bytes is within HKDF-SHA256's output");
    zeroize::Zeroize::zeroize(&mut prk);
    key
}

impl RecoveryCode {
    /// A new code from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`RecoveryCodeError::RandomFailed`] when the random source is unavailable.
    #[cfg(feature = "rng")]
    #[expect(
        clippy::disallowed_methods,
        reason = "secret material generation, not Law output: a recovery code must be unpredictable"
    )]
    pub fn generate() -> Result<Self, RecoveryCodeError> {
        let mut e = Zeroizing::new([0u8; RECOVERY_CODE_ENTROPY]);
        getrandom::getrandom(e.as_mut()).map_err(|_| RecoveryCodeError::RandomFailed)?;
        Ok(Self { entropy: e })
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
    /// [`RecoveryCodeError::Character`] for a character outside the alphabet, [`RecoveryCodeError::Length`] for
    /// other than 28 code characters, [`RecoveryCodeError::Check`] for a set padding bit or a check that does not
    /// match.
    pub fn parse(text: &str) -> Result<Self, RecoveryCodeError> {
        let mut values = Zeroizing::new([0u8; RECOVERY_CODE_LEN]);
        let mut n = 0usize;
        for c in text.chars().filter(|&c| c != '-' && c != ' ') {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let v = u8::try_from(c)
                .ok()
                .and_then(|b| ALPHABET.iter().position(|&a| a == b))
                .ok_or(RecoveryCodeError::Character { position: n })?;
            if n < RECOVERY_CODE_LEN {
                values[n] = v as u8;
            }
            n += 1;
        }
        if n != RECOVERY_CODE_LEN {
            return Err(RecoveryCodeError::Length);
        }
        let mut data = Zeroizing::new([0u8; DATA_SYMBOLS]);
        data.copy_from_slice(&values[..DATA_SYMBOLS]);
        // the two padding bits are the low bits of the last data symbol
        if data[DATA_SYMBOLS - 1] & 0b11 != 0 || check_symbols(&data)[..] != values[DATA_SYMBOLS..]
        {
            return Err(RecoveryCodeError::Check);
        }
        let mut entropy = Zeroizing::new([0u8; RECOVERY_CODE_ENTROPY]);
        for bit in 0..128 {
            let b = data[bit / 5] >> (4 - bit % 5) & 1;
            entropy[bit / 8] |= b << (7 - bit % 8);
        }
        Ok(Self { entropy })
    }

    /// The code as a person writes it down: 7 groups of 4 characters joined by `-`.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let data = data_symbols(&self.entropy);
        let check = check_symbols(&data);
        let mut out = Zeroizing::new(String::with_capacity(RECOVERY_CODE_LEN + 6));
        for (i, &v) in data.iter().chain(check.iter()).enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[usize::from(v)] as char);
        }
        out
    }
}

/// Seal `secret` under `code`, bound to `aad`.
///
/// # Errors
///
/// [`RecoveryCodeError::EmptySecret`] or [`RecoveryCodeError::RandomFailed`].
#[cfg(feature = "rng")]
#[expect(
    clippy::disallowed_methods,
    reason = "secret material generation, not Law output: the salt must be unpredictable"
)]
pub fn seal_secret(
    code: &RecoveryCode,
    secret: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RecoveryCodeError> {
    if secret.is_empty() {
        return Err(RecoveryCodeError::EmptySecret);
    }
    let mut header = [0u8; HEADER];
    header[0] = RECOVERY_BLOB_VERSION;
    getrandom::getrandom(&mut header[1..]).map_err(|_| RecoveryCodeError::RandomFailed)?;
    let key = derive_key(&code.entropy, &header[1..]);
    let mut ad = Vec::with_capacity(HEADER + aad.len());
    ad.extend_from_slice(&header);
    ad.extend_from_slice(aad);
    let sealed = crate::stream::seal_with_aad(&key, &ad, secret)
        .map_err(|_| RecoveryCodeError::RandomFailed)?;
    let mut out = Vec::with_capacity(HEADER + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a secret sealed by [`seal_secret`] with the same code and associated data.
///
/// # Errors
///
/// [`RecoveryCodeError::Malformed`] for bytes shorter than a sealed secret of one byte,
/// [`RecoveryCodeError::UnsupportedVersion`], or [`RecoveryCodeError::Open`] when the code, the associated data or
/// the bytes are not the sealed ones.
pub fn open_secret(
    code: &RecoveryCode,
    blob: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RecoveryCodeError> {
    if blob.len() <= RECOVERY_BLOB_OVERHEAD {
        return Err(RecoveryCodeError::Malformed);
    }
    if blob[0] != RECOVERY_BLOB_VERSION {
        return Err(RecoveryCodeError::UnsupportedVersion(blob[0]));
    }
    let key = derive_key(&code.entropy, &blob[1..HEADER]);
    let mut ad = Vec::with_capacity(HEADER + aad.len());
    ad.extend_from_slice(&blob[..HEADER]);
    ad.extend_from_slice(aad);
    crate::stream::open_with_aad(&key, &ad, &blob[HEADER..])
        .map(Zeroizing::new)
        .map_err(|_| RecoveryCodeError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The module's own multiplication: α = 2 has order 31 (primitive), the 26 data weights α¹ … α²⁶ and the 28
    /// position weights are distinct, and the product is commutative with 1 as identity over all 32 × 32 pairs
    #[test]
    fn the_field_of_the_check_is_gf32_with_a_primitive_alpha() {
        let mut w = 1u8;
        let mut seen = Vec::new();
        for n in 1..=31 {
            w = gf32_mul(w, 2);
            if n <= 28 {
                seen.push(w);
            }
            assert_eq!(w == 1, n == 31, "alpha^{n}");
        }
        let mut s = seen.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), 28);
        for a in 0..32u8 {
            assert_eq!(gf32_mul(a, 1), a);
            for b in 0..32u8 {
                assert_eq!(gf32_mul(a, b), gf32_mul(b, a));
                assert!(gf32_mul(a, b) < 32);
            }
        }
    }
}
