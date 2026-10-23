//! HPKE base mode (RFC 9180) for one cipher suite: KEM `DHKEM(X25519, HKDF-SHA256)` (0x0020), KDF `HKDF-SHA256`
//! (0x0001), AEAD `AES-128-GCM` (0x0001).
//!
//! This is the HPKE of the MLS cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420): it
//! encrypts the path secrets of a commit and the group secrets of a welcome to a member's public key.
//!
//! - [`derive_key_pair`] is the KEM's `DeriveKeyPair` (section 7.1.3).
//! - [`setup_base_sender`] encapsulates to a recipient's public key with a fresh ephemeral key and returns the
//!   encapsulated key `enc` and a sending [`Context`]; [`setup_base_sender_with_ephemeral`] takes the ephemeral
//!   private key instead (for test vectors and for deterministic protocols that derive it).
//! - [`setup_base_receiver`] decapsulates `enc` with the recipient's private key and returns a receiving
//!   [`Context`].
//! - [`Context::seal`] / [`Context::open`] encrypt and decrypt message `n` with nonce `base_nonce XOR n`
//!   (section 5.2), so messages must be opened in the order they were sealed; [`Context::export`] is the secret
//!   export interface (section 5.3).
//!
//! Only the key schedule and the context are written here; the primitives are [`crate::sha256`],
//! [`crate::x25519`] and [`crate::aes_gcm`]. A Diffie-Hellman result of all zero (a recipient key of small order)
//! aborts the setup (section 7.1.4).

use crate::{aes_gcm, sha256, x25519};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

/// The size of an encapsulated key (an X25519 public key), in bytes.
pub const ENC_SIZE: usize = 32;
/// The longest secret [`Context::export`] returns: 255 HKDF-SHA256 blocks.
pub const EXPORT_MAX: usize = sha256::HKDF_MAX_OUTPUT;

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;
const MODE_BASE: u8 = 0x00;
const VERSION_LABEL: &[u8] = b"HPKE-v1";

/// `"KEM" || I2OSP(kem_id, 2)` (section 4.1)
const KEM_SUITE: [u8; 5] = [b'K', b'E', b'M', (KEM_ID >> 8) as u8, KEM_ID as u8];
/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)` (section 5.1)
const HPKE_SUITE: [u8; 10] = [
    b'H',
    b'P',
    b'K',
    b'E',
    (KEM_ID >> 8) as u8,
    KEM_ID as u8,
    (KDF_ID >> 8) as u8,
    KDF_ID as u8,
    (AEAD_ID >> 8) as u8,
    AEAD_ID as u8,
];

/// `LabeledExtract(salt, label, ikm)` = `Extract(salt, "HPKE-v1" || suite_id || label || ikm)` (section 4)
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(
        VERSION_LABEL.len() + suite.len() + label.len() + ikm.len(),
    ));
    input.extend_from_slice(VERSION_LABEL);
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    sha256::hkdf_extract(salt, &input)
}

/// `LabeledExpand(prk, label, info, L)` = `Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`
fn labeled_expand(
    suite: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    if out.len() > EXPORT_MAX {
        return Err(HpkeError::ExportTooLong(out.len()));
    }
    let len = out.len() as u16; // <= 8160, fits I2OSP(L, 2)
    let mut full =
        Vec::with_capacity(2 + VERSION_LABEL.len() + suite.len() + label.len() + info.len());
    full.extend_from_slice(&len.to_be_bytes());
    full.extend_from_slice(VERSION_LABEL);
    full.extend_from_slice(suite);
    full.extend_from_slice(label);
    full.extend_from_slice(info);
    sha256::hkdf_expand(prk, &full, out).map_err(|_| HpkeError::ExportTooLong(out.len()))
}

/// The KEM's `DeriveKeyPair(ikm)` (section 7.1.3): (private key, public key).
///
/// Use at least 32 bytes of uniformly random `ikm`; the same `ikm` always gives the same pair.
#[must_use]
pub fn derive_key_pair(ikm: &[u8]) -> ([u8; x25519::KEY_SIZE], [u8; x25519::KEY_SIZE]) {
    let mut dkp_prk = labeled_extract(&KEM_SUITE, b"", b"dkp_prk", ikm);
    let mut sk = [0u8; x25519::KEY_SIZE];
    labeled_expand(&KEM_SUITE, &dkp_prk, b"sk", b"", &mut sk)
        .expect("32 bytes is within the HKDF limit");
    dkp_prk.zeroize();
    let pk = x25519::public_key(&sk);
    (sk, pk)
}

/// The KEM's `ExtractAndExpand(dh, kem_context)` (section 4.1): the 32-byte shared secret.
fn extract_and_expand(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r);
    let mut eae_prk = labeled_extract(&KEM_SUITE, b"", b"eae_prk", dh);
    let mut shared = Zeroizing::new([0u8; 32]);
    labeled_expand(
        &KEM_SUITE,
        &eae_prk,
        b"shared_secret",
        &kem_context,
        &mut *shared,
    )
    .expect("32 bytes is within the HKDF limit");
    eae_prk.zeroize();
    shared
}

/// `KeySchedule(mode_base, shared_secret, info, "", "")` (section 5.1).
fn key_schedule(shared: &[u8; 32], info: &[u8]) -> Context {
    let psk_id_hash = labeled_extract(&HPKE_SUITE, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&HPKE_SUITE, b"", b"info_hash", info);
    let mut ctx = [0u8; 65];
    ctx[0] = MODE_BASE;
    ctx[1..33].copy_from_slice(&psk_id_hash);
    ctx[33..].copy_from_slice(&info_hash);
    let mut secret = labeled_extract(&HPKE_SUITE, shared, b"secret", b"");
    let mut out = Context {
        key: [0u8; aes_gcm::KEY_SIZE],
        base_nonce: [0u8; aes_gcm::NONCE_SIZE],
        exporter_secret: [0u8; 32],
        seq: 0,
    };
    let fixed = "fixed sizes are within the HKDF limit";
    labeled_expand(&HPKE_SUITE, &secret, b"key", &ctx, &mut out.key).expect(fixed);
    labeled_expand(
        &HPKE_SUITE,
        &secret,
        b"base_nonce",
        &ctx,
        &mut out.base_nonce,
    )
    .expect(fixed);
    labeled_expand(&HPKE_SUITE, &secret, b"exp", &ctx, &mut out.exporter_secret).expect(fixed);
    secret.zeroize();
    out
}

/// Base-mode setup for a sender with a fresh random ephemeral key: (`enc`, sending context).
///
/// # Errors
///
/// [`HpkeError::SmallOrderKey`] when `pk_r` has small order; [`HpkeError::RngFailed`] when the operating
/// system's random source is unavailable.
pub fn setup_base_sender(
    pk_r: &[u8; x25519::KEY_SIZE],
    info: &[u8],
) -> Result<([u8; ENC_SIZE], Context), HpkeError> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    crate::random::fill(&mut *ikm).map_err(|_| HpkeError::RngFailed)?;
    let (mut sk_e, _) = derive_key_pair(&*ikm);
    let out = setup_base_sender_with_ephemeral(pk_r, info, &sk_e);
    sk_e.zeroize();
    out
}

/// Base-mode setup for a sender with the given ephemeral private key `sk_e`: (`enc`, sending context).
///
/// A protocol must use each ephemeral key once; [`setup_base_sender`] makes a fresh one.
///
/// # Errors
///
/// [`HpkeError::SmallOrderKey`] when `pk_r` has small order.
pub fn setup_base_sender_with_ephemeral(
    pk_r: &[u8; x25519::KEY_SIZE],
    info: &[u8],
    sk_e: &[u8; x25519::KEY_SIZE],
) -> Result<([u8; ENC_SIZE], Context), HpkeError> {
    let mut dh = x25519::diffie_hellman(sk_e, pk_r).map_err(|_| HpkeError::SmallOrderKey)?;
    let enc = x25519::public_key(sk_e);
    let shared = extract_and_expand(&dh, &enc, pk_r);
    dh.zeroize();
    Ok((enc, key_schedule(&shared, info)))
}

/// Base-mode setup for the recipient of `enc`, with the recipient's private key `sk_r`.
///
/// # Errors
///
/// [`HpkeError::SmallOrderKey`] when `enc` has small order.
pub fn setup_base_receiver(
    enc: &[u8; ENC_SIZE],
    sk_r: &[u8; x25519::KEY_SIZE],
    info: &[u8],
) -> Result<Context, HpkeError> {
    let mut dh = x25519::diffie_hellman(sk_r, enc).map_err(|_| HpkeError::SmallOrderKey)?;
    let pk_r = x25519::public_key(sk_r);
    let shared = extract_and_expand(&dh, enc, &pk_r);
    dh.zeroize();
    Ok(key_schedule(&shared, info))
}

/// An HPKE encryption context (section 5.2): the AEAD key, the base nonce, the exporter secret and the sequence
/// number of the next message. Secrets are zeroed on drop; `Debug` does not show them.
pub struct Context {
    key: [u8; aes_gcm::KEY_SIZE],
    base_nonce: [u8; aes_gcm::NONCE_SIZE],
    exporter_secret: [u8; 32],
    seq: u64,
}

impl Context {
    /// `base_nonce XOR I2OSP(seq, 12)` (section 5.2)
    fn nonce(&self) -> [u8; aes_gcm::NONCE_SIZE] {
        let mut n = self.base_nonce;
        for (b, s) in n[aes_gcm::NONCE_SIZE - 8..]
            .iter_mut()
            .zip(self.seq.to_be_bytes())
        {
            *b ^= s;
        }
        n
    }

    /// Encrypts the next message: AES-128-GCM of `plaintext` with `aad`, then advances the sequence number.
    ///
    /// # Errors
    ///
    /// [`HpkeError::MessageLimit`] when the sequence number is exhausted (nothing is encrypted).
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let next = self.seq.checked_add(1).ok_or(HpkeError::MessageLimit)?;
        let ct = aes_gcm::seal(&self.key, &self.nonce(), aad, plaintext);
        self.seq = next;
        Ok(ct)
    }

    /// Decrypts the next message; the sequence number advances only when it opens.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Open`] when the ciphertext does not authenticate with this message's nonce (a changed
    /// ciphertext or `aad`, another context, or a message out of order); [`HpkeError::MessageLimit`] when the
    /// sequence number is exhausted.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let next = self.seq.checked_add(1).ok_or(HpkeError::MessageLimit)?;
        let pt = aes_gcm::open(&self.key, &self.nonce(), aad, ciphertext)
            .map_err(|_| HpkeError::Open)?;
        self.seq = next;
        Ok(pt)
    }

    /// `Export(exporter_context, L)` (section 5.3): `len` bytes of secret bound to this context.
    ///
    /// # Errors
    ///
    /// [`HpkeError::ExportTooLong`] when `len` is more than [`EXPORT_MAX`].
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, HpkeError> {
        // before the allocation: a huge `len` must be an error, not an allocation failure
        if len > EXPORT_MAX {
            return Err(HpkeError::ExportTooLong(len));
        }
        let mut out = alloc::vec![0u8; len];
        labeled_expand(
            &HPKE_SUITE,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            &mut out,
        )?;
        Ok(out)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
    }
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// Why an HPKE setup or operation failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeError {
    /// The peer's key (the recipient's public key, or `enc`) has small order: the Diffie-Hellman result is zero.
    SmallOrderKey,
    /// A ciphertext did not authenticate.
    Open,
    /// The context's sequence number is exhausted.
    MessageLimit,
    /// An export longer than [`EXPORT_MAX`] was requested (its length).
    ExportTooLong(usize),
    /// The operating system's random source is unavailable.
    RngFailed,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SmallOrderKey => f.write_str("HPKE peer key has small order"),
            Self::Open => f.write_str("HPKE ciphertext did not authenticate"),
            Self::MessageLimit => f.write_str("HPKE context sequence number exhausted"),
            Self::ExportTooLong(n) => {
                write!(f, "HPKE export of {n} bytes is longer than {EXPORT_MAX}")
            }
            Self::RngFailed => f.write_str("random number generation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}
