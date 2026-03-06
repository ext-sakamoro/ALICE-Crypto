//! BLAKE3-MAC 認証署名
//!
//! 対称鍵ベースのメッセージ認証コード (MAC) を署名として使用。
//! BLAKE3 の keyed hash を利用し、定数時間比較で検証。
//!
//! **注意**: これは対称認証であり、公開鍵署名 (Ed25519等) ではない。
//! 否認防止 (non-repudiation) には公開鍵署名が必要。

use crate::hash;

/// 署名サイズ (バイト)。
pub const SIGNATURE_SIZE: usize = 32;

/// 署名鍵 (32 バイト)。
#[derive(Clone)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// バイト配列から生成。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// ランダム生成。
    ///
    /// # Errors
    ///
    /// OS RNG が利用不可の場合。
    pub fn generate() -> Result<Self, SignatureError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| SignatureError::RngFailed)?;
        Ok(Self(bytes))
    }

    /// バイト列参照。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 対応する検証鍵を取得。
    #[must_use]
    pub const fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// 検証鍵 (対称MACなので署名鍵と同一)。
#[derive(Clone)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// バイト配列から生成。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// バイト列参照。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for VerifyingKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// 署名値 (32 バイト BLAKE3-MAC)。
#[derive(Clone, PartialEq, Eq)]
pub struct Signature([u8; 32]);

impl Signature {
    /// バイト配列から生成。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// バイト列参照。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// バイトスライスからパース。
    ///
    /// # Errors
    ///
    /// 長さが 32 でない場合。
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidSignatureLength)?;
        Ok(Self(arr))
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({:02x}{:02x}...)", self.0[0], self.0[1])
    }
}

/// メッセージに署名。
#[must_use]
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    let h = hash::keyed_hash(&key.0, message);
    Signature(*h.as_bytes())
}

/// コンテキスト付き署名。
///
/// `context || message` を署名対象とし、ドメイン分離を実現。
#[must_use]
pub fn sign_with_context(key: &SigningKey, context: &[u8], message: &[u8]) -> Signature {
    let mut input = alloc::vec::Vec::with_capacity(context.len() + message.len());
    input.extend_from_slice(context);
    input.extend_from_slice(message);
    sign(key, &input)
}

/// 署名を検証 (定数時間比較)。
#[must_use]
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    let expected = hash::keyed_hash(&key.0, message);
    constant_time_eq(expected.as_bytes(), &signature.0)
}

/// コンテキスト付き署名を検証。
#[must_use]
pub fn verify_with_context(
    key: &VerifyingKey,
    context: &[u8],
    message: &[u8],
    signature: &Signature,
) -> bool {
    let mut input = alloc::vec::Vec::with_capacity(context.len() + message.len());
    input.extend_from_slice(context);
    input.extend_from_slice(message);
    verify(key, &input, signature)
}

/// 定数時間バイト比較。
///
/// タイミング攻撃を防ぐため、全バイトを比較してから結果を返す。
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// エラー型
// ============================================================================

/// 署名エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// 署名長が不正。
    InvalidSignatureLength,
    /// 署名検証失敗。
    VerificationFailed,
    /// RNG 失敗。
    RngFailed,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSignatureLength => write!(f, "Invalid signature length"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::RngFailed => write!(f, "Random number generation failed"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate().unwrap();
        let msg = b"hello ALICE";
        let sig = sign(&key, msg);
        assert!(verify(&key.verifying_key(), msg, &sig));
    }

    #[test]
    fn verify_fails_wrong_message() {
        let key = SigningKey::generate().unwrap();
        let sig = sign(&key, b"message A");
        assert!(!verify(&key.verifying_key(), b"message B", &sig));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let key1 = SigningKey::generate().unwrap();
        let key2 = SigningKey::generate().unwrap();
        let sig = sign(&key1, b"msg");
        assert!(!verify(&key2.verifying_key(), b"msg", &sig));
    }

    #[test]
    fn sign_deterministic() {
        let key = SigningKey::from_bytes([42u8; 32]);
        let sig1 = sign(&key, b"data");
        let sig2 = sign(&key, b"data");
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn sign_with_context_roundtrip() {
        let key = SigningKey::generate().unwrap();
        let sig = sign_with_context(&key, b"alice-codec", b"frame data");
        assert!(verify_with_context(
            &key.verifying_key(),
            b"alice-codec",
            b"frame data",
            &sig
        ));
    }

    #[test]
    fn context_changes_signature() {
        let key = SigningKey::from_bytes([1u8; 32]);
        let sig1 = sign_with_context(&key, b"ctx1", b"msg");
        let sig2 = sign_with_context(&key, b"ctx2", b"msg");
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn wrong_context_fails() {
        let key = SigningKey::generate().unwrap();
        let sig = sign_with_context(&key, b"correct", b"msg");
        assert!(!verify_with_context(
            &key.verifying_key(),
            b"wrong",
            b"msg",
            &sig
        ));
    }

    #[test]
    fn signature_from_slice() {
        let sig = Signature::from_bytes([0xAB; 32]);
        let parsed = Signature::from_slice(sig.as_bytes()).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn signature_from_slice_wrong_length() {
        assert!(Signature::from_slice(&[0u8; 16]).is_err());
    }

    #[test]
    fn signature_debug() {
        let sig = Signature::from_bytes([0xAB; 32]);
        let dbg = format!("{sig:?}");
        assert!(dbg.contains("Signature"));
        assert!(dbg.contains("ab"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn error_display() {
        assert!(SignatureError::InvalidSignatureLength
            .to_string()
            .contains("length"));
        assert!(SignatureError::VerificationFailed
            .to_string()
            .contains("verification"));
        assert!(SignatureError::RngFailed.to_string().contains("Random"));
    }
}
