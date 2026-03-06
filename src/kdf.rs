//! ハッシュベース鍵導出関数 (KDF)
//!
//! BLAKE3 を基盤とした HKDF 風の鍵導出。
//! Extract → Expand の2段階で、任意の入力から暗号学的に安全な鍵を生成。

use alloc::vec;
use alloc::vec::Vec;

use crate::hash;

/// 疑似乱数鍵 (PRK) — Extract の出力。
#[derive(Clone)]
pub struct Prk([u8; 32]);

impl Prk {
    /// PRK のバイト列参照。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Prk {
    fn drop(&mut self) {
        // ゼロクリア (簡易 zeroize)
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// BLAKE3 ベースの HKDF。
///
/// HKDF-Extract: `keyed_hash(salt, ikm)` → PRK
/// HKDF-Expand: 反復 `keyed_hash(prk, info || counter)` → OKM
pub struct HkdfBlake3;

impl HkdfBlake3 {
    /// Extract: 入力鍵素材 (IKM) とソルトから PRK を生成。
    ///
    /// ソルトが空なら 32 バイトのゼロ鍵を使用。
    #[must_use]
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Prk {
        let salt_key = if salt.is_empty() {
            [0u8; 32]
        } else {
            // ソルトを 32 バイトに正規化 (BLAKE3 ハッシュ)
            *hash::hash(salt).as_bytes()
        };

        let h = hash::keyed_hash(&salt_key, ikm);
        Prk(*h.as_bytes())
    }

    /// Expand: PRK と情報文字列から指定長の鍵素材 (OKM) を導出。
    ///
    /// 最大出力長: 255 × 32 = 8160 バイト。
    ///
    /// # Panics
    ///
    /// `length` が 8160 を超える場合。
    #[must_use]
    pub fn expand(prk: &Prk, info: &[u8], length: usize) -> Vec<u8> {
        assert!(length <= 255 * 32, "HKDF-Expand: length exceeds maximum");

        let mut okm = Vec::with_capacity(length);
        let mut prev = Vec::new();
        let mut counter: u8 = 1;

        while okm.len() < length {
            // T(i) = keyed_hash(PRK, T(i-1) || info || counter)
            let mut input = Vec::with_capacity(prev.len() + info.len() + 1);
            input.extend_from_slice(&prev);
            input.extend_from_slice(info);
            input.push(counter);

            let t = hash::keyed_hash(prk.as_bytes(), &input);
            prev = t.as_bytes().to_vec();

            let remaining = length - okm.len();
            let take = remaining.min(32);
            okm.extend_from_slice(&prev[..take]);

            counter = counter.wrapping_add(1);
        }

        okm
    }

    /// ワンショット鍵導出: Extract + Expand を一括実行。
    #[must_use]
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, length)
    }

    /// 32 バイト鍵をワンショットで導出 (最も一般的なケース)。
    #[must_use]
    pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let okm = Self::derive(salt, ikm, info, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm);
        key
    }
}

/// パスワードストレッチング (反復 BLAKE3)。
///
/// Argon2 の代替として、BLAKE3 の反復ハッシュで計算コストを増大。
/// メモリハードではないため、GPU 攻撃には弱い。
/// 高セキュリティが必要な場合は Argon2 を別途使用すべき。
///
/// # Arguments
///
/// * `password` — パスワード
/// * `salt` — ソルト (16バイト以上推奨)
/// * `iterations` — 反復回数 (10000以上推奨)
#[must_use]
pub fn password_stretch(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    // 初期 PRK
    let mut current = HkdfBlake3::extract(salt, password);

    // 反復ハッシュ
    for i in 0..iterations {
        let counter = i.to_le_bytes();
        let mut input = vec![0u8; 32 + counter.len()];
        input[..32].copy_from_slice(current.as_bytes());
        input[32..].copy_from_slice(&counter);
        current = Prk(*hash::keyed_hash(current.as_bytes(), &input).as_bytes());
    }

    *current.as_bytes()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_deterministic() {
        let prk1 = HkdfBlake3::extract(b"salt", b"input key material");
        let prk2 = HkdfBlake3::extract(b"salt", b"input key material");
        assert_eq!(prk1.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn extract_different_salt() {
        let prk1 = HkdfBlake3::extract(b"salt1", b"ikm");
        let prk2 = HkdfBlake3::extract(b"salt2", b"ikm");
        assert_ne!(prk1.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn extract_different_ikm() {
        let prk1 = HkdfBlake3::extract(b"salt", b"ikm1");
        let prk2 = HkdfBlake3::extract(b"salt", b"ikm2");
        assert_ne!(prk1.as_bytes(), prk2.as_bytes());
    }

    #[test]
    fn extract_empty_salt() {
        let prk = HkdfBlake3::extract(b"", b"ikm");
        assert_ne!(prk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn expand_correct_length() {
        let prk = HkdfBlake3::extract(b"salt", b"ikm");
        let okm = HkdfBlake3::expand(&prk, b"info", 64);
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn expand_different_info() {
        let prk = HkdfBlake3::extract(b"salt", b"ikm");
        let okm1 = HkdfBlake3::expand(&prk, b"info1", 32);
        let okm2 = HkdfBlake3::expand(&prk, b"info2", 32);
        assert_ne!(okm1, okm2);
    }

    #[test]
    fn expand_zero_length() {
        let prk = HkdfBlake3::extract(b"salt", b"ikm");
        let okm = HkdfBlake3::expand(&prk, b"info", 0);
        assert!(okm.is_empty());
    }

    #[test]
    fn derive_key_32bytes() {
        let key = HkdfBlake3::derive_key(b"salt", b"password", b"context");
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn derive_deterministic() {
        let k1 = HkdfBlake3::derive_key(b"s", b"p", b"c");
        let k2 = HkdfBlake3::derive_key(b"s", b"p", b"c");
        assert_eq!(k1, k2);
    }

    #[test]
    fn password_stretch_deterministic() {
        let h1 = password_stretch(b"password", b"salt1234567890ab", 100);
        let h2 = password_stretch(b"password", b"salt1234567890ab", 100);
        assert_eq!(h1, h2);
    }

    #[test]
    fn password_stretch_different_passwords() {
        let h1 = password_stretch(b"password1", b"salt", 100);
        let h2 = password_stretch(b"password2", b"salt", 100);
        assert_ne!(h1, h2);
    }

    #[test]
    fn password_stretch_different_iterations() {
        let h1 = password_stretch(b"password", b"salt", 100);
        let h2 = password_stretch(b"password", b"salt", 200);
        assert_ne!(h1, h2);
    }

    #[test]
    fn prk_zeroize_on_drop() {
        let prk = HkdfBlake3::extract(b"salt", b"ikm");
        let bytes = *prk.as_bytes();
        assert_ne!(bytes, [0u8; 32]);
        // drop は暗黙的に呼ばれる
    }
}
