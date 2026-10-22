//! ハッシュベース鍵導出関数 (KDF)
//!
//! BLAKE3 を基盤とした HKDF 風の鍵導出。
//! Extract → Expand の2段階で、任意の入力から暗号学的に安全な鍵を生成。
//!
//! password からの鍵導出は [`argon2id`] (RFC 9106、memory-hard) を使う 実装は RustCrypto の
//! `argon2` crate を薄く包む ALICE に Argon2 の実装は無く、memory-hard な KDF を自前で書く方が
//! 検証の済んだ実装から外れる度合いが大きいため

use alloc::vec;
use alloc::vec::Vec;

use crate::hash;
use zeroize::Zeroize;

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
    /// 0 埋めして落とす
    ///
    /// ⚠️ 旧実装の `self.0.iter_mut().for_each(|b| *b = 0)` は「以降読まれない
    /// 書き込み」として最適化で消えうる [`Zeroize`] は volatile write + fence
    fn drop(&mut self) {
        self.0.zeroize();
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
/// BLAKE3 の反復ハッシュで計算コストを増大させる
/// メモリハードではないため、GPU 攻撃には弱い
/// password から鍵を作る時は [`argon2id`] を使う (この関数は名前と挙動を変えずに残す)
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

/// Argon2id の費用 parameter (RFC 9106)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// memory (KiB)、lane ごとに 8 KiB 以上
    pub m_cost_kib: u32,
    /// 反復回数 (1 以上)
    pub t_cost: u32,
    /// 並列度 (lane 数、1 以上)
    pub p_lanes: u32,
}

impl Argon2Params {
    /// RFC 9106 4. の 2 つ目の推奨 (memory が限られる環境): 64 MiB、t = 3、p = 4
    pub const RFC9106_LOW_MEMORY: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_lanes: 4,
    };

    /// RFC 9106 4. の 1 つ目の推奨: 2 GiB、t = 1、p = 4 (端末には大きい)
    pub const RFC9106_RECOMMENDED: Self = Self {
        m_cost_kib: 2 * 1024 * 1024,
        t_cost: 1,
        p_lanes: 4,
    };

    /// 保存用の固定長 encode: `[m u32 BE][t u32 BE][p u32 BE]` (12 byte)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&self.m_cost_kib.to_be_bytes());
        b[4..8].copy_from_slice(&self.t_cost.to_be_bytes());
        b[8..].copy_from_slice(&self.p_lanes.to_be_bytes());
        b
    }

    /// [`Argon2Params::to_bytes`] の逆
    ///
    /// # Errors
    ///
    /// 長さが 12 byte でなければ [`KdfError::InvalidParams`]
    pub fn from_bytes(b: &[u8]) -> Result<Self, KdfError> {
        if b.len() != 12 {
            return Err(KdfError::InvalidParams);
        }
        let word = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Ok(Self {
            m_cost_kib: word(0),
            t_cost: word(4),
            p_lanes: word(8),
        })
    }
}

/// password からの鍵導出の error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// salt が [`ARGON2_MIN_SALT`] byte 未満
    SaltTooShort,
    /// 費用 parameter が範囲外 (t = 0、p = 0、m < 8p など)
    InvalidParams,
    /// 出力が 4 byte 未満か、上限を超える
    InvalidOutputLength,
    /// 上記以外の失敗 (secret / associated data が長すぎる、memory を確保できない)
    Failed,
}

/// [`argon2id`] が要求する salt の最小長 (RFC 9106 が推奨する 16 byte)
pub const ARGON2_MIN_SALT: usize = 16;

/// password から鍵を作る (Argon2id、RFC 9106、memory-hard)
///
/// `out` の長さの鍵を書く 同じ入力からは同じ鍵 (決定的) salt は password ごとに
/// 乱数で作り、`params` と一緒に保存する ([`Argon2Params::to_bytes`])
///
/// # Errors
///
/// [`KdfError`] (salt が短い、parameter が範囲外、出力長が範囲外)
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    out: &mut [u8],
) -> Result<(), KdfError> {
    argon2id_with(password, salt, &[], &[], params, out)
}

/// [`argon2id`] に secret (鍵、RFC 9106 の K) と associated data (X) を足した版
///
/// # Errors
///
/// [`argon2id`] と同じ
pub fn argon2id_with(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: &Argon2Params,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if salt.len() < ARGON2_MIN_SALT {
        return Err(KdfError::SaltTooShort);
    }
    let data = argon2::AssociatedData::new(associated_data).map_err(|_| KdfError::Failed)?;
    let p = argon2::ParamsBuilder::new()
        .m_cost(params.m_cost_kib)
        .t_cost(params.t_cost)
        .p_cost(params.p_lanes)
        .data(data)
        .output_len(out.len())
        .build()
        .map_err(map_argon2_error)?;
    let a = argon2::Argon2::new_with_secret(
        secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        p,
    )
    .map_err(|_| KdfError::Failed)?;
    a.hash_password_into(password, salt, out)
        .map_err(map_argon2_error)
}

// 範囲の検査は argon2 crate の 1 か所で行い、その error をここで分類する
// (同じ検査を手前に書くと 2 つの判定が食い違いうる)
fn map_argon2_error(e: argon2::Error) -> KdfError {
    match e {
        argon2::Error::OutputTooShort | argon2::Error::OutputTooLong => {
            KdfError::InvalidOutputLength
        }
        argon2::Error::MemoryTooLittle
        | argon2::Error::MemoryTooMuch
        | argon2::Error::TimeTooSmall
        | argon2::Error::ThreadsTooFew
        | argon2::Error::ThreadsTooMany => KdfError::InvalidParams,
        _ => KdfError::Failed,
    }
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
