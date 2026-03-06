//! インメモリ鍵管理 (Key Store)
//!
//! 鍵の生成・ローテーション・有効期限管理を提供。
//! 鍵データはドロップ時にゼロクリアされる。

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use alloc::collections::BTreeMap;

/// 鍵 ID。
pub type KeyId = u64;

/// 鍵エントリ。
#[derive(Clone)]
pub struct KeyEntry {
    /// 鍵 ID。
    pub id: KeyId,
    /// 鍵データ (32 バイト)。
    key_data: [u8; 32],
    /// 作成時刻 (Unix タイムスタンプ秒)。
    pub created_at: u64,
    /// 有効期限 (Unix タイムスタンプ秒、0 = 無期限)。
    pub expires_at: u64,
    /// 世代番号 (ローテーションでインクリメント)。
    pub generation: u32,
    /// 無効化済みか。
    pub revoked: bool,
}

impl KeyEntry {
    /// 鍵データへの参照。
    #[must_use]
    pub const fn key_data(&self) -> &[u8; 32] {
        &self.key_data
    }

    /// 指定時刻で有効か。
    #[must_use]
    pub const fn is_valid_at(&self, now: u64) -> bool {
        if self.revoked {
            return false;
        }
        if self.expires_at > 0 && now >= self.expires_at {
            return false;
        }
        true
    }

    /// 有効期限が切れているか。
    #[must_use]
    pub const fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at > 0 && now >= self.expires_at
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        self.key_data.iter_mut().for_each(|b| *b = 0);
    }
}

/// インメモリ鍵ストア。
#[derive(Default)]
pub struct KeyStore {
    /// 鍵エントリ (ID → エントリ)。
    entries: BTreeMap<KeyId, KeyEntry>,
    /// 現在アクティブな鍵 ID。
    active_id: Option<KeyId>,
    /// 次の鍵 ID。
    next_id: KeyId,
    /// デフォルト有効期間 (秒、0 = 無期限)。
    default_ttl: u64,
}

impl KeyStore {
    /// 新しい鍵ストアを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            active_id: None,
            next_id: 1,
            default_ttl: 0,
        }
    }

    /// デフォルト有効期間を設定 (秒)。
    #[must_use]
    pub const fn with_default_ttl(mut self, ttl_seconds: u64) -> Self {
        self.default_ttl = ttl_seconds;
        self
    }

    /// 新しい鍵を生成してストアに追加。
    ///
    /// # Arguments
    ///
    /// * `now` — 現在の Unix タイムスタンプ秒
    ///
    /// # Errors
    ///
    /// OS RNG が利用不可の場合。
    pub fn generate(&mut self, now: u64) -> Result<KeyId, KeyStoreError> {
        let mut key_data = [0u8; 32];
        getrandom::getrandom(&mut key_data).map_err(|_| KeyStoreError::RngFailed)?;

        let id = self.next_id;
        self.next_id += 1;

        let expires_at = if self.default_ttl > 0 {
            now + self.default_ttl
        } else {
            0
        };

        let entry = KeyEntry {
            id,
            key_data,
            created_at: now,
            expires_at,
            generation: 1,
            revoked: false,
        };

        self.entries.insert(id, entry);
        self.active_id = Some(id);
        Ok(id)
    }

    /// 指定バイト配列で鍵を追加。
    pub fn insert(&mut self, key_data: [u8; 32], now: u64) -> KeyId {
        let id = self.next_id;
        self.next_id += 1;

        let expires_at = if self.default_ttl > 0 {
            now + self.default_ttl
        } else {
            0
        };

        let entry = KeyEntry {
            id,
            key_data,
            created_at: now,
            expires_at,
            generation: 1,
            revoked: false,
        };

        self.entries.insert(id, entry);
        self.active_id = Some(id);
        id
    }

    /// 鍵ローテーション: 新しい鍵を生成し、旧鍵を保持。
    ///
    /// # Errors
    ///
    /// OS RNG が利用不可の場合。
    pub fn rotate(&mut self, now: u64) -> Result<KeyId, KeyStoreError> {
        let prev_gen = self
            .active_id
            .and_then(|id| self.entries.get(&id))
            .map_or(0, |e| e.generation);

        let mut key_data = [0u8; 32];
        getrandom::getrandom(&mut key_data).map_err(|_| KeyStoreError::RngFailed)?;

        let id = self.next_id;
        self.next_id += 1;

        let expires_at = if self.default_ttl > 0 {
            now + self.default_ttl
        } else {
            0
        };

        let entry = KeyEntry {
            id,
            key_data,
            created_at: now,
            expires_at,
            generation: prev_gen + 1,
            revoked: false,
        };

        self.entries.insert(id, entry);
        self.active_id = Some(id);
        Ok(id)
    }

    /// 現在アクティブな鍵を取得。
    #[must_use]
    pub fn get_active(&self) -> Option<&KeyEntry> {
        self.active_id.and_then(|id| self.entries.get(&id))
    }

    /// ID で鍵を取得。
    #[must_use]
    pub fn get(&self, id: KeyId) -> Option<&KeyEntry> {
        self.entries.get(&id)
    }

    /// 鍵を無効化。
    pub fn revoke(&mut self, id: KeyId) -> bool {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.revoked = true;
            if self.active_id == Some(id) {
                self.active_id = None;
            }
            true
        } else {
            false
        }
    }

    /// 期限切れの鍵を削除 (ゼロクリア + 除去)。
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let expired_ids: Vec<KeyId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired_at(now))
            .map(|(&id, _)| id)
            .collect();

        let count = expired_ids.len();
        for id in expired_ids {
            self.entries.remove(&id);
            if self.active_id == Some(id) {
                self.active_id = None;
            }
        }
        count
    }

    /// ストア内の鍵数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ストアが空か。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 全鍵 ID のリスト。
    #[must_use]
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.entries.keys().copied().collect()
    }
}

// ============================================================================
// エラー型
// ============================================================================

/// 鍵ストアエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    /// 鍵が見つからない。
    KeyNotFound(KeyId),
    /// RNG 失敗。
    RngFailed,
}

impl core::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyNotFound(id) => write!(f, "Key not found: {id}"),
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
    fn generate_key() {
        let mut store = KeyStore::new();
        let id = store.generate(1000).unwrap();
        assert_eq!(id, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get_active().is_some());
    }

    #[test]
    fn insert_key() {
        let mut store = KeyStore::new();
        let id = store.insert([42u8; 32], 1000);
        let entry = store.get(id).unwrap();
        assert_eq!(entry.key_data(), &[42u8; 32]);
    }

    #[test]
    fn rotate_increments_generation() {
        let mut store = KeyStore::new();
        let id1 = store.generate(1000).unwrap();
        let id2 = store.rotate(2000).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(store.get(id1).unwrap().generation, 1);
        assert_eq!(store.get(id2).unwrap().generation, 2);
        assert_eq!(store.get_active().unwrap().id, id2);
    }

    #[test]
    fn rotate_preserves_old_key() {
        let mut store = KeyStore::new();
        let id1 = store.generate(1000).unwrap();
        let _ = store.rotate(2000).unwrap();

        // 旧鍵はまだアクセス可能
        assert!(store.get(id1).is_some());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn revoke_key() {
        let mut store = KeyStore::new();
        let id = store.generate(1000).unwrap();
        assert!(store.revoke(id));

        let entry = store.get(id).unwrap();
        assert!(entry.revoked);
        assert!(!entry.is_valid_at(1000));
        assert!(store.get_active().is_none());
    }

    #[test]
    fn revoke_nonexistent() {
        let mut store = KeyStore::new();
        assert!(!store.revoke(999));
    }

    #[test]
    fn ttl_expiration() {
        let mut store = KeyStore::new().with_default_ttl(3600);
        let id = store.generate(1000).unwrap();

        let entry = store.get(id).unwrap();
        assert_eq!(entry.expires_at, 4600);
        assert!(entry.is_valid_at(2000));
        assert!(!entry.is_valid_at(5000));
    }

    #[test]
    fn purge_expired() {
        let mut store = KeyStore::new().with_default_ttl(100);
        let _ = store.generate(1000).unwrap();
        let _ = store.generate(1050).unwrap();

        // t=1200: 最初の鍵 (expires 1100) は期限切れ、2番目 (expires 1150) も期限切れ
        let purged = store.purge_expired(1200);
        assert_eq!(purged, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn purge_keeps_valid() {
        let mut store = KeyStore::new().with_default_ttl(1000);
        let _ = store.generate(1000).unwrap();

        let purged = store.purge_expired(1500);
        assert_eq!(purged, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn key_ids() {
        let mut store = KeyStore::new();
        let id1 = store.generate(100).unwrap();
        let id2 = store.generate(200).unwrap();
        let ids = store.key_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn empty_store() {
        let store = KeyStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get_active().is_none());
    }

    #[test]
    fn error_display() {
        assert!(KeyStoreError::KeyNotFound(42).to_string().contains("42"));
        assert!(KeyStoreError::RngFailed.to_string().contains("Random"));
    }
}
