//! BLAKE3 hashing wrapper
//!
//! Faster than SHA-256, Merkle-tree based, SIMD accelerated.

extern crate alloc;

/// 32-byte hash output
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const SIZE: usize = 32;

    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    #[inline(always)]
    pub const fn into_bytes(self) -> [u8; 32] { self.0 }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0[..4] {
            write!(f, "{:02x}", b)?;
        }
        f.write_str("...")
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Hash data using BLAKE3
#[inline(always)]
pub fn hash(data: &[u8]) -> Hash {
    Hash(*blake3::hash(data).as_bytes())
}

/// Incremental hasher
pub struct Hasher(blake3::Hasher);

impl Hasher {
    #[inline(always)]
    pub fn new() -> Self { Self(blake3::Hasher::new()) }

    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) { self.0.update(data); }

    #[inline(always)]
    pub fn finalize(&self) -> Hash { Hash(*self.0.finalize().as_bytes()) }

    #[inline(always)]
    pub fn reset(&mut self) { self.0.reset(); }
}

impl Default for Hasher {
    fn default() -> Self { Self::new() }
}

/// Keyed hash (MAC)
#[inline(always)]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    Hash(*blake3::keyed_hash(key, data).as_bytes())
}

/// Derive key from context string and input
#[inline(always)]
pub fn derive_key(context: &str, input: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let h = hash(b"Hello, ALICE!");
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_incremental() {
        let mut hasher = Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"ALICE!");
        let h1 = hasher.finalize();

        let h2 = hash(b"Hello, ALICE!");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_keyed() {
        let key = [0x42u8; 32];
        let h1 = keyed_hash(&key, b"data");
        let h2 = keyed_hash(&key, b"data");
        let h3 = keyed_hash(&key, b"different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_derive_key() {
        let k1 = derive_key("ALICE-Crypto test", b"input");
        let k2 = derive_key("ALICE-Crypto test", b"input");
        let k3 = derive_key("different context", b"input");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    // ── New tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_hash_empty_input() {
        // Empty input should produce a valid (nonzero) 32-byte hash
        let h = hash(b"");
        assert_eq!(h.0.len(), 32);
        // BLAKE3("") is a well-known nonzero value
        let is_nonzero = h.0.iter().any(|&b| b != 0);
        assert!(is_nonzero);
    }

    #[test]
    fn test_hash_determinism() {
        let data = b"determinism test";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs_differ() {
        let h1 = hash(b"input_a");
        let h2 = hash(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_size_constant() {
        assert_eq!(Hash::SIZE, 32);
    }

    #[test]
    fn test_hash_as_bytes_roundtrip() {
        let h = hash(b"roundtrip");
        let bytes = h.as_bytes();
        assert_eq!(bytes.len(), 32);
        let h2 = Hash(*bytes);
        assert_eq!(h, h2);
    }

    #[test]
    fn test_hash_into_bytes() {
        let h = hash(b"into_bytes");
        let arr = h.into_bytes();
        assert_eq!(arr.len(), 32);
    }

    #[test]
    fn test_hash_clone_copy() {
        let h = hash(b"clone");
        let h2 = h;       // Copy
        let h3 = h.clone(); // Clone
        assert_eq!(h, h2);
        assert_eq!(h, h3);
    }

    #[test]
    fn test_hash_eq() {
        let h1 = hash(b"same");
        let h2 = hash(b"same");
        let h3 = hash(b"different");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hash_debug_format() {
        let h = hash(b"debug");
        let s = alloc::format!("{:?}", h);
        // Debug shows first 4 bytes as hex + "..."
        assert!(s.ends_with("..."));
        assert_eq!(s.len(), 4 * 2 + 3); // 8 hex chars + "..."
    }

    #[test]
    fn test_hash_display_format() {
        let h = hash(b"display");
        let s = alloc::format!("{}", h);
        // Display shows all 32 bytes as hex
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hasher_default() {
        let h1 = Hasher::new();
        let h2 = Hasher::default();
        // Both should produce same hash on same input
        let mut h1 = h1;
        let mut h2 = h2;
        h1.update(b"test");
        h2.update(b"test");
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_hasher_reset() {
        let mut hasher = Hasher::new();
        hasher.update(b"first");
        let h1 = hasher.finalize();

        hasher.reset();
        hasher.update(b"first");
        let h2 = hasher.finalize();

        // After reset, should produce the same result
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hasher_multiple_updates_order_matters() {
        let mut h1 = Hasher::new();
        h1.update(b"ab");

        let mut h2 = Hasher::new();
        h2.update(b"a");
        h2.update(b"b");

        // Streaming should match single update
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_keyed_hash_different_keys_differ() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let data = b"same data";
        let h1 = keyed_hash(&key1, data);
        let h2 = keyed_hash(&key2, data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_keyed_hash_vs_plain_hash_differ() {
        // Keyed hash should differ from plain hash of same data
        let key = [0x42u8; 32];
        let data = b"data";
        let plain = hash(data);
        let keyed = keyed_hash(&key, data);
        assert_ne!(plain, keyed);
    }

    #[test]
    fn test_derive_key_output_length() {
        let k = derive_key("ALICE-Crypto", b"material");
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn test_derive_key_nonzero() {
        let k = derive_key("ALICE-Crypto context", b"key material");
        let is_nonzero = k.iter().any(|&b| b != 0);
        assert!(is_nonzero);
    }

    extern crate alloc;
    #[allow(unused_imports)]
    use alloc::format;
}
