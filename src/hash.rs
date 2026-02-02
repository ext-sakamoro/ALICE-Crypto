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
#[inline]
pub fn hash(data: &[u8]) -> Hash {
    Hash(*blake3::hash(data).as_bytes())
}

/// Incremental hasher
pub struct Hasher(blake3::Hasher);

impl Hasher {
    #[inline]
    pub fn new() -> Self { Self(blake3::Hasher::new()) }

    #[inline]
    pub fn update(&mut self, data: &[u8]) { self.0.update(data); }

    #[inline]
    pub fn finalize(&self) -> Hash { Hash(*self.0.finalize().as_bytes()) }

    #[inline]
    pub fn reset(&mut self) { self.0.reset(); }
}

impl Default for Hasher {
    fn default() -> Self { Self::new() }
}

/// Keyed hash (MAC)
#[inline]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    Hash(*blake3::keyed_hash(key, data).as_bytes())
}

/// Derive key from context string and input
#[inline]
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
}
