//! # ALICE-Crypto
//!
//! **Information-Theoretic Security Primitives for ALICE**
//!
//! > "Encryption guarantees safety against time. Information theory guarantees safety against God."
//!
//! ## Primitives
//!
//! - **SSS (Shamir's Secret Sharing)**: Split secrets into K-of-N shards
//! - **BLAKE3**: High-performance cryptographic hashing
//! - **XChaCha20-Poly1305**: Authenticated stream encryption

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod gf256;
pub mod sss;
pub mod hash;
pub mod stream;

// Re-exports
pub use gf256::{GF, batch_inv, batch_inv_stack};
pub use sss::{Shard, SssError, split, recover};
pub use hash::{Hash, Hasher, hash, keyed_hash, derive_key};
pub use stream::{
    Key, Nonce, CipherError, TAG_SIZE,
    // Core: Zero-allocation in-place APIs
    encrypt_in_place, decrypt_in_place,
    encrypt_in_place_aead, decrypt_in_place_aead,
    // Convenience: Allocating wrappers
    seal, open,
};

/// Version
pub const VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_sss_encrypt() {
        // 1. Generate master key
        let master_key = Key::generate().unwrap();

        // 2. Split master key using SSS
        let shards = split(&master_key.0, 5, 3).unwrap();

        // 3. Encrypt data with master key
        let data = b"Top secret ALICE data";
        let encrypted = seal(&master_key, data).unwrap();

        // 4. Recover master key from any 3 shards
        let recovered_key_bytes = recover(&[
            shards[1].clone(),
            shards[3].clone(),
            shards[4].clone()
        ]).unwrap();

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&recovered_key_bytes);
        let recovered_key = Key::from_bytes(key_arr);

        // 5. Decrypt with recovered key
        let decrypted = open(&recovered_key, &encrypted).unwrap();
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn test_hash_then_encrypt() {
        let key = Key::generate().unwrap();
        let data = b"data to hash and encrypt";

        // Hash first
        let h = hash(data);

        // Encrypt the hash
        let encrypted = seal(&key, h.as_bytes()).unwrap();
        let decrypted = open(&key, &encrypted).unwrap();

        assert_eq!(&decrypted, h.as_bytes());
    }
}
