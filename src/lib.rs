#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::module_name_repetitions,
    clippy::inline_always,
    clippy::too_many_lines
)]

//! # ALICE-Crypto
//!
//! **Information-Theoretic Security Primitives for ALICE**
//!
//! > "Encryption guarantees safety against time. Information theory guarantees safety against God."
//!
//! ALICE-Crypto provides three complementary cryptographic primitives designed
//! for the ALICE P2P ecosystem: secret splitting, hashing, and authenticated
//! encryption. All operations are constant-time and `no_std`-compatible.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`gf256`] | GF(2^8) Galois field arithmetic — branchless, constant-time mul and inv |
//! | [`sss`] | Shamir's Secret Sharing — K-of-N threshold splitting with Montgomery batch inv |
//! | `hash` | BLAKE3 hashing — content addressing, keyed MAC, key derivation |
//! | [`stream`] | XChaCha20-Poly1305 — authenticated encryption with zero-allocation in-place API |
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std` | yes | Standard library support (OS RNG, std I/O) |
//! | `alloc` | no | Heap allocation without std (embedded / WASM) |
//! | `ffi` | no | C-compatible cdylib exports (implies `std`) |
//!
//! ## Quick Start
//!
//! ```rust
//! use alice_crypto::{sss, Key, seal, open};
//!
//! // Generate a master key
//! let master_key = Key::generate().unwrap();
//!
//! // Split into 5 shards, require 3 to recover
//! let shards = sss::split(&master_key.0, 5, 3).unwrap();
//!
//! // Encrypt data
//! let encrypted = seal(&master_key, b"Top secret ALICE data").unwrap();
//!
//! // Recover key from any 3 shards
//! let recovered = sss::recover(&[
//!     shards[0].clone(), shards[2].clone(), shards[4].clone()
//! ]).unwrap();
//! let mut key_arr = [0u8; 32];
//! key_arr.copy_from_slice(&recovered);
//!
//! // Decrypt
//! let data = open(&Key::from_bytes(key_arr), &encrypted).unwrap();
//! assert_eq!(&data, b"Top secret ALICE data");
//! ```
//!
//! ## Security Properties
//!
//! | Primitive | Security Model | Quantum Resistant |
//! |-----------|---------------|-------------------|
//! | SSS | Information-theoretic (K-1 shards reveal zero information) | Yes |
//! | BLAKE3 | Computational (256-bit preimage resistance) | Partially (128-bit post-quantum) |
//! | XChaCha20-Poly1305 | Computational (256-bit key, 192-bit nonce) | No (symmetric = 128-bit post-quantum) |

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod gf256;
pub mod hash;
pub mod sss;
pub mod stream;

// Re-exports
pub use gf256::{batch_inv, batch_inv_stack, GF};
pub use hash::{derive_key, hash, keyed_hash, Hash, Hasher};
pub use sss::{recover, split, Shard, SssError};
pub use stream::{
    decrypt_in_place,
    decrypt_in_place_aead,
    // Core: Zero-allocation in-place APIs
    encrypt_in_place,
    encrypt_in_place_aead,
    open,
    // Convenience: Allocating wrappers
    seal,
    CipherError,
    Key,
    Nonce,
    TAG_SIZE,
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
        let recovered_key_bytes =
            recover(&[shards[1].clone(), shards[3].clone(), shards[4].clone()]).unwrap();

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
