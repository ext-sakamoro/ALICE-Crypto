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
//! encryption. Every module is `no_std`-compatible.
//!
//! ## Timing behaviour
//!
//! There is no single "all operations are constant-time" guarantee: the honest
//! statement is per operation, because some operations legitimately depend on
//! public inputs (slice lengths, iteration counts, key identifiers) and some are
//! delegated to upstream crates. The table below says, for each operation, what
//! the running time is allowed to depend on. Anything not listed there — in
//! particular the *value* of a key, a share, a tag or a field element — must not
//! affect it.
//!
//! | Operation | Running time may depend on |
//! |-----------|----------------------------|
//! | [`gf256::GF::add`] / `sub` / [`mul`](gf256::GF::mul) | nothing (unrolled bit operations, no tables, no branches) |
//! | [`gf256::GF::inv_or_zero`] / [`div_or_zero`](gf256::GF::div_or_zero) | nothing |
//! | [`gf256::GF::inv`] / [`div`](gf256::GF::div) | whether the argument was zero — i.e. exactly the `Option` that is returned |
//! | [`gf256::batch_inv`] / [`batch_inv_stack`] | `inputs.len()`, plus the single "was any input zero" bit that the `Option` returns |
//! | [`sss::split`] / [`sss::recover`] | secret length, share count, threshold (all public parameters) |
//! | [`signature::verify`] / `verify_with_context` / `Signature as PartialEq` | message length (tag comparison is constant-time over all 32 bytes) |
//! | `hash::*` / [`kdf`] | input length, and the requested output length / iteration count |
//! | [`stream`] encrypt / decrypt | buffer and associated-data length |
//! | [`keystore`] lookup / revoke / purge | number of stored entries (key *ids* and timestamps are public metadata, not secrets) |
//! | [`dp`] noise generation | the number of samples drawn and the public ε / Δ — not the key, the true value or the noise produced (fixed trip counts and masked choices; each draw takes a fixed number of keystream words, checked by `tests/dp_cost_model.rs` and the `// CONSTANT-TIME:` functions of `scripts/constant_time_guard.py`) |
//!
//! Caveats, stated rather than glossed over:
//!
//! - `hash`, `kdf` and `stream` delegate to the `blake3` and `chacha20poly1305`
//!   crates. Those implementations are written without secret-dependent branches
//!   or table lookups (and `chacha20poly1305` compares tags with `subtle`), but
//!   this crate does not re-verify that property.
//! - The table is enforced *statically* by `scripts/constant_time_guard.py`,
//!   which rejects comparison `derive`s on secret-carrying types and
//!   value-dependent early exits inside the operations above. That is a check on
//!   how the code is written, not a proof: instruction selection, compiler
//!   transformations and cache behaviour are not measured.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`gf256`] | GF(2^8) Galois field arithmetic — branchless, constant-time mul and inv |
//! | [`sss`] | Shamir's Secret Sharing — K-of-N threshold splitting with Montgomery batch inv |
//! | `hash` | BLAKE3 hashing — content addressing, keyed MAC, key derivation |
//! | [`stream`] | XChaCha20-Poly1305 — authenticated encryption with zero-allocation in-place API |
//! | [`dp`] | Differential-privacy noise over a **keyed** ChaCha20 CSPRNG: discrete Laplace for counts and on a power-of-two lattice for real values, sampled with integer arithmetic only and in constant time — reproducible for whoever holds the key, unpredictable for everyone else |
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

pub mod dp;
pub mod gf256;
pub mod hash;
pub mod kdf;
pub mod keystore;
pub mod signature;
pub mod sss;
pub mod stream;

// Re-exports
pub use dp::{dp_count, dp_sum, DpError, DpNoise, EntropyError, SecureRng};
pub use gf256::{batch_inv, batch_inv_stack, GF};
pub use hash::{derive_key, hash, keyed_hash, Hash, Hasher};
pub use kdf::{password_stretch, HkdfBlake3, Prk};
pub use keystore::{KeyEntry, KeyId, KeyStore, KeyStoreError};
pub use signature::{sign, verify, Signature, SignatureError, SigningKey, VerifyingKey};
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

/// Version (always the built crate's `CARGO_PKG_VERSION`)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_matches_cargo_pkg_version() {
        // VERSION は Cargo.toml の version と常に一致する (手書き literal は drift する)
        assert!(!VERSION.is_empty());
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

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
