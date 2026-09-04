//! Fuzz target: BLAKE3 `hash()` / `keyed_hash()` / `derive_key()` が任意 bytes で panic しないこと
//!
//! canonical CI template [[reference_alice_ci_canonical_template]] 準拠
//!
//! 想定する危険:
//! - 空 slice / huge slice / non-UTF8 / edge bytes で panic
//! - keyed_hash 経路 (key 固定 + arbitrary message) の differential
//! - derive_key 経路 (context + key material) の panic

#![no_main]

use alice_crypto::hash::{derive_key, hash, keyed_hash};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op<'a> {
    /// 通常 hash
    Hash { data: &'a [u8] },
    /// Keyed MAC hash
    Keyed { key: [u8; 32], data: &'a [u8] },
    /// KDF 経路
    Derive { context: &'a str, key_material: &'a [u8] },
}

fuzz_target!(|op: Op<'_>| {
    match op {
        Op::Hash { data } => {
            let h1 = hash(data);
            let h2 = hash(data);
            // Deterministic property: 同じ入力は同じ hash
            assert_eq!(h1.as_bytes(), h2.as_bytes());
        }
        Op::Keyed { key, data } => {
            let h1 = keyed_hash(&key, data);
            let h2 = keyed_hash(&key, data);
            assert_eq!(h1.as_bytes(), h2.as_bytes());
        }
        Op::Derive { context, key_material } => {
            // derive_key: context は non-empty かつ ASCII 相当が推奨
            // arbitrary で empty / invalid が来ても panic しないこと確認
            let _k1 = derive_key(context, key_material);
            let _k2 = derive_key(context, key_material);
        }
    }
});
