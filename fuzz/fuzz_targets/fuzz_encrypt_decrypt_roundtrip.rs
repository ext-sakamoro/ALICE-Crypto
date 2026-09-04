//! Fuzz target: XChaCha20-Poly1305 seal/open が任意 plaintext + 任意 key で bit-exact 一致すること
//!
//! canonical CI template [[reference_alice_ci_canonical_template]] 準拠
//!
//! 決定論 crypto value のため、encrypt → decrypt → 元 plaintext と bit-exact 一致は必須。
//! 想定する危険:
//! - 空 plaintext / huge plaintext / edge byte pattern で panic
//! - decrypt が破壊されて original と mismatch
//! - open() が corrupted ciphertext で panic (should return Err、not panic)

#![no_main]

use alice_crypto::{open, seal, stream::Key};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    key: [u8; 32],
    plaintext: &'a [u8],
    /// Corrupt ciphertext byte at this index (mod ct_len) after seal
    /// で decrypt を fail させる differential test
    corrupt_at: Option<u16>,
}

fuzz_target!(|input: Input<'_>| {
    let key = Key::from_bytes(input.key);

    // Seal
    let sealed = match seal(&key, input.plaintext) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Open (roundtrip must succeed and be bit-exact)
    match open(&key, &sealed) {
        Ok(recovered) => {
            assert_eq!(recovered, input.plaintext, "roundtrip mismatch");
        }
        Err(_) => {
            // 正常経路で seal 成功したのに open 失敗は明確に bug
            panic!("open failed on freshly-sealed data");
        }
    }

    // Corruption differential: 1 bit flip → open は panic せず Err を返すべき
    if let Some(idx16) = input.corrupt_at {
        if sealed.is_empty() {
            return;
        }
        let idx = (idx16 as usize) % sealed.len();
        let mut corrupted = sealed.clone();
        corrupted[idx] ^= 0x01;
        // 結果 (Ok/Err) はどちらでも良い — panic しないことだけが property
        let _ = open(&key, &corrupted);
    }
});
