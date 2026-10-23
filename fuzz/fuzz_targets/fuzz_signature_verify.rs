//! Fuzz target: BLAKE3-MAC の mac / verify が任意 bytes で panic せず、property が成立すること
//!
//! Part of the shared ALICE-* fuzz set: one target per public entry point
//! that parses untrusted bytes.
//!
//! Property:
//! - mac(k, m) → verify(k, m, tag) == true (roundtrip 常に成功)
//! - verify(k, m, arbitrary_tag) は panic せず bool を返す (differential)
//! - verify(k, tampered_m, tag) は false を返す (tamper detection)

#![no_main]

use alice_crypto::mac::{mac, verify, MacKey, Tag};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    key_bytes: [u8; 32],
    message: &'a [u8],
    /// 任意 signature bytes で verify() が panic しないこと確認
    arbitrary_sig_bytes: [u8; 32],
    /// message tamper 用 xor byte (Some なら 1 byte flip)
    tamper_at: Option<u16>,
}

fuzz_target!(|input: Input<'_>| {
    let key = MacKey::from_bytes(input.key_bytes);

    // Property 1: sign → verify roundtrip
    let sig = mac(&key, input.message);
    assert!(
        verify(&key, input.message, &sig),
        "mac/verify roundtrip failed"
    );

    // Property 2: arbitrary signature bytes → verify は panic せず bool
    let arbitrary_sig = Tag::from_bytes(input.arbitrary_sig_bytes);
    let _ = verify(&key, input.message, &arbitrary_sig);

    // Property 3: tampered message → verify() は false を返すべき
    if let Some(idx16) = input.tamper_at {
        if input.message.is_empty() {
            return;
        }
        let idx = (idx16 as usize) % input.message.len();
        let mut tampered = input.message.to_vec();
        tampered[idx] ^= 0x01;
        assert!(
            !verify(&key, &tampered, &sig),
            "tamper detection failed: sig verified against altered message"
        );
    }
});
