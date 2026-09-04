//! Fuzz target: BLAKE3-MAC sign/verify が任意 bytes で panic せず、property が成立すること
//!
//! canonical CI template [[reference_alice_ci_canonical_template]] 準拠
//!
//! Property:
//! - sign(k, m) → verify(k.vk, m, sig) == true (roundtrip 常に成功)
//! - verify(k.vk, m, arbitrary_sig) は panic せず bool を返す (differential)
//! - verify(k.vk, tampered_m, sig) は false を返す (tamper detection)

#![no_main]

use alice_crypto::signature::{sign, verify, Signature, SigningKey};
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
    let sk = SigningKey::from_bytes(input.key_bytes);
    let vk = sk.verifying_key();

    // Property 1: sign → verify roundtrip
    let sig = sign(&sk, input.message);
    assert!(
        verify(&vk, input.message, &sig),
        "sign/verify roundtrip failed"
    );

    // Property 2: arbitrary signature bytes → verify は panic せず bool
    let arbitrary_sig = Signature::from_bytes(input.arbitrary_sig_bytes);
    let _ = verify(&vk, input.message, &arbitrary_sig);

    // Property 3: tampered message → verify() は false を返すべき
    if let Some(idx16) = input.tamper_at {
        if input.message.is_empty() {
            return;
        }
        let idx = (idx16 as usize) % input.message.len();
        let mut tampered = input.message.to_vec();
        tampered[idx] ^= 0x01;
        assert!(
            !verify(&vk, &tampered, &sig),
            "tamper detection failed: sig verified against altered message"
        );
    }
});
