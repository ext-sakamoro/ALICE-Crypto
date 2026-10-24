//! Oracle for the IETF ChaCha20-Poly1305 AEAD (RFC 8439). The expected bytes are the RFC's own
//! test vectors (section 2.8.2 for sealing, appendix A.5 for opening), copied from the RFC text;
//! none comes from the code under test.

use alice_crypto::chacha20poly1305_ietf::{open, seal, AeadError, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

// RFC 8439 section 2.8.2: the nonce is the 32-bit fixed-common part followed by the 64-bit IV
const S282_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const S282_NONCE: &str = "070000004041424344454647";
const S282_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const S282_PLAINTEXT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
const S282_CIPHERTEXT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
const S282_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

// RFC 8439 appendix A.5
const A5_KEY: &str = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
const A5_NONCE: &str = "000000000102030405060708";
const A5_AAD: &str = "f33388860000000000004e91";
const A5_CIPHERTEXT: &str = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b";
const A5_TAG: &str = "eead9d67890cbb22392336fea1851f38";
const A5_PLAINTEXT: &str = "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d";

fn sealed(ciphertext: &str, tag: &str) -> Vec<u8> {
    let mut v = hex(ciphertext);
    v.extend_from_slice(&hex(tag));
    v
}

#[test]
fn the_sizes_are_the_rfcs() {
    assert_eq!((KEY_SIZE, NONCE_SIZE, TAG_SIZE), (32, 12, 16));
}

#[test]
fn seal_matches_rfc8439_section_2_8_2() {
    let out = seal(
        &arr(S282_KEY),
        &arr(S282_NONCE),
        &hex(S282_AAD),
        &hex(S282_PLAINTEXT),
    );
    assert_eq!(hex(S282_PLAINTEXT).len(), 114);
    assert_eq!(out, sealed(S282_CIPHERTEXT, S282_TAG));
    assert_eq!(
        open(&arr(S282_KEY), &arr(S282_NONCE), &hex(S282_AAD), &out).unwrap(),
        hex(S282_PLAINTEXT)
    );
}

#[test]
fn open_matches_rfc8439_appendix_a5() {
    let pt = open(
        &arr(A5_KEY),
        &arr(A5_NONCE),
        &hex(A5_AAD),
        &sealed(A5_CIPHERTEXT, A5_TAG),
    )
    .unwrap();
    assert_eq!(pt, hex(A5_PLAINTEXT));
    assert!(pt.starts_with(b"Internet-Drafts are draft documents"));
    assert_eq!(
        seal(&arr(A5_KEY), &arr(A5_NONCE), &hex(A5_AAD), &pt),
        sealed(A5_CIPHERTEXT, A5_TAG)
    );
}

#[test]
fn any_change_is_refused() {
    let key: [u8; KEY_SIZE] = arr(S282_KEY);
    let nonce: [u8; NONCE_SIZE] = arr(S282_NONCE);
    let aad = hex(S282_AAD);
    let good = sealed(S282_CIPHERTEXT, S282_TAG);
    for i in [
        0,
        57,
        good.len() - TAG_SIZE - 1,
        good.len() - TAG_SIZE,
        good.len() - 1,
    ] {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert_eq!(
            open(&key, &nonce, &aad, &bad),
            Err(AeadError::Authentication),
            "byte {i}"
        );
    }
    let mut other_key = key;
    other_key[31] ^= 0x80;
    assert_eq!(
        open(&other_key, &nonce, &aad, &good),
        Err(AeadError::Authentication)
    );
    let mut other_nonce = nonce;
    other_nonce[0] ^= 0x01;
    assert_eq!(
        open(&key, &other_nonce, &aad, &good),
        Err(AeadError::Authentication)
    );
    let mut other_aad = aad.clone();
    other_aad[11] ^= 0x01;
    assert_eq!(
        open(&key, &nonce, &other_aad, &good),
        Err(AeadError::Authentication)
    );
    assert_eq!(
        open(&key, &nonce, &[], &good),
        Err(AeadError::Authentication)
    );
}

#[test]
fn input_shorter_than_a_tag_is_refused_and_an_empty_message_round_trips() {
    let key: [u8; KEY_SIZE] = arr(S282_KEY);
    let nonce: [u8; NONCE_SIZE] = arr(S282_NONCE);
    for n in 0..TAG_SIZE {
        assert_eq!(
            open(&key, &nonce, b"", &vec![0u8; n]),
            Err(AeadError::Authentication),
            "{n} bytes"
        );
    }
    let empty = seal(&key, &nonce, b"header", b"");
    assert_eq!(empty.len(), TAG_SIZE);
    assert_eq!(
        open(&key, &nonce, b"header", &empty).unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        open(&key, &nonce, b"other", &empty),
        Err(AeadError::Authentication)
    );
}

#[test]
fn both_aeads_report_one_error_type() {
    // the crate has one AEAD failure type; each AEAD module re-exports it
    let e: alice_crypto::aead::AeadError = AeadError::Authentication;
    let same: alice_crypto::aes_gcm::AeadError = e;
    assert_eq!(same, alice_crypto::aead::AeadError::Authentication);
    assert_eq!(e.to_string(), "AEAD authentication failed");
    let key = [0u8; 32];
    let gcm_key = [0u8; 16];
    let nonce = [0u8; 12];
    let a = open(&key, &nonce, b"", &[0u8; 16]);
    let b = alice_crypto::aes_gcm::open(&gcm_key, &nonce, b"", &[0u8; 16]);
    assert_eq!(a, b.map(|_| Vec::new()));
}
