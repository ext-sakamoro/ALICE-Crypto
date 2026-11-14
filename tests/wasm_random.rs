//! The OS random source and key generation on WebAssembly (wasm32-unknown-unknown) in a JavaScript host.
//!
//! On wasm32-unknown-unknown the default build takes its randomness from `crypto.getRandomValues`
//! (getrandom's `js` backend, feature `wasm-js` in `std-base`), so a consumer depends on
//! alice-crypto with no extra feature and no extra dependency. CI runs this file under Node with
//! `wasm-bindgen-test-runner` and fails when fewer tests pass than it has; on other targets the same
//! tests run as ordinary tests against the OS random source.

#![cfg(feature = "std")]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

use alice_crypto::{dp::SecureRng, mac, random, stream, x25519};

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn two_fills_differ_and_write_the_whole_buffer() {
    // 2^-256 chance of a false failure for an honest source
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
    let mut long = [0xA5u8; 4096];
    random::fill(&mut long).unwrap();
    assert!(long[..64].iter().any(|&x| x != 0xA5));
    assert!(long[4096 - 64..].iter().any(|&x| x != 0xA5));
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn generated_cipher_keys_differ_and_seal_and_open() {
    let (k1, k2) = (
        stream::Key::generate().unwrap(),
        stream::Key::generate().unwrap(),
    );
    let sealed = stream::seal(&k1, b"over the edge").unwrap();
    assert_eq!(stream::open(&k1, &sealed).unwrap(), b"over the edge");
    assert!(
        stream::open(&k2, &sealed).is_err(),
        "two generated keys are different keys"
    );
    // the nonce is drawn per seal: the same plaintext seals to different bytes
    assert_ne!(sealed, stream::seal(&k1, b"over the edge").unwrap());
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn generated_mac_keys_tag_and_verify() {
    let (k1, k2) = (
        mac::MacKey::generate().unwrap(),
        mac::MacKey::generate().unwrap(),
    );
    let tag = mac::mac(&k1, b"message");
    assert!(mac::verify(&k1, b"message", &tag));
    assert!(!mac::verify(&k2, b"message", &tag));
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn random_x25519_secrets_agree() {
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    let (pa, pb) = (x25519::public_key(&a), x25519::public_key(&b));
    let ab = x25519::diffie_hellman(&a, &pb).unwrap();
    let ba = x25519::diffie_hellman(&b, &pa).unwrap();
    assert_eq!(ab, ba);
    assert_ne!(pa, pb);
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn dp_keys_from_entropy_differ() {
    let mut r1 = SecureRng::try_from_entropy().unwrap();
    let mut r2 = SecureRng::try_from_entropy().unwrap();
    let s1: Vec<u64> = (0..4).map(|_| r1.next_u64()).collect();
    let s2: Vec<u64> = (0..4).map(|_| r2.next_u64()).collect();
    assert_ne!(s1, s2);
}
