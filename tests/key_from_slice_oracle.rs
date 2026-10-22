//! Oracle for `Key::from_slice`.
//!
//! Expected values do not come from the code under test:
//! - the accepted length is the XChaCha20-Poly1305 key size, 32 bytes (RFC 8439 §2.8 key, draft-irtf-cfrg-xchacha-03);
//! - a rejected slice reports its own length, which the test knows from the input;
//! - an accepted key holds exactly the input bytes (each position distinct, so a shifted or partial copy shows),
//!   and seals what a key built with `Key::from_bytes` from the same bytes opens.

use alice_crypto::{open, seal, CipherError, Key};

fn distinct_bytes() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(7).wrapping_add(3))
}

#[test]
fn rejects_every_length_but_32_and_reports_it() {
    for len in [0usize, 1, 16, 31, 33, 64] {
        let v = vec![0xa5u8; len];
        match Key::from_slice(&v) {
            Err(CipherError::InvalidKeyLength(n)) => assert_eq!(n, len, "reported length for a {len}-byte slice"),
            Err(e) => panic!("{len}-byte slice: want InvalidKeyLength({len}), got {e:?}"),
            Ok(_) => panic!("{len}-byte slice was accepted"),
        }
    }
}

#[test]
fn a_32_byte_slice_becomes_exactly_those_bytes() {
    let bytes = distinct_bytes();
    let key = Key::from_slice(&bytes).expect("32 bytes");
    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn a_32_byte_window_of_a_longer_buffer_is_accepted() {
    let mut buf = [0u8; 40];
    buf[4..36].copy_from_slice(&distinct_bytes());
    let key = Key::from_slice(&buf[4..36]).expect("32-byte window");
    assert_eq!(key.as_bytes(), &distinct_bytes());
}

#[test]
fn interoperates_with_from_bytes() {
    let bytes = distinct_bytes();
    let from_slice = Key::from_slice(&bytes).expect("32 bytes");
    let from_array = Key::from_bytes(bytes);
    let sealed = seal(&from_slice, b"from_slice").expect("seal");
    assert_eq!(open(&from_array, &sealed).expect("open"), b"from_slice");
    let sealed = seal(&from_array, b"from_bytes").expect("seal");
    assert_eq!(open(&from_slice, &sealed).expect("open"), b"from_bytes");
}
