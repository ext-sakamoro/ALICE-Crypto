//! Oracle for the sealed envelope (`seal_envelope` / `open_envelope`).
//!
//! Layout under test: `[version u8 = 1][key id u32 big-endian][nonce 24][ciphertext][tag 16]`,
//! where the AEAD associated data is the 5-byte header followed by the caller's
//! associated data. Expected bytes are computed with the `chacha20poly1305`
//! crate directly, not with the code under test.

use alice_crypto::envelope::{
    envelope_key_id, open_envelope, reseal_envelope, seal_envelope, EnvelopeError,
    ENVELOPE_HEADER_SIZE, ENVELOPE_OVERHEAD, ENVELOPE_VERSION,
};
use alice_crypto::{CipherError, Key};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

fn key(b: u8) -> Key {
    Key::from_bytes([b; 32])
}

const KID: u32 = 0x0102_0304;
const AAD: &[u8] = b"record-7";
const PT: &[u8] = b"a secret of thirty-two bytes....";

#[test]
fn constants_describe_the_layout() {
    assert_eq!(ENVELOPE_VERSION, 1);
    assert_eq!(ENVELOPE_HEADER_SIZE, 5);
    assert_eq!(ENVELOPE_OVERHEAD, 5 + 24 + 16);
}

#[test]
fn header_and_body_match_the_reference_crate() {
    let k = key(7);
    let sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    assert_eq!(sealed.len(), PT.len() + 45);
    assert_eq!(&sealed[..5], &[1, 0x01, 0x02, 0x03, 0x04]);

    let mut aad = sealed[..5].to_vec();
    aad.extend_from_slice(AAD);
    let expected = XChaCha20Poly1305::new_from_slice(k.as_bytes())
        .unwrap()
        .encrypt(
            XNonce::from_slice(&sealed[5..29]),
            Payload { msg: PT, aad: &aad },
        )
        .unwrap();
    assert_eq!(&sealed[29..], &expected[..]);
}

#[test]
fn round_trip_and_key_id_peek() {
    let k = key(7);
    let sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    assert_eq!(envelope_key_id(&sealed), Ok(KID));
    assert_eq!(open_envelope(&k, KID, AAD, &sealed).unwrap(), PT);
}

#[test]
fn empty_plaintext_round_trips() {
    let k = key(1);
    let sealed = seal_envelope(&k, 0, b"", b"").unwrap();
    assert_eq!(sealed.len(), ENVELOPE_OVERHEAD);
    assert_eq!(open_envelope(&k, 0, b"", &sealed).unwrap(), b"");
}

#[test]
fn rewriting_the_key_id_in_the_header_does_not_open() {
    // the header is authenticated: an attacker relabelling the blob is caught
    // even when the opener is handed the relabelled id
    let k = key(7);
    let mut sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    sealed[4] ^= 1;
    let relabelled = envelope_key_id(&sealed).unwrap();
    assert_eq!(
        open_envelope(&k, relabelled, AAD, &sealed),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
}

#[test]
fn opening_with_a_different_key_id_is_reported_before_decryption() {
    let k = key(7);
    let sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    assert_eq!(
        open_envelope(&k, KID + 1, AAD, &sealed),
        Err(EnvelopeError::KeyIdMismatch {
            expected: KID + 1,
            found: KID
        })
    );
}

#[test]
fn an_unknown_version_is_rejected() {
    let k = key(7);
    let mut sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    for v in [0u8, 2, 0xff] {
        sealed[0] = v;
        assert_eq!(
            open_envelope(&k, KID, AAD, &sealed),
            Err(EnvelopeError::UnsupportedVersion(v))
        );
        assert_eq!(
            envelope_key_id(&sealed),
            Err(EnvelopeError::UnsupportedVersion(v))
        );
    }
}

#[test]
fn flipping_any_bit_after_the_version_does_not_open() {
    let k = key(7);
    let sealed = seal_envelope(&k, KID, AAD, b"0123456789").unwrap();
    for byte in 1..sealed.len() {
        for bit in 0..8 {
            let mut t = sealed.clone();
            t[byte] ^= 1 << bit;
            let kid = envelope_key_id(&t).unwrap();
            assert_eq!(
                open_envelope(&k, kid, AAD, &t),
                Err(EnvelopeError::Cipher(CipherError::DecryptionFailed)),
                "byte {byte} bit {bit}"
            );
        }
    }
}

#[test]
fn a_different_aad_or_key_does_not_open() {
    let k = key(7);
    let sealed = seal_envelope(&k, KID, AAD, PT).unwrap();
    assert_eq!(
        open_envelope(&k, KID, b"record-8", &sealed),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
    assert_eq!(
        open_envelope(&key(8), KID, AAD, &sealed),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
}

#[test]
fn the_aad_is_not_confused_with_header_bytes() {
    // header || aad is unambiguous because the header has a fixed length:
    // moving a byte between the key id and the aad must not open
    let k = key(7);
    let sealed = seal_envelope(&k, 0x0000_0061, b"b", PT).unwrap();
    let mut forged = sealed.clone();
    forged[1..5].copy_from_slice(&0x0000_0000u32.to_be_bytes());
    assert_eq!(
        open_envelope(&k, 0, b"ab", &forged),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
}

#[test]
fn short_input_is_rejected_without_panicking() {
    let k = key(7);
    for len in 0..ENVELOPE_OVERHEAD {
        let mut v = vec![0u8; len];
        if len > 0 {
            v[0] = ENVELOPE_VERSION;
        }
        assert_eq!(
            open_envelope(&k, 0, b"", &v),
            Err(EnvelopeError::TooShort),
            "len {len}"
        );
        let peek = envelope_key_id(&v);
        if len < ENVELOPE_HEADER_SIZE {
            assert_eq!(peek, Err(EnvelopeError::TooShort), "len {len}");
        } else {
            assert_eq!(peek, Ok(0), "len {len}");
        }
    }
}

#[test]
fn reseal_moves_the_blob_to_the_new_key_and_id() {
    let old = key(7);
    let new = key(9);
    let sealed = seal_envelope(&old, 1, AAD, PT).unwrap();
    let moved = reseal_envelope(&old, 1, &new, 2, AAD, &sealed).unwrap();
    assert_eq!(envelope_key_id(&moved), Ok(2));
    assert_eq!(open_envelope(&new, 2, AAD, &moved).unwrap(), PT);
    assert_eq!(
        open_envelope(&old, 2, AAD, &moved),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
}

#[test]
fn reseal_refuses_a_blob_that_does_not_open() {
    let sealed = seal_envelope(&key(7), 1, AAD, PT).unwrap();
    assert_eq!(
        reseal_envelope(&key(8), 1, &key(9), 2, AAD, &sealed),
        Err(EnvelopeError::Cipher(CipherError::DecryptionFailed))
    );
}
