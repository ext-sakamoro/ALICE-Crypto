//! Oracle for `seal_with_aad` / `open_with_aad`.
//!
//! Expected values do not come from the code under test:
//! - the known-answer vector is draft-irtf-cfrg-xchacha-03, Appendix A.3.1
//!   (AEAD_XChaCha20_Poly1305 with associated data);
//! - the sealed form is cross-checked against the `chacha20poly1305` crate
//!   called directly with the nonce read from the sealed prefix.

use alice_crypto::{open_with_aad, seal_with_aad, CipherError, Key, Nonce, TAG_SIZE};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// draft-irtf-cfrg-xchacha-03, A.3.1
const KAT_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const KAT_NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
const KAT_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const KAT_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const KAT_CT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                      731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                      2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                      21f9664c97637da9768812f615c68b13b52e";
const KAT_TAG: &str = "c0875924c1c7987947deafd8780acf49";

fn kat_key() -> Key {
    Key::from_bytes(hex(KAT_KEY).try_into().unwrap())
}

fn kat_sealed() -> Vec<u8> {
    let mut v = hex(KAT_NONCE);
    v.extend(hex(KAT_CT));
    v.extend(hex(KAT_TAG));
    v
}

#[test]
fn open_with_aad_reproduces_the_published_vector() {
    let pt = open_with_aad(&kat_key(), &hex(KAT_AAD), &kat_sealed()).unwrap();
    assert_eq!(pt, KAT_PT);
}

#[test]
fn the_vector_is_the_one_the_reference_crate_computes() {
    // guards against a mistyped vector: the reference crate must agree with it
    let cipher = XChaCha20Poly1305::new_from_slice(&hex(KAT_KEY)).unwrap();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&hex(KAT_NONCE)),
            Payload {
                msg: KAT_PT,
                aad: &hex(KAT_AAD),
            },
        )
        .unwrap();
    let mut expected = hex(KAT_CT);
    expected.extend(hex(KAT_TAG));
    assert_eq!(ct, expected);
}

#[test]
fn seal_with_aad_matches_the_reference_crate_under_its_own_nonce() {
    let key = kat_key();
    let aad = b"table\0column\0row-17";
    let pt = b"thirty-two bytes of secret key..";
    let sealed = seal_with_aad(&key, aad, pt).unwrap();
    assert_eq!(sealed.len(), Nonce::SIZE + pt.len() + TAG_SIZE);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
    let expected = cipher
        .encrypt(
            XNonce::from_slice(&sealed[..Nonce::SIZE]),
            Payload { msg: pt, aad },
        )
        .unwrap();
    assert_eq!(&sealed[Nonce::SIZE..], &expected[..]);
    assert_eq!(open_with_aad(&key, aad, &sealed).unwrap(), pt);
}

#[test]
fn two_seals_of_the_same_input_draw_different_nonces() {
    let key = kat_key();
    let a = seal_with_aad(&key, b"aad", b"same").unwrap();
    let b = seal_with_aad(&key, b"aad", b"same").unwrap();
    assert_ne!(a[..Nonce::SIZE], b[..Nonce::SIZE]);
}

#[test]
fn a_different_aad_does_not_open() {
    let key = kat_key();
    let sealed = seal_with_aad(&key, b"row-1", b"secret").unwrap();
    assert_eq!(
        open_with_aad(&key, b"row-2", &sealed),
        Err(CipherError::DecryptionFailed)
    );
    assert_eq!(
        open_with_aad(&key, b"", &sealed),
        Err(CipherError::DecryptionFailed)
    );
}

#[test]
fn flipping_any_single_bit_of_the_sealed_form_does_not_open() {
    let key = kat_key();
    let aad = b"aad";
    let sealed = seal_with_aad(&key, aad, b"0123456789").unwrap();
    for byte in 0..sealed.len() {
        for bit in 0..8 {
            let mut t = sealed.clone();
            t[byte] ^= 1 << bit;
            assert_eq!(
                open_with_aad(&key, aad, &t),
                Err(CipherError::DecryptionFailed),
                "byte {byte} bit {bit}"
            );
        }
    }
}

#[test]
fn flipping_a_bit_of_the_aad_does_not_open() {
    let key = kat_key();
    let aad = hex(KAT_AAD);
    for byte in 0..aad.len() {
        let mut a = aad.clone();
        a[byte] ^= 0x01;
        assert_eq!(
            open_with_aad(&key, &a, &kat_sealed()),
            Err(CipherError::DecryptionFailed)
        );
    }
}

#[test]
fn a_wrong_key_does_not_open() {
    let mut k = hex(KAT_KEY);
    k[0] ^= 1;
    let wrong = Key::from_bytes(k.try_into().unwrap());
    assert_eq!(
        open_with_aad(&wrong, &hex(KAT_AAD), &kat_sealed()),
        Err(CipherError::DecryptionFailed)
    );
}

#[test]
fn empty_plaintext_and_empty_aad_round_trip() {
    let key = kat_key();
    let sealed = seal_with_aad(&key, b"", b"").unwrap();
    assert_eq!(sealed.len(), Nonce::SIZE + TAG_SIZE);
    assert_eq!(open_with_aad(&key, b"", &sealed).unwrap(), b"");
}

#[test]
fn input_shorter_than_nonce_and_tag_is_rejected() {
    let key = kat_key();
    for len in 0..Nonce::SIZE + TAG_SIZE {
        assert_eq!(
            open_with_aad(&key, b"", &vec![0u8; len]),
            Err(CipherError::BufferTooSmall),
            "len {len}"
        );
    }
}

#[test]
fn seal_with_empty_aad_opens_with_plain_open() {
    // empty associated data is the same AEAD computation as `seal` / `open`
    let key = kat_key();
    let sealed = seal_with_aad(&key, b"", b"interop").unwrap();
    assert_eq!(alice_crypto::open(&key, &sealed).unwrap(), b"interop");
    let sealed = alice_crypto::seal(&key, b"interop").unwrap();
    assert_eq!(open_with_aad(&key, b"", &sealed).unwrap(), b"interop");
}
