//! Oracle for the recovery code (`alice_crypto::recovery_code`).
//!
//! The text form and the sealed layout are checked against an encoder and an opener written here from the module
//! docs with the `sha2`, `hkdf` and `chacha20poly1305` crates directly, not with the code under test: the check is
//! the first 10 bits of SHA-256(context || entropy), the key HKDF-SHA256(salt, entropy, info), the AEAD
//! XChaCha20-Poly1305 over version || salt || aad. Every refusal test counts what it compared and fails on 0.

use alice_crypto::recovery_code::{
    open_secret, seal_secret, RecoveryCode, RecoveryCodeError, RECOVERY_BLOB_OVERHEAD,
    RECOVERY_BLOB_VERSION, RECOVERY_CODE_CHECK_CONTEXT, RECOVERY_CODE_ENTROPY,
    RECOVERY_CODE_KEY_INFO, RECOVERY_CODE_LEN,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn entropy(seed: u8) -> [u8; RECOVERY_CODE_ENTROPY] {
    core::array::from_fn(|i| {
        seed.wrapping_mul(37)
            .wrapping_add((i as u8).wrapping_mul(101))
    })
}

/// The 28 characters for `e`, from the module docs
fn reference_text(e: &[u8; RECOVERY_CODE_ENTROPY]) -> String {
    let mut h = Sha256::new();
    h.update(RECOVERY_CODE_CHECK_CONTEXT);
    h.update(e);
    let d = h.finalize();
    let check = (u16::from(d[0]) << 2) | u16::from(d[1] >> 6);
    // 128 + 10 + 2 = 140 bits, most significant first
    let mut bits: Vec<bool> = e
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1))
        .collect();
    bits.extend((0..10).rev().map(|i| check >> i & 1 == 1));
    bits.extend([false, false]);
    bits.chunks(5)
        .map(|c| {
            let v = c.iter().fold(0usize, |a, &b| a << 1 | usize::from(b));
            ALPHABET[v] as char
        })
        .collect()
}

fn grouped(text: &str) -> String {
    text.as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Open a blob by the documented layout without the code under test
fn reference_open(e: &[u8; RECOVERY_CODE_ENTROPY], blob: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < RECOVERY_BLOB_OVERHEAD || blob[0] != RECOVERY_BLOB_VERSION {
        return None;
    }
    let salt = &blob[1..17];
    let nonce = XNonce::from_slice(&blob[17..41]);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), e);
    let mut key = [0u8; 32];
    hk.expand(RECOVERY_CODE_KEY_INFO, &mut key)
        .expect("32 bytes");
    let mut ad = blob[..17].to_vec();
    ad.extend_from_slice(aad);
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            nonce,
            Payload {
                msg: &blob[41..],
                aad: &ad,
            },
        )
        .ok()
}

#[test]
fn the_text_is_the_documented_encoding_and_reads_back() {
    let mut compared = 0;
    for seed in 0..=255u8 {
        let e = entropy(seed);
        let want = reference_text(&e);
        assert_eq!(want.len(), RECOVERY_CODE_LEN);
        let code = RecoveryCode::from_entropy(e);
        assert_eq!(code.to_text().as_str(), grouped(&want), "seed {seed}");
        // reading back the grouped text, the bare text, lower case, spaces and the confusable letters
        let loose = grouped(&want)
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        for text in [grouped(&want), want.clone(), loose] {
            let back = RecoveryCode::parse(&text).expect("reads");
            assert_eq!(back.to_text().as_str(), grouped(&want));
            compared += 1;
        }
    }
    assert!(compared > 0, "0 compared");
}

#[test]
fn every_single_character_change_is_refused() {
    let mut compared = 0;
    for seed in [0u8, 1, 77, 200, 255] {
        let text = reference_text(&entropy(seed));
        for pos in 0..RECOVERY_CODE_LEN {
            for &c in ALPHABET.iter() {
                if c == text.as_bytes()[pos] {
                    continue;
                }
                let mut b = text.clone().into_bytes();
                b[pos] = c;
                let t = String::from_utf8(b).expect("ascii");
                assert!(
                    RecoveryCode::parse(&t).is_err(),
                    "seed {seed}: {t} (position {pos}) was read"
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 5 * RECOVERY_CODE_LEN * 31);
}

#[test]
fn malformed_text_is_refused_with_its_reason() {
    let text = reference_text(&entropy(9));
    assert_eq!(
        RecoveryCode::parse(&text[..27]).map(|_| ()),
        Err(RecoveryCodeError::Length)
    );
    assert_eq!(
        RecoveryCode::parse(&format!("{text}0")).map(|_| ()),
        Err(RecoveryCodeError::Length)
    );
    assert_eq!(
        RecoveryCode::parse("").map(|_| ()),
        Err(RecoveryCodeError::Length)
    );
    // U is not in the alphabet (and is not read as anything)
    let mut b = text.clone().into_bytes();
    b[5] = b'U';
    assert_eq!(
        RecoveryCode::parse(core::str::from_utf8(&b).expect("ascii")).map(|_| ()),
        Err(RecoveryCodeError::Character { position: 5 })
    );
    // a padding bit set: the last character carries the 2 padding bits in its low bits
    let mut b = text.into_bytes();
    let last = ALPHABET
        .iter()
        .position(|&c| c == b[27])
        .expect("in alphabet");
    b[27] = ALPHABET[last | 1];
    assert_eq!(
        RecoveryCode::parse(core::str::from_utf8(&b).expect("ascii")).map(|_| ()),
        Err(RecoveryCodeError::Check)
    );
}

#[test]
fn a_sealed_secret_opens_with_its_code_and_by_the_documented_layout() {
    let code = RecoveryCode::from_entropy(entropy(3));
    let secret = b"thirty-two bytes of master seed!";
    let aad = b"bound to this identity";
    let blob = seal_secret(&code, secret, aad).expect("seals");
    assert_eq!(blob.len(), secret.len() + RECOVERY_BLOB_OVERHEAD);
    assert_eq!(
        reference_open(&entropy(3), &blob, aad).as_deref(),
        Some(&secret[..])
    );
    assert_eq!(
        open_secret(&code, &blob, aad).expect("opens").as_slice(),
        secret
    );
    // two seals of the same secret differ (fresh salt and nonce)
    let again = seal_secret(&code, secret, aad).expect("seals");
    assert_ne!(blob, again);
}

#[test]
fn a_wrong_code_a_changed_blob_or_other_aad_does_not_open() {
    let e = entropy(4);
    let code = RecoveryCode::from_entropy(e);
    let secret = [0x5au8; 32];
    let aad = b"identity A";
    let blob = seal_secret(&code, &secret, aad).expect("seals");
    let mut compared = 0;
    // every single bit of the code
    for i in 0..RECOVERY_CODE_ENTROPY * 8 {
        let mut w = e;
        w[i / 8] ^= 1 << (i % 8);
        assert_eq!(
            open_secret(&RecoveryCode::from_entropy(w), &blob, aad).map(|_| ()),
            Err(RecoveryCodeError::Open),
            "code bit {i}"
        );
        compared += 1;
    }
    // every byte of the blob (a flipped version byte is refused as a version)
    for i in 0..blob.len() {
        let mut b = blob.clone();
        b[i] ^= 0x01;
        let want = if i == 0 {
            Err(RecoveryCodeError::UnsupportedVersion(
                RECOVERY_BLOB_VERSION ^ 1,
            ))
        } else {
            Err(RecoveryCodeError::Open)
        };
        assert_eq!(
            open_secret(&code, &b, aad).map(|_| ()),
            want,
            "blob byte {i}"
        );
        compared += 1;
    }
    for other in [&b"identity B"[..], b"", b"identity A "] {
        assert_eq!(
            open_secret(&code, &blob, other).map(|_| ()),
            Err(RecoveryCodeError::Open)
        );
        compared += 1;
    }
    assert_eq!(compared, 128 + blob.len() + 3);
}

#[test]
fn degenerate_inputs_give_their_stated_errors() {
    let code = RecoveryCode::from_entropy(entropy(5));
    assert_eq!(
        seal_secret(&code, b"", b"").map(|_| ()),
        Err(RecoveryCodeError::EmptySecret)
    );
    for len in [0, 1, RECOVERY_BLOB_OVERHEAD - 1, RECOVERY_BLOB_OVERHEAD] {
        let mut b = vec![RECOVERY_BLOB_VERSION; len];
        if len > 0 {
            b[0] = RECOVERY_BLOB_VERSION;
        }
        assert_eq!(
            open_secret(&code, &b, b"").map(|_| ()),
            Err(RecoveryCodeError::Malformed),
            "length {len}"
        );
    }
    // a generated code reads back from its own text and is not the all-zero code
    let g = RecoveryCode::generate().expect("random source");
    let back = RecoveryCode::parse(&g.to_text()).expect("reads");
    assert_eq!(back.to_text(), g.to_text());
    assert_ne!(
        g.to_text().as_str(),
        grouped(&reference_text(&[0u8; RECOVERY_CODE_ENTROPY]))
    );
    assert_eq!(format!("{g:?}"), "RecoveryCode(..)");
}
