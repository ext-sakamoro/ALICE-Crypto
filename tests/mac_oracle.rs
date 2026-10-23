//! The MAC: a BLAKE3 keyed hash tag over a message, and over a message bound to a context.
//!
//! oracle: `tests/data/mac/vectors.txt`, written by `tests/data/mac/mac_ref.py`, a BLAKE3 written from the
//! specification that first reproduces the official BLAKE3 `keyed_hash` test vectors (the `official` lines,
//! taken from the BLAKE3 repository's test_vectors.json) and then computes the `plain` and `context` lines.
//! None of the expected tags comes from this crate.
//!
//! Rules pinned here:
//! - `mac(key, message)` is BLAKE3 keyed_hash(key, message), 32 bytes
//! - `mac_with_context(key, context, message)` is BLAKE3 keyed_hash(key, u64-LE len(context) || context || message):
//!   the length prefix keeps (context, message) splits apart, so ("ab", "c") and ("a", "bc") give different tags
//! - `verify` / `verify_with_context` accept exactly the tag `mac` / `mac_with_context` give, and reject any other
//! - a key and a tag are read from exactly 32 bytes

use alice_crypto::mac::{self, MacError, MacKey, Tag, TAG_SIZE};

const VECTORS: &str = include_str!("data/mac/vectors.txt");
const KEY: &[u8; 32] = b"whats the Elvish word for friend";

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tag_of(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

/// One line of the vectors file.
struct Vector {
    kind: String,
    context: Vec<u8>,
    message: Vec<u8>,
    tag: [u8; 32],
}

fn vectors() -> Vec<Vector> {
    let rows: Vec<Vector> = VECTORS
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let (context, len, tag) = match f[0] {
                "official" | "plain" => (Vec::new(), f[1], f[2]),
                "context" => (if f[1] == "-" { Vec::new() } else { hex(f[1]) }, f[2], f[3]),
                other => panic!("unknown vector kind {other}"),
            };
            Vector {
                kind: f[0].to_string(),
                context,
                message: pattern(len.parse().unwrap()),
                tag: tag_of(tag),
            }
        })
        .collect();
    assert!(
        rows.iter().filter(|r| r.kind == "official").count() >= 35,
        "the official vectors are read"
    );
    assert!(
        rows.iter().filter(|r| r.kind == "context").count() >= 6,
        "the context vectors are read"
    );
    rows
}

#[test]
fn the_tag_is_the_blake3_keyed_hash() {
    let key = MacKey::from_bytes(*KEY);
    let mut compared = 0;
    for Vector {
        kind,
        message: msg,
        tag: want,
        ..
    } in vectors().into_iter().filter(|r| r.kind != "context")
    {
        assert_eq!(
            *mac::mac(&key, &msg).as_bytes(),
            want,
            "{kind} length {}",
            msg.len()
        );
        assert!(mac::verify(&key, &msg, &Tag::from_bytes(want)));
        compared += 1;
    }
    assert!(compared >= 43, "compared {compared}");
}

#[test]
fn the_context_is_length_prefixed() {
    let key = MacKey::from_bytes(*KEY);
    let mut compared = 0;
    for Vector {
        context: ctx,
        message: msg,
        tag: want,
        ..
    } in vectors().into_iter().filter(|r| r.kind == "context")
    {
        assert_eq!(
            *mac::mac_with_context(&key, &ctx, &msg).as_bytes(),
            want,
            "context {} bytes",
            ctx.len()
        );
        assert!(mac::verify_with_context(
            &key,
            &ctx,
            &msg,
            &Tag::from_bytes(want)
        ));
        compared += 1;
    }
    assert!(compared >= 6);
}

#[test]
fn a_context_split_differently_gives_another_tag() {
    let key = MacKey::from_bytes(*KEY);
    let a = mac::mac_with_context(&key, b"ab", b"c");
    let b = mac::mac_with_context(&key, b"a", b"bc");
    assert_ne!(a, b);
    assert!(!mac::verify_with_context(&key, b"a", b"bc", &a));
}

#[test]
fn any_other_tag_key_or_message_is_rejected() {
    let key = MacKey::from_bytes(*KEY);
    let tag = mac::mac(&key, b"message");
    for i in 0..TAG_SIZE {
        let mut bad = *tag.as_bytes();
        bad[i] ^= 1;
        assert!(
            !mac::verify(&key, b"message", &Tag::from_bytes(bad)),
            "byte {i}"
        );
    }
    assert!(!mac::verify(&key, b"messagE", &tag));
    let mut other = *KEY;
    other[0] ^= 1;
    assert!(!mac::verify(&MacKey::from_bytes(other), b"message", &tag));
}

#[test]
fn keys_and_tags_are_read_from_exactly_32_bytes() {
    assert!(MacKey::from_slice(&[7; 32]).is_ok());
    assert!(Tag::from_slice(&[7; 32]).is_ok());
    for n in [0, 31, 33] {
        assert_eq!(
            MacKey::from_slice(&vec![7; n]).err(),
            Some(MacError::InvalidLength(n))
        );
        assert_eq!(
            Tag::from_slice(&vec![7; n]).err(),
            Some(MacError::InvalidLength(n))
        );
    }
}

#[test]
fn the_debug_form_does_not_show_the_key() {
    let s = format!("{:?}", MacKey::from_bytes([0xAB; 32]));
    assert!(!s.to_lowercase().contains("ab"), "{s}");
}

#[test]
fn a_generated_key_makes_a_working_tag() {
    let key = MacKey::generate().unwrap();
    assert!(mac::verify(&key, b"m", &mac::mac(&key, b"m")));
}

#[test]
fn the_error_has_a_message() {
    let _: &dyn std::error::Error = &MacError::InvalidLength(3);
    assert!(!MacError::InvalidLength(3).to_string().is_empty());
}

/// the old names stay for one release and compute the same tag as `mac` for a plain message
#[test]
#[allow(deprecated)]
fn the_deprecated_signature_names_still_give_the_mac_tag() {
    use alice_crypto::signature::{sign, verify, SigningKey};
    let key = SigningKey::from_bytes(*KEY);
    let old = sign(&key, b"message");
    assert_eq!(
        old.as_bytes(),
        mac::mac(&MacKey::from_bytes(*KEY), b"message").as_bytes()
    );
    assert!(verify(&key.verifying_key(), b"message", &old));
}
