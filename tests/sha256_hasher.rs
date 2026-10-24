//! `sha256::Hasher` gives the same digest as `sha256::digest` however the input is split
//!
//! The expected digests are the NIST CAVP short and long messages (tests/data/mls/,
//! pinned by tests/mls_primitives_kat.rs); each message is fed whole, one byte at a
//! time, and in chunks of several sizes, and the hasher is reused after `reset`

use alice_crypto::sha256;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mls/");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// (message, expected digest) from the CAVP response files
fn vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for file in ["SHA256ShortMsg.rsp", "SHA256LongMsg.rsp"] {
        let text = std::fs::read_to_string(format!("{DATA}{file}")).unwrap();
        let (mut len, mut msg) = (None, None);
        for line in text.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("Len = ") {
                len = Some(v.parse::<usize>().unwrap());
            } else if let Some(v) = line.strip_prefix("Msg = ") {
                msg = Some(if len == Some(0) { Vec::new() } else { hex(v) });
            } else if let Some(v) = line.strip_prefix("MD = ") {
                out.extend([(msg.take().unwrap(), hex(v))]);
            }
        }
    }
    out
}

#[test]
fn every_split_of_a_cavp_message_gives_its_digest() {
    let vectors = vectors();
    // 65 short + 64 long messages
    assert_eq!(vectors.len(), 129);
    let mut hasher = sha256::Hasher::new();
    for (msg, md) in &vectors {
        for chunk in [1, 3, 63, 64, 65, 1000, usize::MAX] {
            hasher.reset();
            for part in msg.chunks(chunk.min(msg.len().max(1))) {
                hasher.update(part);
            }
            assert_eq!(
                hasher.finalize().to_vec(),
                *md,
                "chunk {chunk}, {} bytes",
                msg.len()
            );
        }
        assert_eq!(sha256::digest(msg).to_vec(), *md);
    }
}

#[test]
fn finalize_does_not_consume_the_state() {
    let mut hasher = sha256::Hasher::default();
    hasher.update(b"ab");
    let first = hasher.finalize();
    assert_eq!(first, hasher.finalize());
    hasher.update(b"c");
    assert_eq!(hasher.finalize(), sha256::digest(b"abc"));
    assert_ne!(first, hasher.finalize());
}

#[test]
fn an_empty_hasher_is_the_digest_of_nothing() {
    assert_eq!(sha256::Hasher::new().finalize(), sha256::digest(b""));
}
