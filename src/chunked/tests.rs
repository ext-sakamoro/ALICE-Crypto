//! The crate's chunked envelope against the independent reference writer
//! (`tests/data/chunked/chunked_ref.py`, pycryptodome XChaCha20-Poly1305 with
//! the STREAM-BE32 nonce built by hand)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::Key;
use alloc::vec::Vec;

const VECTORS: &str = include_str!("../../tests/data/chunked/vectors.txt");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + 3) % 256) as u8).collect()
}

/// (key, key id, aad, prefix, chunk size) from the header line of the vectors
fn parameters() -> ([u8; 32], u32, Vec<u8>, [u8; 19], u32) {
    let head = VECTORS.lines().next().unwrap();
    let f: Vec<&str> = head.split_whitespace().collect();
    let at = |name: &str| f[f.iter().position(|x| *x == name).unwrap() + 1];
    (
        hex(at("key")).try_into().unwrap(),
        at("key_id").parse().unwrap(),
        hex(at("aad")),
        hex(at("prefix")).try_into().unwrap(),
        at("chunk").parse().unwrap(),
    )
}

/// Seals `pt` chunk by chunk with the core sealer and a fixed nonce prefix
fn seal_with(
    pt: &[u8],
    key: &Key,
    key_id: u32,
    aad: &[u8],
    prefix: [u8; 19],
    chunk: u32,
) -> Vec<u8> {
    let mut s = ChunkSealer::with_prefix(key, key_id, aad, chunk, prefix).unwrap();
    let mut out = s.header().to_vec();
    let size = chunk as usize;
    let mut rest = pt;
    loop {
        let last = rest.len() < size;
        let n = if last { rest.len() } else { size };
        let mut buf = vec![0u8; n + TAG_SIZE];
        buf[..n].copy_from_slice(&rest[..n]);
        let len = s.seal_chunk(&mut buf, n, last).unwrap();
        out.extend_from_slice(&buf[..len]);
        rest = &rest[n..];
        if last {
            break;
        }
    }
    out
}

#[test]
fn the_sealed_bytes_match_the_reference_writer() {
    let (key, key_id, aad, prefix, chunk) = parameters();
    let key = Key::from_bytes(key);
    let mut compared = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let n: usize = f[1].parse().unwrap();
        let want = hex(f[2]);
        let got = seal_with(&plaintext(n), &key, key_id, &aad, prefix, chunk);
        assert_eq!(got, want, "{}: differs from the reference", f[0]);
        compared += 1;
    }
    assert_eq!(compared, 6, "every vector was compared");
}

#[test]
fn the_reference_bytes_open_to_the_plaintext() {
    let (key, key_id, aad, _, _) = parameters();
    let mut compared = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let n: usize = f[1].parse().unwrap();
        let sealed = hex(f[2]);
        let got = open_to_end(
            &sealed[..],
            |id| {
                assert_eq!(id, key_id);
                Ok(Key::from_bytes(key))
            },
            &aad,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(&got[..], &plaintext(n)[..], "{}", f[0]);
        compared += 1;
    }
    assert_eq!(compared, 6);
}
