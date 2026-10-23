//! Secret sharing: the shard byte form, and the checks `recover` makes on the shards it is given.
//!
//! oracle: `tests/data/sss/vectors.txt`, written by `tests/data/sss/sss_ref.py`: Shamir's scheme over GF(2^8)
//! (polynomial 0x11B) written from its definition with fixed coefficients, and the shard byte form encoded with a
//! BLAKE3 written from the specification (checked against official hash vectors first). The crate decodes those
//! shards and recovers the secrets the script started from.
//!
//! The byte form, version 1: `[1][threshold k][x][split id, 16 bytes][u32-LE length of y][y][first 16 bytes of
//! BLAKE3(everything before)]`. The split id is drawn at random for each split and is the same in all its shards.
//! The check catches a damaged or mistyped shard; it is not authentication (anyone can make a valid-looking shard).
//!
//! Rules pinned here:
//! - a shard knows its threshold and its split; `recover` refuses fewer shards than the threshold
//!   (`NotEnoughShards`), and shards of different splits, thresholds or lengths (`InvalidShard`), instead of
//!   returning wrong bytes or panicking: two splits with the same threshold and length differ only in the split id
//! - `from_bytes` refuses a wrong version, threshold < 2, x = 0, an empty y, a length that does not match, a bad
//!   check, and trailing or missing bytes (`Malformed`)
//! - `to_bytes` and `from_bytes` round-trip, and the encoding of a split shard decodes to the same shard
//! - `Debug` does not show y

use alice_crypto::sss::{self, Shard, SssError};

const VECTORS: &str = include_str!("data/sss/vectors.txt");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct Case {
    secret: Vec<u8>,
    k: u8,
    split_id: [u8; 16],
    shards: Vec<(u8, Vec<u8>)>,
}

fn cases() -> Vec<Case> {
    let mut out: Vec<Case> = Vec::new();
    for l in VECTORS.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        match f[0] {
            "case" => out.push(Case {
                secret: hex(f[1]),
                k: f[2].parse().unwrap(),
                split_id: hex(f[4]).try_into().unwrap(),
                shards: Vec::new(),
            }),
            "shard" => out
                .last_mut()
                .unwrap()
                .shards
                .push((f[1].parse().unwrap(), hex(f[2]))),
            _ => {}
        }
    }
    assert!(out.len() >= 6 && out.iter().all(|c| !c.shards.is_empty()));
    out
}

fn bad() -> Vec<(String, Vec<u8>)> {
    let out: Vec<_> = VECTORS
        .lines()
        .filter_map(|l| l.strip_prefix("bad "))
        .map(|r| {
            let (reason, h) = r.split_once(' ').unwrap();
            (reason.to_string(), hex(h))
        })
        .collect();
    assert!(out.len() >= 10, "read {} malformed encodings", out.len());
    out
}

fn decode(c: &Case) -> Vec<Shard> {
    c.shards
        .iter()
        .map(|(_, b)| Shard::from_bytes(b).unwrap())
        .collect()
}

#[test]
fn the_reference_shards_decode_and_recover_the_secret() {
    let mut recovered = 0;
    for c in cases() {
        let shards = decode(&c);
        for (s, (x, _)) in shards.iter().zip(&c.shards) {
            assert_eq!((s.x(), s.threshold(), s.len()), (*x, c.k, c.secret.len()));
            assert_eq!(s.split_id(), c.split_id);
        }
        let k = usize::from(c.k);
        assert_eq!(*sss::recover(&shards[..k]).unwrap(), c.secret);
        assert_eq!(
            *sss::recover(&shards[shards.len() - k..]).unwrap(),
            c.secret
        );
        assert_eq!(*sss::recover(&shards).unwrap(), c.secret);
        recovered += 1;
    }
    assert!(recovered >= 6);
}

#[test]
fn the_byte_form_round_trips() {
    for c in cases() {
        for (_, b) in &c.shards {
            assert_eq!(*Shard::from_bytes(b).unwrap().to_bytes().unwrap(), *b);
        }
    }
}

#[test]
fn every_malformed_encoding_is_refused() {
    for (reason, b) in bad() {
        assert_eq!(
            Shard::from_bytes(&b).err(),
            Some(SssError::Malformed),
            "{reason}"
        );
    }
}

#[test]
fn fewer_shards_than_the_threshold_are_refused() {
    let c = &cases()[0];
    assert_eq!(c.k, 3);
    let shards = decode(c);
    assert_eq!(
        sss::recover(&shards[..2]).err(),
        Some(SssError::NotEnoughShards)
    );
}

#[test]
fn shards_of_different_thresholds_or_lengths_are_refused_without_a_panic() {
    let all = cases();
    // same threshold (2), different lengths (32 and 1 bytes): the indexing that used to panic
    let (a, b) = (decode(&all[1]), decode(&all[2]));
    assert_eq!((a[0].threshold(), b[0].threshold()), (2, 2));
    let mixed = [a[0].clone(), b[1].clone()];
    assert_eq!(sss::recover(&mixed).err(), Some(SssError::InvalidShard));
    // different thresholds (3 and 5)
    let (c, d) = (decode(&all[0]), decode(&all[3]));
    let mixed = [c[0].clone(), c[1].clone(), d[2].clone()];
    assert_eq!(sss::recover(&mixed).err(), Some(SssError::InvalidShard));
}

#[test]
fn split_shards_carry_their_threshold_and_survive_the_byte_form() {
    let secret = b"a secret of some length";
    let shards = sss::split(secret, 5, 3).unwrap();
    let again: Vec<Shard> = shards
        .iter()
        .map(|s| Shard::from_bytes(&s.to_bytes().unwrap()).unwrap())
        .collect();
    for (s, t) in shards.iter().zip(&again) {
        assert_eq!((t.x(), t.threshold(), t.len()), (s.x(), 3, secret.len()));
        assert_eq!(t.split_id(), shards[0].split_id());
    }
    assert_eq!(*sss::recover(&again[1..4]).unwrap(), secret.to_vec());
}

#[test]
fn the_debug_form_does_not_show_the_share() {
    let s = &decode(&cases()[0])[0];
    let shown = format!("{s:?}");
    // the share starts 0xf5 0x02 0xc1 0xf7 (245, 2, 193, 247): none of it may be shown
    for b in ["245", "193", "247"] {
        assert!(!shown.contains(b), "{shown}");
    }
}

#[test]
fn the_error_has_a_message() {
    let _: &dyn std::error::Error = &SssError::Malformed;
    for e in [
        SssError::Malformed,
        SssError::InvalidShard,
        SssError::NotEnoughShards,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn two_splits_with_the_same_threshold_and_length_are_not_mixed() {
    // the reference pair: 8-byte secrets, threshold 2, told apart only by the split id
    let all = cases();
    let (a, b) = (decode(&all[4]), decode(&all[5]));
    assert_eq!(
        (a[0].threshold(), a[0].len()),
        (b[0].threshold(), b[0].len())
    );
    assert_eq!(*sss::recover(&a[..2]).unwrap(), all[4].secret);
    let mixed = [a[0].clone(), b[1].clone()];
    assert_eq!(sss::recover(&mixed).err(), Some(SssError::InvalidShard));
}

#[test]
fn shards_of_two_random_splits_are_not_mixed() {
    // the probe: two splits of different 8-byte secrets, threshold 2
    let a = sss::split(b"8 bytes!", 3, 2).unwrap();
    let b = sss::split(b"other 8B", 3, 2).unwrap();
    assert_ne!(a[0].split_id(), b[0].split_id());
    assert_eq!(*sss::recover(&a[..2]).unwrap(), b"8 bytes!".to_vec());
    assert_eq!(
        sss::recover(&[a[0].clone(), b[1].clone()]).err(),
        Some(SssError::InvalidShard)
    );
}

#[test]
fn shards_of_different_thresholds_and_the_same_length_are_refused() {
    let a = sss::split(b"8 bytes!", 3, 2).unwrap();
    let b = sss::split(b"8 bytes!", 3, 3).unwrap();
    assert_eq!((a[0].len(), b[0].len()), (8, 8));
    assert_eq!(
        sss::recover(&[a[0].clone(), a[1].clone(), b[2].clone()]).err(),
        Some(SssError::InvalidShard)
    );
}
