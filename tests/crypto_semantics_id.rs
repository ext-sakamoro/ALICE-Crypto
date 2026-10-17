//! `CRYPTO_SEMANTICS_ID` is the fold of the recorded-bit goldens of
//! `tests/semantics_golden.rs`.
//!
//! Every digest is read from the golden test that records it, so changing a
//! recorded scenario without re-recording the entry (or the entry without the
//! identifier) fails here, and so does a golden that no entry folds.

use std::collections::BTreeMap;
use std::path::Path;

use alice_crypto::semantics::{CRYPTO_SEMANTICS_CHECKED_AT, CRYPTO_SEMANTICS_PINS};
use alice_crypto::CRYPTO_SEMANTICS_ID;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "a digest is 64 hex digits: {s}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit");
    }
    out
}

/// The fold of `alice-det-math`: names sorted, u32 big-endian name length,
/// name bytes, digest bytes, all under one SHA-256.
fn fold(entries: &[(&str, [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<_> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut h = Sha256::new();
    for (name, digest) in &sorted {
        h.update(u32::try_from(name.len()).expect("short name").to_be_bytes());
        h.update(name.as_bytes());
        h.update(digest);
    }
    h.finalize().into()
}

/// `scenario name -> recorded digest` of every `assert_golden(` call in
/// `tests/semantics_golden.rs`
fn recorded_goldens() -> BTreeMap<String, [u8; 32]> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/semantics_golden.rs");
    let src = std::fs::read_to_string(&path).expect("tests/semantics_golden.rs");
    let mut out = BTreeMap::new();
    let mut rest = src.as_str();
    while let Some(at) = rest.find("assert_golden(") {
        rest = &rest[at + "assert_golden(".len()..];
        let call = &rest[..rest.find(");").expect("call ends")];
        let quoted: Vec<&str> = call.split('"').skip(1).step_by(2).collect();
        if let (Some(name), Some(digest)) = (quoted.first(), quoted.last()) {
            if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.insert((*name).to_string(), unhex32(digest));
            }
        }
    }
    out
}

#[test]
fn the_entries_are_exactly_the_recorded_goldens() {
    let goldens = recorded_goldens();
    assert!(
        goldens.len() >= 5,
        "read {} goldens: the parse lost them",
        goldens.len()
    );
    let pinned: BTreeMap<String, [u8; 32]> = CRYPTO_SEMANTICS_PINS
        .iter()
        .map(|(n, d)| ((*n).to_string(), *d))
        .collect();
    let golden_names: Vec<&String> = goldens.keys().collect();
    let pinned_names: Vec<&String> = pinned.keys().collect();
    assert_eq!(
        golden_names, pinned_names,
        "every golden must be folded, and only goldens"
    );
    for (name, digest) in &goldens {
        assert_eq!(
            hex(digest),
            hex(&pinned[name]),
            "entry {name:?} is not the recorded golden"
        );
    }
}

#[test]
fn the_identifier_is_the_fold_of_the_table() {
    assert_eq!(hex(&fold(CRYPTO_SEMANTICS_PINS)), hex(&CRYPTO_SEMANTICS_ID));
}

#[test]
fn the_identifier_is_the_recorded_value() {
    assert_eq!(
        hex(&CRYPTO_SEMANTICS_ID),
        "65285bfd28e836408ac51c4989a6430b2508f25cf51e4ca30db9f3d36e26acef"
    );
}

#[test]
fn one_changed_bit_in_any_entry_changes_the_identifier() {
    for i in 0..CRYPTO_SEMANTICS_PINS.len() {
        let mut entries = CRYPTO_SEMANTICS_PINS.to_vec();
        entries[i].1[0] ^= 1;
        assert_ne!(
            fold(&entries),
            CRYPTO_SEMANTICS_ID,
            "entry {} does not move the identifier",
            entries[i].0
        );
    }
}

#[test]
fn the_table_and_identifier_are_not_behind_a_cfg() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/semantics.rs");
    let src = std::fs::read_to_string(path).expect("src/semantics.rs");
    assert!(
        !src.contains("#[cfg"),
        "src/semantics.rs must not gate anything behind cfg"
    );
}

/// The pins were checked on this crate version and toolchain: the version in
/// Cargo.toml, the channel of rust-toolchain.toml, and the rustc that runs
/// the test (a toolchain override that bypasses the file is caught too)
#[test]
fn the_pins_were_checked_on_this_version_and_toolchain() {
    assert_eq!(
        CRYPTO_SEMANTICS_CHECKED_AT.0,
        env!("CARGO_PKG_VERSION"),
        "crate version"
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rust-toolchain.toml");
    let toml = std::fs::read_to_string(path).expect("rust-toolchain.toml");
    let channel = toml
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .expect("a channel line")
        .trim_matches('"');
    assert_eq!(CRYPTO_SEMANTICS_CHECKED_AT.1, channel, "toolchain channel");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let out = std::process::Command::new(rustc)
        .arg("-V")
        .output()
        .expect("rustc -V");
    let version = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        version.starts_with(&format!("rustc {} ", CRYPTO_SEMANTICS_CHECKED_AT.1)),
        "running {version:?}, pins checked on {}",
        CRYPTO_SEMANTICS_CHECKED_AT.1
    );
}
