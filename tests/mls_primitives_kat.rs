//! Known-answer tests of the primitives of the MLS ciphersuite 0x0001
//! (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM): SHA-256 against
//! NIST CAVP (FIPS 180-4), HMAC/HKDF-SHA256 against RFC 5869, X25519 against
//! RFC 7748, AES-128-GCM against NIST CAVP, and HPKE base mode against RFC 9180.
//!
//! The vectors are tests/data/mls/*, extracted from their published sources by
//! tests/data/mls/extract.py (each source SHA-256 pinned there); MANIFEST pins
//! each extracted file, and the first test checks it. None of the expected
//! values comes from this crate.

use alice_crypto::{aes_gcm, hpke, sha256, x25519};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mls/");

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DATA}{name}")).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "{s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

/// `key = value` records separated by blank lines (comments start with `#`).
fn records(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut out = vec![BTreeMap::new()];
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if line.is_empty() {
            if !out.last().unwrap().is_empty() {
                out.push(BTreeMap::new());
            }
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        out.last_mut()
            .unwrap()
            .insert(k.trim().to_owned(), v.trim().to_owned());
    }
    out.retain(|r| !r.is_empty());
    out
}

#[test]
fn the_vector_files_are_the_extracted_ones() {
    let manifest = read("MANIFEST");
    let mut n = 0;
    for line in manifest.lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        let got = format!(
            "{:x}",
            Sha256::digest(std::fs::read(format!("{DATA}{name}")).unwrap())
        );
        assert_eq!(got, sum, "{name}");
        n += 1;
    }
    assert_eq!(n, 8);
}

// ---------------------------------------------------------------- SHA-256

#[test]
fn sha256_matches_the_cavp_short_and_long_messages() {
    let mut n = 0;
    for file in ["SHA256ShortMsg.rsp", "SHA256LongMsg.rsp"] {
        for r in records(&read(file)) {
            let Some(len) = r.get("Len") else { continue };
            let len: usize = len.parse().unwrap();
            // a zero-length message is written as one 00 byte
            let msg = if len == 0 { vec![] } else { hex(&r["Msg"]) };
            assert_eq!(msg.len() * 8, len);
            assert_eq!(
                sha256::digest(&msg).to_vec(),
                hex(&r["MD"]),
                "{file} Len {len}"
            );
            n += 1;
        }
    }
    assert_eq!(n, 65 + 64);
}

#[test]
fn sha256_matches_the_cavp_monte_carlo_chain() {
    // SHAVS 6.4: MD0 = MD1 = MD2 = seed; MDi = SHA(MDi-3 || MDi-2 || MDi-1)
    // for i = 3..1002, and the 100 checkpoints are each MD1002 used as the
    // next seed
    let rs = records(&read("SHA256Monte.rsp"));
    let mut seed = hex(&rs[0]["Seed"]);
    let mut n = 0;
    for r in rs.iter().filter(|r| r.contains_key("COUNT")) {
        let (mut a, mut b, mut c) = (seed.clone(), seed.clone(), seed.clone());
        for _ in 3..1003 {
            let m = [a.as_slice(), b.as_slice(), c.as_slice()].concat();
            let d = sha256::digest(&m).to_vec();
            (a, b, c) = (b, c, d);
        }
        assert_eq!(c, hex(&r["MD"]), "COUNT {}", r["COUNT"]);
        seed = c;
        n += 1;
    }
    assert_eq!(n, 100);
}

// ----------------------------------------------------------- HMAC / HKDF

#[test]
fn hkdf_sha256_matches_rfc5869() {
    let rs = records(&read("hkdf_sha256.txt"));
    assert_eq!(rs.len(), 3);
    for r in &rs {
        let prk = sha256::hkdf_extract(&hex(&r["salt"]), &hex(&r["IKM"]));
        assert_eq!(prk.to_vec(), hex(&r["PRK"]));
        let mut okm = vec![0u8; r["L"].parse().unwrap()];
        sha256::hkdf_expand(&prk, &hex(&r["info"]), &mut okm).unwrap();
        assert_eq!(okm, hex(&r["OKM"]));
        // extract is HMAC(salt, IKM), with an empty salt read as 32 zero bytes
        let salt = hex(&r["salt"]);
        let key = if salt.is_empty() { vec![0u8; 32] } else { salt };
        assert_eq!(sha256::hmac(&key, &hex(&r["IKM"])).to_vec(), hex(&r["PRK"]));
    }
}

#[test]
fn hkdf_expand_refuses_more_than_255_blocks() {
    let prk = [7u8; 32];
    let mut ok = vec![0u8; 255 * 32];
    sha256::hkdf_expand(&prk, b"", &mut ok).unwrap();
    let mut too_long = vec![0u8; 255 * 32 + 1];
    assert!(sha256::hkdf_expand(&prk, b"", &mut too_long).is_err());
    assert!(
        too_long.iter().all(|&b| b == 0),
        "nothing is written on error"
    );
}

// ---------------------------------------------------------------- X25519

#[test]
fn x25519_matches_rfc7748() {
    let rs = records(&read("x25519.txt"));
    let mut fixed = 0;
    for r in rs.iter().filter(|r| r.contains_key("scalar")) {
        assert_eq!(
            x25519::x25519(&arr(&r["scalar"]), &arr(&r["u"])),
            arr::<32>(&r["out"])
        );
        fixed += 1;
    }
    assert_eq!(fixed, 2);

    // the iterated function, 1 and 1,000 times (1,000,000 in the ignored test)
    for r in rs.iter().filter(|r| r.contains_key("iterations")) {
        let n: u32 = r["iterations"].parse().unwrap();
        if n > 1000 {
            continue;
        }
        assert_eq!(iterate(n), arr::<32>(&r["k"]), "{n} iterations");
    }

    let dh = rs.iter().find(|r| r.contains_key("shared")).unwrap();
    let (a, b) = (
        arr::<32>(&dh["alice_private"]),
        arr::<32>(&dh["bob_private"]),
    );
    assert_eq!(x25519::public_key(&a), arr::<32>(&dh["alice_public"]));
    assert_eq!(x25519::public_key(&b), arr::<32>(&dh["bob_public"]));
    let k = arr::<32>(&dh["shared"]);
    assert_eq!(
        x25519::diffie_hellman(&a, &arr(&dh["bob_public"])).unwrap(),
        k
    );
    assert_eq!(
        x25519::diffie_hellman(&b, &arr(&dh["alice_public"])).unwrap(),
        k
    );
}

fn iterate(n: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;
    for _ in 0..n {
        let next = x25519::x25519(&k, &u);
        u = k;
        k = next;
    }
    k
}

#[test]
#[ignore = "one million X25519 evaluations; run with --ignored"]
fn x25519_matches_rfc7748_after_a_million_iterations() {
    let rs = records(&read("x25519.txt"));
    let r = rs
        .iter()
        .find(|r| r.get("iterations").map(String::as_str) == Some("1000000"))
        .unwrap();
    assert_eq!(iterate(1_000_000), arr::<32>(&r["k"]));
}

#[test]
fn x25519_diffie_hellman_refuses_an_all_zero_shared_secret() {
    // u = 0 and u = 1 are points of small order: X25519 of them is zero
    // (RFC 7748 section 6.1 allows the check, RFC 9180 section 7.1.4 requires it)
    let sk = [0x42u8; 32];
    let mut one = [0u8; 32];
    one[0] = 1;
    for pk in [[0u8; 32], one] {
        assert_eq!(x25519::x25519(&sk, &pk), [0u8; 32]);
        assert!(x25519::diffie_hellman(&sk, &pk).is_err());
    }
}

// ----------------------------------------------------------- AES-128-GCM

#[test]
fn aes128gcm_seal_matches_the_cavp_encryptions() {
    let mut n = 0;
    for r in records(&read("aes128gcm_encrypt.rsp")) {
        let Some(key) = r.get("Key") else { continue };
        let (key, nonce) = (arr::<16>(key), arr::<12>(&r["IV"]));
        let (pt, aad) = (hex(&r["PT"]), hex(&r["AAD"]));
        let want = [hex(&r["CT"]), hex(&r["Tag"])].concat();
        assert_eq!(
            aes_gcm::seal(&key, &nonce, &aad, &pt),
            want,
            "Count {}",
            r["Count"]
        );
        assert_eq!(aes_gcm::open(&key, &nonce, &aad, &want).unwrap(), pt);
        n += 1;
    }
    assert_eq!(n, 375);
}

#[test]
fn aes128gcm_open_matches_the_cavp_decryptions_and_refuses_the_failures() {
    let (mut opened, mut refused) = (0, 0);
    for r in records(&read("aes128gcm_decrypt.rsp")) {
        let Some(key) = r.get("Key") else { continue };
        let (key, nonce) = (arr::<16>(key), arr::<12>(&r["IV"]));
        let ct = [hex(&r["CT"]), hex(&r["Tag"])].concat();
        let got = aes_gcm::open(&key, &nonce, &hex(&r["AAD"]), &ct);
        if r.contains_key("FAIL") {
            assert!(got.is_err(), "Count {} must fail", r["Count"]);
            refused += 1;
        } else {
            assert_eq!(got.unwrap(), hex(&r["PT"]), "Count {}", r["Count"]);
            opened += 1;
        }
    }
    assert_eq!((opened, refused), (375 - 196, 196));
}

#[test]
fn aes128gcm_open_refuses_input_shorter_than_a_tag() {
    let (key, nonce) = ([1u8; 16], [2u8; 12]);
    for len in 0..16 {
        assert!(
            aes_gcm::open(&key, &nonce, b"", &vec![0u8; len]).is_err(),
            "{len}"
        );
    }
}

// ------------------------------------------------------------------- HPKE

/// The setup record, then the encryptions (in sequence order), then the exports.
struct HpkeVector {
    setup: BTreeMap<String, String>,
    encryptions: Vec<BTreeMap<String, String>>,
    exports: Vec<BTreeMap<String, String>>,
}

fn hpke_vector() -> HpkeVector {
    let mut rs = records(&read("hpke_base_x25519_sha256_aes128gcm.txt")).into_iter();
    let setup = rs.next().unwrap();
    let (mut encryptions, mut exports) = (vec![], vec![]);
    for r in rs {
        if r.contains_key("seq") {
            assert_eq!(r["seq"], encryptions.len().to_string());
            encryptions.extend([r]);
        } else {
            exports.extend([r]);
        }
    }
    HpkeVector {
        setup,
        encryptions,
        exports,
    }
}

#[test]
fn hpke_derive_key_pair_matches_rfc9180() {
    let s = hpke_vector().setup;
    let (sk_e, pk_e) = hpke::derive_key_pair(&hex(&s["ikmE"]));
    assert_eq!(
        (sk_e.to_vec(), pk_e.to_vec()),
        (hex(&s["skEm"]), hex(&s["pkEm"]))
    );
    let (sk_r, pk_r) = hpke::derive_key_pair(&hex(&s["ikmR"]));
    assert_eq!(
        (sk_r.to_vec(), pk_r.to_vec()),
        (hex(&s["skRm"]), hex(&s["pkRm"]))
    );
}

#[test]
fn hpke_base_mode_matches_rfc9180_for_every_encryption_and_export() {
    let v = hpke_vector();
    let s = &v.setup;
    let info = hex(&s["info"]);
    let (mut enc, mut sender) =
        hpke::setup_base_sender_with_ephemeral(&arr(&s["pkRm"]), &info, &arr(&s["skEm"])).unwrap();
    assert_eq!(enc.to_vec(), hex(&s["enc"]));
    let mut receiver = hpke::setup_base_receiver(&arr(&s["enc"]), &arr(&s["skRm"]), &info).unwrap();
    // the vectors are consecutive sequence numbers from 0
    assert_eq!(v.encryptions.len(), 257);
    for (seq, e) in v.encryptions.iter().enumerate() {
        let ct = sender.seal(&hex(&e["aad"]), &hex(&e["pt"])).unwrap();
        assert_eq!(ct, hex(&e["ct"]), "seal {seq}");
        assert_eq!(
            receiver.open(&hex(&e["aad"]), &ct).unwrap(),
            hex(&e["pt"]),
            "open {seq}"
        );
    }
    assert_eq!(v.exports.len(), 3);
    for x in &v.exports {
        let want = hex(&x["exported_value"]);
        let len: usize = x["L"].parse().unwrap();
        assert_eq!(
            sender.export(&hex(&x["exporter_context"]), len).unwrap(),
            want
        );
        assert_eq!(
            receiver.export(&hex(&x["exporter_context"]), len).unwrap(),
            want
        );
    }
    enc[0] ^= 1;
    let mut wrong = hpke::setup_base_receiver(&enc, &arr(&s["skRm"]), &info).unwrap();
    let e = &v.encryptions[0];
    assert!(
        wrong.open(&hex(&e["aad"]), &hex(&e["ct"])).is_err(),
        "another enc opens nothing"
    );
}

#[test]
fn hpke_open_out_of_order_fails_and_a_failed_open_does_not_advance() {
    let v = hpke_vector();
    let s = &v.setup;
    let info = hex(&s["info"]);
    let mut receiver = hpke::setup_base_receiver(&arr(&s["enc"]), &arr(&s["skRm"]), &info).unwrap();
    let (e0, e1) = (&v.encryptions[0], &v.encryptions[1]);
    // message 1 first: the nonce is message 0's, so it does not open
    assert!(receiver.open(&hex(&e1["aad"]), &hex(&e1["ct"])).is_err());
    // and the failure did not consume sequence number 0
    assert_eq!(
        receiver.open(&hex(&e0["aad"]), &hex(&e0["ct"])).unwrap(),
        hex(&e0["pt"])
    );
    assert_eq!(
        receiver.open(&hex(&e1["aad"]), &hex(&e1["ct"])).unwrap(),
        hex(&e1["pt"])
    );
}

#[test]
fn hpke_refuses_a_small_order_recipient_key_and_an_export_beyond_255_blocks() {
    // pkR = 0 makes the DH all zero (RFC 9180 section 7.1.4: abort)
    assert!(hpke::setup_base_sender_with_ephemeral(&[0u8; 32], b"", &[0x42; 32]).is_err());
    let s = hpke_vector().setup;
    let (_, ctx) = hpke::setup_base_sender_with_ephemeral(
        &arr(&s["pkRm"]),
        &hex(&s["info"]),
        &arr(&s["skEm"]),
    )
    .unwrap();
    assert!(ctx.export(b"", 255 * 32).is_ok());
    assert!(ctx.export(b"", 255 * 32 + 1).is_err());
}
