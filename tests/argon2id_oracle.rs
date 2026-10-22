//! Oracle for `kdf::argon2id` / `kdf::argon2id_with`.
//!
//! The expected tag is the Argon2id test vector of RFC 9106, Section 5.3
//! (m = 32 KiB, t = 3, p = 4, password 32 x 0x01, salt 16 x 0x02,
//! secret 8 x 0x03, associated data 12 x 0x04, tag 32 bytes); it does not
//! come from the code under test.

use alice_crypto::kdf::{argon2id, argon2id_with, Argon2Params, KdfError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const RFC9106_ARGON2ID_TAG: &str =
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

fn rfc_params() -> Argon2Params {
    Argon2Params {
        m_cost_kib: 32,
        t_cost: 3,
        p_lanes: 4,
    }
}

#[test]
fn reproduces_the_rfc9106_argon2id_vector() {
    let mut out = [0u8; 32];
    argon2id_with(
        &[0x01; 32],
        &[0x02; 16],
        &[0x03; 8],
        &[0x04; 12],
        &rfc_params(),
        &mut out,
    )
    .unwrap();
    assert_eq!(out.to_vec(), hex(RFC9106_ARGON2ID_TAG));
}

#[test]
fn each_input_changes_the_tag() {
    let base = |pw: &[u8], salt: &[u8], k: &[u8], x: &[u8], p: &Argon2Params| {
        let mut out = [0u8; 32];
        argon2id_with(pw, salt, k, x, p, &mut out).unwrap();
        out
    };
    let p = rfc_params();
    let reference = base(&[1; 32], &[2; 16], &[3; 8], &[4; 12], &p);
    assert_ne!(base(&[9; 32], &[2; 16], &[3; 8], &[4; 12], &p), reference);
    assert_ne!(base(&[1; 32], &[9; 16], &[3; 8], &[4; 12], &p), reference);
    assert_ne!(base(&[1; 32], &[2; 16], &[9; 8], &[4; 12], &p), reference);
    assert_ne!(base(&[1; 32], &[2; 16], &[3; 8], &[9; 12], &p), reference);
    for q in [
        Argon2Params {
            m_cost_kib: 64,
            ..p
        },
        Argon2Params { t_cost: 4, ..p },
        Argon2Params { p_lanes: 2, ..p },
    ] {
        assert_ne!(base(&[1; 32], &[2; 16], &[3; 8], &[4; 12], &q), reference);
    }
}

#[test]
fn argon2id_is_argon2id_with_empty_secret_and_data() {
    let p = rfc_params();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    argon2id(b"password", &[7; 16], &p, &mut a).unwrap();
    argon2id_with(b"password", &[7; 16], b"", b"", &p, &mut b).unwrap();
    assert_eq!(a, b);
    // and it is deterministic
    let mut c = [0u8; 32];
    argon2id(b"password", &[7; 16], &p, &mut c).unwrap();
    assert_eq!(a, c);
}

#[test]
fn output_length_is_the_requested_length() {
    let p = rfc_params();
    for len in [4usize, 16, 32, 64, 100] {
        let mut out = vec![0u8; len];
        argon2id(b"pw", &[7; 16], &p, &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0), "len {len}");
    }
}

#[test]
fn a_salt_shorter_than_16_bytes_is_rejected() {
    let mut out = [0u8; 32];
    for len in [0usize, 1, 8, 15] {
        assert_eq!(
            argon2id(b"pw", &vec![7; len], &rfc_params(), &mut out),
            Err(KdfError::SaltTooShort),
            "len {len}"
        );
    }
    assert!(argon2id(b"pw", &[7; 16], &rfc_params(), &mut out).is_ok());
}

#[test]
fn degenerate_parameters_are_rejected() {
    let mut out = [0u8; 32];
    let p = rfc_params();
    for bad in [
        Argon2Params { t_cost: 0, ..p },
        Argon2Params { p_lanes: 0, ..p },
        // m must be at least 8 KiB per lane
        Argon2Params {
            m_cost_kib: 31,
            ..p
        },
    ] {
        assert_eq!(
            argon2id(b"pw", &[7; 16], &bad, &mut out),
            Err(KdfError::InvalidParams),
            "{bad:?}"
        );
    }
    let mut short = [0u8; 3];
    assert_eq!(
        argon2id(b"pw", &[7; 16], &p, &mut short),
        Err(KdfError::InvalidOutputLength)
    );
}

#[test]
fn the_presets_are_the_rfc9106_recommendations() {
    assert_eq!(
        Argon2Params::RFC9106_LOW_MEMORY,
        Argon2Params {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_lanes: 4
        }
    );
    assert_eq!(
        Argon2Params::RFC9106_RECOMMENDED,
        Argon2Params {
            m_cost_kib: 2 * 1024 * 1024,
            t_cost: 1,
            p_lanes: 4
        }
    );
}

#[test]
fn params_round_trip_through_their_fixed_encoding() {
    let p = Argon2Params::RFC9106_LOW_MEMORY;
    let b = p.to_bytes();
    assert_eq!(b.len(), 12);
    assert_eq!(&b[..4], &(64u32 * 1024).to_be_bytes());
    assert_eq!(Argon2Params::from_bytes(&b), Ok(p));
    assert_eq!(
        Argon2Params::from_bytes(&b[..11]),
        Err(KdfError::InvalidParams)
    );
}

/// The 2 GiB preset is asserted by its constants above and never executed in
/// CI: this test is ignored so that the default `cargo test` does not allocate
/// 2 GiB (run it by hand with `--ignored` on a machine that has the memory).
#[test]
#[ignore = "allocates 2 GiB (RFC9106_RECOMMENDED); run manually with --ignored"]
fn the_recommended_preset_runs() {
    let mut out = [0u8; 32];
    argon2id(
        b"pw",
        &[7; 16],
        &Argon2Params::RFC9106_RECOMMENDED,
        &mut out,
    )
    .unwrap();
    assert!(out.iter().any(|&b| b != 0));
}

/// Inputs outside the ranges RFC 9106 allows are the caller's error, reported
/// as `InvalidInput`, not as an internal failure. The associated data limit
/// (32 bytes in the wrapped implementation) is the one that can be exercised
/// without allocating gigabytes; the password, salt and secret limits are
/// 2^32 - 1 bytes and map to the same variant.
#[test]
fn an_over_long_associated_data_is_invalid_input() {
    let mut out = [0u8; 32];
    assert!(argon2id_with(b"pw", &[7; 16], b"", &[4; 32], &rfc_params(), &mut out).is_ok());
    assert_eq!(
        argon2id_with(b"pw", &[7; 16], b"", &[4; 33], &rfc_params(), &mut out),
        Err(KdfError::InvalidInput)
    );
}
