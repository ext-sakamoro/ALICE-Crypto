//! The bounds of the MLS primitives that the known-answer tests do not reach.

use alice_crypto::hpke;

#[test]
fn hpke_export_of_a_length_no_allocation_can_hold_is_an_error() {
    let (sk_r, pk_r) = hpke::derive_key_pair(&[1u8; 32]);
    let (enc, ctx) = hpke::setup_base_sender_with_ephemeral(&pk_r, b"", &[2u8; 32]).unwrap();
    assert_eq!(
        ctx.export(b"", usize::MAX),
        Err(hpke::HpkeError::ExportTooLong(usize::MAX))
    );
    let rx = hpke::setup_base_receiver(&enc, &sk_r, b"").unwrap();
    assert_eq!(
        rx.export(b"", usize::MAX),
        Err(hpke::HpkeError::ExportTooLong(usize::MAX))
    );
}

#[test]
fn hpke_random_sender_round_trips_and_uses_a_fresh_ephemeral_key() {
    let (sk_r, pk_r) = hpke::derive_key_pair(&[3u8; 32]);
    let (enc1, mut tx) = hpke::setup_base_sender(&pk_r, b"info").unwrap();
    let (enc2, _) = hpke::setup_base_sender(&pk_r, b"info").unwrap();
    assert_ne!(enc1, enc2, "each setup draws a new ephemeral key");
    let mut rx = hpke::setup_base_receiver(&enc1, &sk_r, b"info").unwrap();
    let ct = tx.seal(b"aad", b"message").unwrap();
    assert_eq!(rx.open(b"aad", &ct).unwrap(), b"message");
    assert_eq!(tx.export(b"x", 42).unwrap(), rx.export(b"x", 42).unwrap());
}

#[test]
fn hpke_context_debug_does_not_show_the_secrets() {
    let (_, pk_r) = hpke::derive_key_pair(&[4u8; 32]);
    let (_, ctx) = hpke::setup_base_sender_with_ephemeral(&pk_r, b"", &[5u8; 32]).unwrap();
    let s = format!("{ctx:?}");
    assert_eq!(s, "Context { seq: 0, .. }");
}
