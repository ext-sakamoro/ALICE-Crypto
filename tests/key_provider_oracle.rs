//! The key provider: a store of 32-byte keys by generation, the shape every key store (in memory, an OS keychain,
//! a foreign callback) implements so that sealing code asks for "the current key" and "the key of generation g"
//! without knowing where keys live.
//!
//! oracle: the keys are bytes the test inserts itself (`KeyStore::insert`), so every expected key is a literal;
//! the generation of a `KeyStore` key is its id (`KeyId`, from 1, never reused), the same 32-bit key id an
//! envelope header carries.
//!
//! Rules pinned here:
//! - `current` is the active key, unexpired and unrevoked at the view's time; otherwise `Unavailable`
//! - `by_generation` opens older data: an expired key is still returned, a revoked one is refused
//!   (`Irrecoverable`), a generation that never existed (and 0, never a generation) is `UnknownGeneration`
//! - a key id that does not fit 32 bits is never handed out as a generation

use alice_crypto::keystore::{KeyGeneration, KeyProvider, KeyProviderError, KeyStore};

const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];

fn two_keys() -> KeyStore {
    let mut s = KeyStore::new();
    s.insert(A, 100); // id 1
    s.insert(B, 200); // id 2, now the active key
    s
}

#[test]
fn current_is_the_active_key_with_its_id_as_the_generation() {
    let s = two_keys();
    let p = s.provider_at(300);
    let (g, k) = p.current().unwrap();
    assert_eq!((g, *k.as_bytes()), (2, B));
}

#[test]
fn an_older_generation_returns_its_own_bytes() {
    let s = two_keys();
    let p = s.provider_at(300);
    assert_eq!(*p.by_generation(1).unwrap().as_bytes(), A);
    assert_eq!(*p.by_generation(2).unwrap().as_bytes(), B);
}

#[test]
fn zero_and_a_missing_generation_are_unknown() {
    let s = two_keys();
    let p = s.provider_at(300);
    assert_eq!(
        p.by_generation(0).err(),
        Some(KeyProviderError::UnknownGeneration(0))
    );
    assert_eq!(
        p.by_generation(9).err(),
        Some(KeyProviderError::UnknownGeneration(9))
    );
}

#[test]
fn a_revoked_key_is_refused_and_is_not_current() {
    let mut s = two_keys();
    assert!(s.revoke(1));
    assert!(matches!(
        s.provider_at(300).by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert!(s.revoke(2));
    assert!(matches!(
        s.provider_at(300).current(),
        Err(KeyProviderError::Unavailable(_))
    ));
}

#[test]
fn an_expired_key_still_opens_old_data_but_is_not_current() {
    let mut s = KeyStore::new().with_default_ttl(50);
    s.insert(A, 100); // id 1, expires at 150
    assert_eq!(s.provider_at(149).current().unwrap().0, 1);
    assert!(matches!(
        s.provider_at(150).current(),
        Err(KeyProviderError::Unavailable(_))
    ));
    assert_eq!(*s.provider_at(150).by_generation(1).unwrap().as_bytes(), A);
}

#[test]
fn an_empty_store_has_no_current_key() {
    let s = KeyStore::new();
    assert!(matches!(
        s.provider_at(0).current(),
        Err(KeyProviderError::Unavailable(_))
    ));
}

#[test]
fn rotation_moves_current_and_keeps_the_previous_generation() {
    let mut s = KeyStore::new();
    s.insert(A, 100);
    let id = s.rotate(200).unwrap();
    let p = s.provider_at(300);
    let (g, _) = p.current().unwrap();
    assert_eq!(KeyGeneration::try_from(id).unwrap(), g);
    assert_eq!(*p.by_generation(1).unwrap().as_bytes(), A);
}

#[test]
fn the_provider_is_usable_as_a_shared_trait_object() {
    fn first_byte(p: &(dyn KeyProvider + Send + Sync)) -> u8 {
        p.current().unwrap().1.as_bytes()[0]
    }
    let s = two_keys();
    assert_eq!(first_byte(&s.provider_at(300)), 0xB2);
}

#[test]
fn the_error_is_a_copyable_value_with_a_message() {
    let e = KeyProviderError::Unavailable("locked");
    let f = e; // Copy
    assert_eq!(e, f);
    for e in [
        KeyProviderError::UnknownGeneration(3),
        KeyProviderError::Unavailable("locked"),
        KeyProviderError::Irrecoverable("gone"),
    ] {
        assert!(!e.to_string().is_empty());
    }
    let _: &dyn std::error::Error = &KeyProviderError::Irrecoverable("gone");
}

#[test]
fn a_purged_key_is_irrecoverable_not_unknown() {
    // the generation existed: removing it does not make it a generation that never was
    let mut s = KeyStore::new().with_default_ttl(50);
    s.insert(A, 100); // id 1, expires at 150
    s.insert(B, 120); // id 2, expires at 170
    assert_eq!(s.purge_expired(160), 1);
    assert!(matches!(
        s.provider_at(160).by_generation(1),
        Err(KeyProviderError::Irrecoverable(_))
    ));
    assert_eq!(*s.provider_at(160).by_generation(2).unwrap().as_bytes(), B);
    assert_eq!(
        s.provider_at(160).by_generation(3).err(),
        Some(KeyProviderError::UnknownGeneration(3))
    );
}
