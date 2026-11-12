//! The blanket `KeyOps` over a `KeyProvider` does exactly what calling `stream` and `mac`
//! with the provider's key does: values sealed one way open the other way, a changed value
//! or generation does not open, and the futures of `AsyncKeyOps` are ready at once with the
//! same results.
//!
//! oracle: `stream::seal_with_aad` / `open_with_aad` called directly with the provider's
//! bytes (the functions every store used before `KeyOps`), and for the MAC the published
//! derivation (`hash::derive_key(KEY_OPS_MAC_CONTEXT, key)` then `mac_with_context`).

#![cfg(all(feature = "aead", feature = "hash", feature = "rng"))]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use alice_crypto::key_ops::KEY_OPS_MAC_CONTEXT;
use alice_crypto::mac::{mac_with_context, MacKey};
use alice_crypto::stream::{open_with_aad, seal_with_aad, Key};
use alice_crypto::{
    AsyncKeyOps, KeyGeneration, KeyOps, KeyOpsError, KeyProvider, KeyProviderError,
};

/// Two generations with fixed keys, the second current.
struct Fixed;

const K1: [u8; 32] = [0x11; 32];
const K2: [u8; 32] = [0x22; 32];

impl KeyProvider for Fixed {
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        Ok((2, Key::from_bytes(K2)))
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        match generation {
            1 => Ok(Key::from_bytes(K1)),
            2 => Ok(Key::from_bytes(K2)),
            3 => Err(KeyProviderError::Irrecoverable("removed")),
            g => Err(KeyProviderError::UnknownGeneration(g)),
        }
    }
}

fn now<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the blanket future was not ready at once"),
    }
}

#[test]
fn sealing_through_key_ops_is_sealing_with_the_providers_key() {
    let store = Fixed;
    let aad = b"aad";
    let sealed = KeyOps::seal(&store, 1, aad, b"through key ops").expect("seal");
    assert_eq!(
        open_with_aad(&Key::from_bytes(K1), aad, &sealed).expect("stream opens it"),
        b"through key ops"
    );
    let direct = seal_with_aad(&Key::from_bytes(K2), aad, b"directly").expect("seal");
    assert_eq!(
        KeyOps::open(&store, 2, aad, &direct).expect("key ops opens it"),
        b"directly"
    );
    assert_eq!(
        sealed.len(),
        direct.len() - b"directly".len() + b"through key ops".len()
    );
    assert_eq!(KeyOps::current_generation(&store), Ok(2));
}

#[test]
fn a_changed_value_another_generation_or_a_missing_key_does_not_open() {
    let store = Fixed;
    let sealed = KeyOps::seal(&store, 1, b"aad", b"x").expect("seal");
    let mut changed = sealed.clone();
    *changed.last_mut().expect("tag") ^= 1;
    assert_eq!(
        KeyOps::open(&store, 1, b"aad", &changed),
        Err(KeyOpsError::Open)
    );
    assert_eq!(
        KeyOps::open(&store, 1, b"aaD", &sealed),
        Err(KeyOpsError::Open)
    );
    assert_eq!(
        KeyOps::open(&store, 2, b"aad", &sealed),
        Err(KeyOpsError::Open)
    );
    assert_eq!(
        KeyOps::open(&store, 0, b"aad", &sealed),
        Err(KeyOpsError::Key(KeyProviderError::UnknownGeneration(0)))
    );
    assert_eq!(
        KeyOps::seal(&store, 3, b"aad", b"x"),
        Err(KeyOpsError::Key(KeyProviderError::Irrecoverable("removed")))
    );
}

#[test]
fn the_mac_key_is_derived_and_never_the_sealing_key() {
    let store = Fixed;
    let tag = KeyOps::mac(&store, 1, b"ctx", b"message").expect("mac");
    let derived = MacKey::from_bytes(alice_crypto::hash::derive_key(KEY_OPS_MAC_CONTEXT, &K1));
    assert_eq!(
        &tag,
        mac_with_context(&derived, b"ctx", b"message").as_bytes()
    );
    let reused = MacKey::from_bytes(K1);
    assert_ne!(
        &tag,
        mac_with_context(&reused, b"ctx", b"message").as_bytes()
    );
    assert_ne!(
        tag,
        KeyOps::mac(&store, 2, b"ctx", b"message").expect("mac")
    );
}

#[test]
fn the_async_view_is_ready_at_once_with_the_same_results() {
    let store = Fixed;
    assert_eq!(now(AsyncKeyOps::current_generation(&store)), Ok(2));
    let sealed = now(AsyncKeyOps::seal(&store, 2, b"a", b"async")).expect("seal");
    assert_eq!(
        now(AsyncKeyOps::open(&store, 2, b"a", &sealed)).expect("open"),
        b"async"
    );
    assert_eq!(
        now(AsyncKeyOps::mac(&store, 2, b"c", b"m")),
        KeyOps::mac(&store, 2, b"c", b"m")
    );
    let dynamic: &dyn KeyProvider = &store;
    assert_eq!(KeyOps::current_generation(dynamic), Ok(2));
}
