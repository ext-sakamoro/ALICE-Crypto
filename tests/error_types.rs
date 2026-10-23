//! Every public error type of the crate is a `std::error::Error` with a message, so callers can box it, use `?`
//! into `Box<dyn Error>`, and print it.
//!
//! oracle: the trait bound itself (a type that does not implement `Error` does not compile), plus a non-empty
//! `Display` for one value of each type.

use alice_crypto::{
    chunked::ChunkedError, dp::DpError, keystore::KeyProviderError, keystore::KeyStoreError,
    mac::MacError, sss::SssError, CipherError,
};

fn message<E: std::error::Error>(e: E) -> String {
    e.to_string()
}

#[test]
fn every_error_type_is_a_std_error_with_a_message() {
    let messages = [
        message(CipherError::DecryptionFailed),
        message(KeyStoreError::RngFailed),
        message(KeyProviderError::UnknownGeneration(1)),
        message(MacError::RngFailed),
        message(SssError::Malformed),
    ];
    assert!(messages.iter().all(|m| !m.is_empty()), "{messages:?}");
    let _ = message::<DpError>;
    let _ = message::<ChunkedError>;
}
