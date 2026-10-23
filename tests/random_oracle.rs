//! `random::fill`: OS entropy on every call, an error instead of a fallback.

use alice_crypto::random::{self, RngError};

#[test]
fn two_consecutive_fills_differ() {
    // 2^-256 chance of a false failure for an honest source; a constant or a replayed stream fails
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32], "the buffer was written");
}

#[test]
fn every_byte_of_a_long_buffer_is_written() {
    // 4096 bytes left at 0xA5 with probability (1/256)^k per run of k bytes: a fill that writes only a prefix
    // leaves a long run of the sentinel at the end
    let mut buf = [0xA5u8; 4096];
    random::fill(&mut buf).unwrap();
    assert!(buf[4096 - 64..].iter().any(|&b| b != 0xA5));
    assert!(buf[..64].iter().any(|&b| b != 0xA5));
}

#[test]
fn an_empty_fill_is_ok() {
    random::fill(&mut []).unwrap();
}

#[test]
fn the_error_is_typed_and_says_what_failed() {
    // the OS source cannot be made to fail from a test: pin the type and its message instead
    let fill: fn(&mut [u8]) -> Result<(), RngError> = random::fill;
    let _ = fill;
    let e = RngError::Unavailable;
    assert_eq!(
        e.to_string(),
        "the operating system's random source is unavailable"
    );
    fn is_error<E: std::error::Error>(_: &E) {}
    is_error(&e);
}
