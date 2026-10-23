//! No plaintext is left in memory the process gives back while a chunked
//! stream is opened
//!
//! The test binary's allocator scans every block when it is freed, while the
//! check is armed, for a 32-byte marker the plaintext is made of. A block that
//! still holds the marker when freed (a buffer that grew by reallocation and
//! left its old copy behind) is counted; the count must be 0.
#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use alice_crypto::chunked::{open_to_end, ChunkedWriter, MIN_CHUNK_SIZE};
use alice_crypto::Key;

const MARKER: [u8; 32] = *b"plaintext-marker:0123456789abcde";

static ARMED: AtomicBool = AtomicBool::new(false);
static LEAKED: AtomicUsize = AtomicUsize::new(0);
static SCANNED: AtomicUsize = AtomicUsize::new(0);
/// The armed tests run one at a time (the counters are process-wide)
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Scanning;

// SAFETY: every call is passed through to the system allocator unchanged; the
// scan only reads the block being freed, which is valid for `layout.size()`
// bytes until the system allocator takes it back.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && layout.size() >= MARKER.len() {
            // SAFETY: the block is still owned by this call and valid for its size
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            SCANNED.fetch_add(1, Ordering::SeqCst);
            if block.windows(MARKER.len()).any(|w| w == MARKER) {
                LEAKED.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: as above
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Scanning = Scanning;

fn sealed(len: usize) -> (Vec<u8>, [u8; 32]) {
    let key = [9u8; 32];
    let mut w =
        ChunkedWriter::new(Vec::new(), &Key::from_bytes(key), 1, b"aad", MIN_CHUNK_SIZE).unwrap();
    let plain: Vec<u8> = MARKER.iter().copied().cycle().take(len).collect();
    w.write_all(&plain).unwrap();
    (w.finish().unwrap(), key)
}

/// Opens `bytes` with the check armed and returns (blocks holding plaintext, blocks scanned)
fn open_armed(bytes: &[u8], key: [u8; 32]) -> (usize, usize) {
    LEAKED.store(0, Ordering::SeqCst);
    SCANNED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let out = open_to_end(bytes, |_| Ok(Key::from_bytes(key)), b"aad", u64::MAX);
    let ok = out.as_ref().map(|v| v.len()).unwrap_or(0);
    // the returned value is zeroed on drop, so dropping it here is part of the check
    drop(out);
    ARMED.store(false, Ordering::SeqCst);
    assert!(ok > 0, "the stream did not open");
    (
        LEAKED.load(Ordering::SeqCst),
        SCANNED.load(Ordering::SeqCst),
    )
}

#[test]
fn opening_a_stream_frees_no_block_that_holds_plaintext() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // many chunks, so a growing output would reallocate many times
    let (bytes, key) = sealed(64 * MIN_CHUNK_SIZE as usize + 123);
    let (leaked, scanned) = open_armed(&bytes, key);
    assert!(
        scanned > 0,
        "the allocator scanned nothing (the check is not armed)"
    );
    assert_eq!(leaked, 0, "{leaked} freed block(s) still held plaintext");
}

/// The scan itself sees plaintext in a block freed without zeroing (the check
/// has teeth)
#[test]
fn the_scan_sees_plaintext_in_a_block_freed_without_zeroing() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    LEAKED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let v: Vec<u8> = MARKER.repeat(4);
    drop(std::hint::black_box(v));
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(LEAKED.load(Ordering::SeqCst), 1);
}
