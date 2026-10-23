//! The secrets the MAC and secret sharing hand out are zeroed before their memory is given back: a MAC key, the
//! share bytes of a shard, and the secret `recover` returns.
//!
//! The test binary's allocator scans every block when it is freed, while the check is armed, for a 32-byte marker
//! the secret is made of (the method of `tests/chunked_freed_memory.rs`). A block that still holds the marker when
//! freed is counted; the count must be 0, and at least one block must have been scanned (a scan of nothing proves
//! nothing). Inputs are built before the check is armed and dropped after it is disarmed, so only what the crate
//! frees is read.
#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use alice_crypto::mac::MacKey;
use alice_crypto::sss::{self, Shard};

const MARKER: [u8; 32] = *b"secret-marker:0123456789abcdefgh";

static ARMED: AtomicBool = AtomicBool::new(false);
static LEAKED: AtomicUsize = AtomicUsize::new(0);
static SCANNED: AtomicUsize = AtomicUsize::new(0);
/// The armed tests run one at a time (the counters are process-wide)
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Scanning;

// SAFETY: every call is passed through to the system allocator unchanged; the scan only reads the block being freed,
// which is valid for `layout.size()` bytes until the system allocator takes it back.
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

/// Runs `f` with the check armed and returns (blocks still holding the marker, blocks scanned)
fn armed(f: impl FnOnce()) -> (usize, usize) {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    LEAKED.store(0, Ordering::SeqCst);
    SCANNED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    (
        LEAKED.load(Ordering::SeqCst),
        SCANNED.load(Ordering::SeqCst),
    )
}

#[test]
fn a_mac_key_is_zeroed_when_it_is_dropped() {
    let key = Box::new(MacKey::from_bytes(MARKER));
    let (leaked, scanned) = armed(|| drop(key));
    assert!(scanned > 0, "nothing was scanned");
    assert_eq!(leaked, 0, "the key's bytes were freed as they were");
}

#[test]
fn a_shards_share_is_zeroed_when_it_is_dropped() {
    // a shard whose share bytes are the marker (the byte form: [1][k][x][split id][u32 LE len][y][check])
    let mut body = vec![1u8, 2, 1];
    body.extend_from_slice(&[7u8; 16]);
    body.extend_from_slice(&u32::try_from(MARKER.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&MARKER);
    let check = alice_crypto::hash(&body);
    body.extend_from_slice(&check.as_bytes()[..16]);
    let shard = Shard::from_bytes(&body).unwrap();
    let (leaked, scanned) = armed(|| drop(shard));
    assert!(scanned > 0, "nothing was scanned");
    assert_eq!(leaked, 0, "the share was freed as it was");
    drop(body);
}

#[test]
fn the_recovered_secret_is_zeroed_when_it_is_dropped() {
    let shards = sss::split(&MARKER, 3, 2).unwrap();
    let (leaked, scanned) = armed(|| {
        let secret = sss::recover(&shards[..2]).unwrap();
        assert_eq!(&secret[..], &MARKER[..]);
        drop(secret);
    });
    assert!(scanned > 0, "nothing was scanned");
    assert_eq!(
        leaked, 0,
        "the recovered secret (or a copy made on the way) was freed as it was"
    );
}
