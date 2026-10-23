//! Oracles for the chunked envelope (`alice_crypto::chunked`)
//!
//! A sealed stream opens only whole, in order and untruncated: cutting it at any
//! chunk boundary (or inside a chunk), swapping or repeating chunks, appending
//! bytes, editing the header or using other associated data are all refused, and
//! `open_to_end` returns no plaintext unless the whole stream verified.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use alice_crypto::chunked::{
    open_to_end, ChunkedError, ChunkedWriter, DEFAULT_CHUNK_SIZE, HEADER_SIZE, MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
};
use alice_crypto::{Key, TAG_SIZE};

const AAD: &[u8] = b"chunked oracle";
const CHUNK: u32 = MIN_CHUNK_SIZE;

fn key() -> Key {
    Key::from_bytes([0x5a; 32])
}

fn plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn seal(pt: &[u8], chunk: u32) -> Vec<u8> {
    let mut w = ChunkedWriter::new(Vec::new(), &key(), 3, AAD, chunk).unwrap();
    // write in uneven pieces so the writer's own chunking is exercised
    for piece in pt.chunks(1000) {
        w.write_all(piece).unwrap();
    }
    w.finish().unwrap()
}

fn open(bytes: &[u8]) -> Result<Vec<u8>, ChunkedError> {
    open_to_end(bytes, |_| Ok(key()), AAD, u64::MAX).map(|v| v.to_vec())
}

/// Byte offsets where each sealed chunk starts (after the header)
fn chunk_starts(sealed: &[u8], chunk: u32) -> Vec<usize> {
    let size = chunk as usize + TAG_SIZE;
    (HEADER_SIZE..sealed.len()).step_by(size).collect()
}

const SIZES: [usize; 7] = [0, 1, 4095, 4096, 4097, 3 * 4096, 10_000];

#[test]
fn every_length_round_trips() {
    for n in SIZES {
        let pt = plaintext(n);
        assert_eq!(open(&seal(&pt, CHUNK)).unwrap(), pt, "length {n}");
    }
    // the default chunk size too
    let pt = plaintext(200_000);
    assert_eq!(open(&seal(&pt, DEFAULT_CHUNK_SIZE)).unwrap(), pt);
}

#[test]
fn the_last_chunk_is_shorter_than_a_full_one() {
    // a length that fills whole chunks ends with an empty last chunk
    for (n, chunks) in [(0usize, 1usize), (4095, 1), (4096, 2), (3 * 4096, 4)] {
        let sealed = seal(&plaintext(n), CHUNK);
        assert_eq!(
            sealed.len(),
            HEADER_SIZE + n + chunks * TAG_SIZE,
            "length {n}"
        );
    }
}

#[test]
fn a_stream_cut_anywhere_does_not_open() {
    let sealed = seal(&plaintext(3 * 4096 + 7), CHUNK);
    let mut cuts: Vec<usize> = chunk_starts(&sealed, CHUNK);
    cuts.extend(chunk_starts(&sealed, CHUNK).iter().map(|s| s + 100));
    cuts.extend([0, 1, HEADER_SIZE - 1, sealed.len() - 1]);
    cuts.retain(|c| *c < sealed.len());
    assert!(cuts.len() >= 9, "{cuts:?}");
    for cut in cuts {
        let r = open(&sealed[..cut]);
        assert!(
            r.is_err(),
            "a stream cut at {cut} of {} opened",
            sealed.len()
        );
    }
}

#[test]
fn swapped_or_repeated_chunks_do_not_open() {
    let sealed = seal(&plaintext(3 * 4096 + 7), CHUNK);
    let size = CHUNK as usize + TAG_SIZE;
    let starts = chunk_starts(&sealed, CHUNK);
    // the three full chunks
    for (a, b) in [(0, 1), (1, 2), (0, 2)] {
        let mut v = sealed.clone();
        let (x, y) = (starts[a], starts[b]);
        let chunk_a = sealed[x..x + size].to_vec();
        let chunk_b = sealed[y..y + size].to_vec();
        v[x..x + size].copy_from_slice(&chunk_b);
        v[y..y + size].copy_from_slice(&chunk_a);
        assert!(open(&v).is_err(), "chunks {a} and {b} swapped");
    }
    // a full chunk repeated in place of the next one
    let mut v = sealed.clone();
    let first = sealed[starts[0]..starts[0] + size].to_vec();
    v[starts[1]..starts[1] + size].copy_from_slice(&first);
    assert!(open(&v).is_err(), "a chunk repeated");
}

#[test]
fn bytes_after_the_last_chunk_are_refused() {
    let sealed = seal(&plaintext(5000), CHUNK);
    let last = *chunk_starts(&sealed, CHUNK).last().unwrap();
    // the last chunk repeated after itself
    let mut v = sealed.clone();
    v.extend_from_slice(&sealed[last..]);
    // the reader finds the last chunk by the end of the input, so the appended bytes join the
    // last chunk and it does not open
    assert!(
        matches!(open(&v), Err(ChunkedError::Tampered { .. })),
        "{:?}",
        open(&v)
    );
    // a single extra byte
    let mut v = sealed.clone();
    v.push(0);
    assert!(open(&v).is_err());
}

#[test]
fn an_edited_header_or_other_associated_data_does_not_open() {
    let sealed = seal(&plaintext(5000), CHUNK);
    // version, key id, chunk size, nonce prefix
    for at in [0usize, 1, 4, 5, 8, 9, 27] {
        let mut v = sealed.clone();
        v[at] ^= 0x01;
        assert!(open(&v).is_err(), "header byte {at} changed");
    }
    let r = open_to_end(&sealed[..], |_| Ok(key()), b"other", u64::MAX);
    assert!(matches!(r, Err(ChunkedError::Tampered { .. })), "{r:?}");
    let r = open_to_end(&sealed[..], |_| Ok(Key::from_bytes([1; 32])), AAD, u64::MAX);
    assert!(matches!(r, Err(ChunkedError::Tampered { .. })), "{r:?}");
}

#[test]
fn the_key_is_chosen_by_the_recorded_key_id() {
    let sealed = seal(&plaintext(10), CHUNK);
    let mut asked = None;
    let r = open_to_end(
        &sealed[..],
        |id| {
            asked = Some(id);
            Ok(key())
        },
        AAD,
        u64::MAX,
    );
    assert!(r.is_ok());
    assert_eq!(asked, Some(3));
}

#[test]
fn a_chunk_size_outside_the_bounds_is_refused_before_reading() {
    for size in [MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, 0, u32::MAX] {
        assert!(
            matches!(
                ChunkedWriter::new(Vec::new(), &key(), 3, AAD, size),
                Err(ChunkedError::ChunkSize(s)) if s == size
            ),
            "writer accepted {size}"
        );
        let mut v = seal(&plaintext(10), CHUNK);
        v[5..9].copy_from_slice(&size.to_be_bytes());
        assert!(
            matches!(open(&v), Err(ChunkedError::ChunkSize(s)) if s == size),
            "reader accepted {size}"
        );
    }
}

#[test]
fn a_stream_longer_than_the_limit_returns_nothing() {
    let sealed = seal(&plaintext(10_000), CHUNK);
    let r = open_to_end(&sealed[..], |_| Ok(key()), AAD, 9_999);
    assert!(matches!(r, Err(ChunkedError::TooLong { .. })), "{r:?}");
    assert!(open_to_end(&sealed[..], |_| Ok(key()), AAD, 10_000).is_ok());
}

#[test]
fn an_unfinished_writer_leaves_a_stream_that_does_not_open() {
    let mut w = ChunkedWriter::new(Vec::new(), &key(), 3, AAD, CHUNK).unwrap();
    w.write_all(&plaintext(9000)).unwrap();
    // only the full chunks reached the inner writer; the last chunk was never written
    let partial = w.into_unfinished();
    assert!(
        matches!(open(&partial), Err(ChunkedError::Truncated)),
        "{:?}",
        open(&partial)
    );
}

#[test]
fn two_streams_of_the_same_plaintext_differ() {
    // the nonce prefix is drawn from the OS for every stream
    let a = seal(&plaintext(100), CHUNK);
    let b = seal(&plaintext(100), CHUNK);
    assert_ne!(a[9..HEADER_SIZE], b[9..HEADER_SIZE]);
    assert_ne!(a, b);
}

#[test]
fn the_core_refuses_chunks_of_the_wrong_length() {
    use alice_crypto::chunked::{ChunkOpener, ChunkSealer};
    let size = CHUNK as usize;
    // each refusal on a fresh sealer / opener: after a refusal they accept nothing more
    let sealer = || ChunkSealer::new(&key(), 3, AAD, CHUNK).unwrap();
    let mut buf = vec![0u8; size + TAG_SIZE];
    // a last chunk is shorter than a full one, any other chunk is exactly full
    assert!(matches!(
        sealer().seal_chunk(&mut buf, size, true),
        Err(ChunkedError::ChunkLength)
    ));
    assert!(matches!(
        sealer().seal_chunk(&mut buf, size - 1, false),
        Err(ChunkedError::ChunkLength)
    ));
    // a buffer without room for the tag
    let mut short = vec![0u8; size];
    assert!(matches!(
        sealer().seal_chunk(&mut short, size, false),
        Err(ChunkedError::ChunkLength)
    ));
    // after the last chunk nothing more is sealed
    let mut s = sealer();
    assert_eq!(s.seal_chunk(&mut buf, 10, true).unwrap(), 10 + TAG_SIZE);
    assert!(matches!(
        s.seal_chunk(&mut buf, 10, true),
        Err(ChunkedError::Finished)
    ));

    let header = *s.header();
    let opener = || ChunkOpener::new(&header, |_| Ok(key()), AAD).unwrap();
    let mut buf = vec![0u8; size + TAG_SIZE];
    assert!(matches!(
        opener().open_chunk(&mut buf, size + TAG_SIZE, true),
        Err(ChunkedError::ChunkLength)
    ));
    assert!(matches!(
        opener().open_chunk(&mut buf, TAG_SIZE - 1, true),
        Err(ChunkedError::ChunkLength)
    ));
    assert!(matches!(
        opener().open_chunk(&mut buf, size, false),
        Err(ChunkedError::ChunkLength)
    ));
}

/// After a chunk fails to open, the reader hands out nothing more: every later
/// read and `finish` return an error (no stale bytes, no panic)
#[test]
fn the_reader_refuses_every_read_after_a_chunk_failed_to_open() {
    use alice_crypto::chunked::UnverifiedChunkedReader;
    use std::io::Read;
    let size = CHUNK as usize;
    let mut sealed = seal(&plaintext(size + 100), CHUNK);
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01; // the short last chunk no longer opens
    let mut r = UnverifiedChunkedReader::new(&sealed[..], |_| Ok(key()), AAD).unwrap();
    let mut out = vec![0u8; size];
    assert_eq!(
        r.read(&mut out).unwrap(),
        size,
        "the first full chunk opens"
    );
    let e = r.read(&mut out).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e:?}");
    for _ in 0..3 {
        let mut probe = vec![0xEE_u8; size + TAG_SIZE];
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.read(&mut probe)));
        let again = again.expect("a read after the failure panicked");
        assert!(
            again.is_err(),
            "a read after the failure returned {again:?}"
        );
        assert!(
            probe.iter().all(|&b| b == 0xEE),
            "bytes were handed out after the failure"
        );
    }
    assert!(matches!(r.finish(), Err(ChunkedError::Failed)));
}

/// An I/O error from the input mid-chunk: later reads return an error instead of
/// treating the buffer's filler as sealed bytes
#[test]
fn the_reader_refuses_every_read_after_an_input_error() {
    use alice_crypto::chunked::UnverifiedChunkedReader;
    use std::io::Read;
    /// Gives `ok` bytes, then one error, then the rest
    struct FailOnce<'a> {
        data: &'a [u8],
        at: usize,
        fail_at: usize,
        failed: bool,
    }
    impl Read for FailOnce<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.failed && self.at >= self.fail_at {
                self.failed = true;
                return Err(std::io::Error::other("injected"));
            }
            let end = if self.failed {
                self.data.len()
            } else {
                self.fail_at
            };
            let n = buf.len().min(end - self.at);
            buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    let size = CHUNK as usize;
    let sealed = seal(&plaintext(3 * size), CHUNK);
    let input = FailOnce {
        data: &sealed,
        at: 0,
        fail_at: HEADER_SIZE + 100,
        failed: false,
    };
    let mut r = UnverifiedChunkedReader::new(input, |_| Ok(key()), AAD).unwrap();
    let mut out = vec![0u8; size];
    let e = r.read(&mut out).unwrap_err();
    assert_eq!(e.to_string().contains("injected"), true, "{e}");
    for _ in 0..2 {
        let mut probe = vec![0xEE_u8; size];
        let again = r.read(&mut probe);
        assert!(
            again.is_err(),
            "a read after the input error returned {again:?}"
        );
        assert!(probe.iter().all(|&b| b == 0xEE));
    }
    assert!(matches!(r.finish(), Err(ChunkedError::Failed)));
}
