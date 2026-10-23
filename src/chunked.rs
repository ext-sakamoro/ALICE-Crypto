//! Sealing a value in fixed-size chunks (STREAM over XChaCha20-Poly1305)
//!
//! [`crate::envelope`] seals a value in one piece, so sealing or opening it needs
//! the whole value in memory. This module seals it chunk by chunk with the STREAM
//! construction of Hoang, Reyhanitabar, Rogaway and Vizár ("Online
//! Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", 2015), the
//! `StreamBE32` variant of the `aead` crate: every chunk is sealed with
//! XChaCha20-Poly1305 under the nonce `prefix ‖ counter ‖ last-flag`, so a chunk
//! moved to another position, repeated, or a stream cut short or extended does
//! not open.
//!
//! # Layout
//!
//! | bytes | content |
//! |---|---|
//! | 1 | [`CHUNKED_VERSION`] (`0x81`, distinct from the envelope's version byte) |
//! | 4 | key id, big-endian (chosen by the caller, as in the envelope) |
//! | 4 | chunk size, big-endian ([`MIN_CHUNK_SIZE`]..=[`MAX_CHUNK_SIZE`]) |
//! | 19 | nonce prefix, drawn from the operating system for every stream |
//! | … | the chunks |
//!
//! Every chunk but the last holds exactly the chunk size of plaintext; the last
//! holds less (possibly nothing), so a value whose length is a multiple of the
//! chunk size ends with an empty last chunk. Each sealed chunk is its ciphertext
//! followed by a [`TAG_SIZE`]-byte tag. The associated data of every chunk is the
//! 28-byte header followed by the caller's associated data, so an edited header
//! does not open. The counter is a `u32`: at most `2^32` chunks.
//!
//! # Reading
//!
//! The reader knows which chunk is the last one only when the input ends: a
//! chunk shorter than a full one must be the last, and an input that ends right
//! after a full chunk was cut short. ⚠️ A streaming reader hands out plaintext
//! before it has seen the last chunk, so that plaintext is **not yet verified**:
//! the stream may still turn out to be truncated. [`UnverifiedChunkedReader`]
//! says so in its name, and only [`UnverifiedChunkedReader::finish`] returning
//! `Ok` confirms the whole stream. [`open_to_end`] returns nothing until the
//! whole stream verified.
//!
//! The core ([`ChunkSealer`] / [`ChunkOpener`]) works on caller-provided buffers
//! and needs no `std`; the `std` adapters wrap it around `Write` / `Read`.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn main() -> Result<(), alice_crypto::chunked::ChunkedError> {
//! use std::io::Write;
//! use alice_crypto::chunked::{open_to_end, ChunkedWriter, DEFAULT_CHUNK_SIZE};
//! use alice_crypto::Key;
//!
//! let key = Key::from_bytes([7; 32]);
//! let mut w = ChunkedWriter::new(Vec::new(), &key, 1, b"backup", DEFAULT_CHUNK_SIZE)?;
//! w.write_all(b"a value too large to hold twice in memory")?;
//! let sealed = w.finish()?; // writes the last chunk; an unfinished stream does not open
//! let plain = open_to_end(&sealed[..], |_id| Ok(key.clone()), b"backup", 1 << 30)?;
//! assert_eq!(&plain[..], b"a value too large to hold twice in memory");
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::stream::{NewStream, StreamBE32, StreamPrimitive};
use chacha20poly1305::aead::{Buffer, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

use crate::stream::{Key, TAG_SIZE};

/// First byte of a chunked stream
pub const CHUNKED_VERSION: u8 = 0x81;
/// Length of the nonce prefix (the AEAD's 24-byte nonce minus the 4-byte
/// counter and the 1-byte last-flag)
pub const NONCE_PREFIX_SIZE: usize = 19;
/// Length of the header in front of the chunks
pub const HEADER_SIZE: usize = 1 + 4 + 4 + NONCE_PREFIX_SIZE;
/// Smallest chunk size a stream may use (and a reader accepts)
pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
/// Largest chunk size a stream may use (a reader refuses a larger one before
/// allocating its buffer)
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// The chunk size to use unless there is a reason not to
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// Why a chunked stream could not be sealed or opened
#[derive(Debug)]
#[non_exhaustive]
pub enum ChunkedError {
    /// The first byte is not [`CHUNKED_VERSION`]
    Version(u8),
    /// The chunk size is outside [`MIN_CHUNK_SIZE`]..=[`MAX_CHUNK_SIZE`]
    ChunkSize(u32),
    /// The input ended inside the header
    Header,
    /// The caller could not supply the key for the recorded key id
    Key,
    /// A chunk did not open (wrong key or associated data, edited, moved,
    /// repeated, or bytes appended after the last chunk)
    Tampered {
        /// Position of the chunk that did not open
        chunk: u32,
    },
    /// The stream ended without its last chunk
    Truncated,
    /// The plaintext is longer than the caller's limit
    TooLong {
        /// The limit
        limit: u64,
    },
    /// More than `2^32` chunks
    TooManyChunks,
    /// A chunk passed to the core has the wrong length or its buffer is too small
    ChunkLength,
    /// The stream already ended (the last chunk was sealed or opened)
    Finished,
    /// An earlier call on this sealer or opener failed: it accepts nothing more
    /// (a sealer retried at the same position would repeat the keystream)
    Failed,
    /// The operating system's entropy source failed
    Rng,
    /// Reading or writing the underlying stream failed
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl fmt::Display for ChunkedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version(v) => write!(f, "not a chunked stream (version byte {v:#04x})"),
            Self::ChunkSize(s) => write!(
                f,
                "chunk size {s} outside {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}"
            ),
            Self::Header => write!(f, "the stream ended inside its header"),
            Self::Key => write!(f, "no key for the stream's key id"),
            Self::Tampered { chunk } => write!(f, "chunk {chunk} does not open"),
            Self::Truncated => write!(f, "the stream ended without its last chunk"),
            Self::TooLong { limit } => write!(f, "the plaintext is longer than {limit} bytes"),
            Self::TooManyChunks => write!(f, "more than 2^32 chunks"),
            Self::Failed => write!(f, "an earlier call failed, the stream accepts nothing more"),
            Self::ChunkLength => write!(f, "a chunk has the wrong length"),
            Self::Finished => write!(f, "the stream already ended"),
            Self::Rng => write!(f, "the operating system's entropy source failed"),
            #[cfg(feature = "std")]
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChunkedError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for ChunkedError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = core::result::Result<T, ChunkedError>;

fn check_chunk_size(size: u32) -> Result<()> {
    if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) {
        Ok(())
    } else {
        Err(ChunkedError::ChunkSize(size))
    }
}

fn header(key_id: u32, chunk_size: u32, prefix: &[u8; NONCE_PREFIX_SIZE]) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0] = CHUNKED_VERSION;
    h[1..5].copy_from_slice(&key_id.to_be_bytes());
    h[5..9].copy_from_slice(&chunk_size.to_be_bytes());
    h[9..].copy_from_slice(prefix);
    h
}

fn stream(key: &Key, prefix: &[u8; NONCE_PREFIX_SIZE]) -> StreamBE32<XChaCha20Poly1305> {
    let aead = XChaCha20Poly1305::new(key.as_bytes().into());
    StreamBE32::from_aead(aead, prefix.into())
}

/// A caller buffer seen as an `aead::Buffer` (no allocation)
struct SliceBuffer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl AsRef<[u8]> for SliceBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl AsMut<[u8]> for SliceBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl Buffer for SliceBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        let end = self.len + other.len();
        if end > self.buf.len() {
            return Err(chacha20poly1305::aead::Error);
        }
        self.buf[self.len..end].copy_from_slice(other);
        self.len = end;
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

/// Seals a stream chunk by chunk into caller buffers (no `std`)
pub struct ChunkSealer {
    stream: StreamBE32<XChaCha20Poly1305>,
    header: [u8; HEADER_SIZE],
    aad: Vec<u8>,
    chunk_size: u32,
    next: u32,
    finished: bool,
    failed: bool,
}

impl ChunkSealer {
    /// A sealer with a nonce prefix drawn from the operating system.
    ///
    /// `aad` is bound to every chunk (after the header).
    ///
    /// # Errors
    ///
    /// [`ChunkedError::ChunkSize`] outside the bounds, [`ChunkedError::Rng`]
    /// when the entropy source fails.
    #[expect(
        clippy::disallowed_methods,
        reason = "secret material generation, not Law output: the nonce prefix must be unpredictable and fresh for every stream"
    )]
    pub fn new(key: &Key, key_id: u32, aad: &[u8], chunk_size: u32) -> Result<Self> {
        let mut prefix = [0u8; NONCE_PREFIX_SIZE];
        getrandom::getrandom(&mut prefix).map_err(|_| ChunkedError::Rng)?;
        Self::with_prefix(key, key_id, aad, chunk_size, prefix)
    }

    /// A sealer with a given nonce prefix (only for comparing with reference
    /// vectors: a prefix used twice under one key repeats the keystream)
    pub(crate) fn with_prefix(
        key: &Key,
        key_id: u32,
        aad: &[u8],
        chunk_size: u32,
        prefix: [u8; NONCE_PREFIX_SIZE],
    ) -> Result<Self> {
        check_chunk_size(chunk_size)?;
        let header = header(key_id, chunk_size, &prefix);
        let mut full = Vec::with_capacity(HEADER_SIZE + aad.len());
        full.extend_from_slice(&header);
        full.extend_from_slice(aad);
        Ok(Self {
            stream: stream(key, &prefix),
            header,
            aad: full,
            chunk_size,
            next: 0,
            finished: false,
            failed: false,
        })
    }

    /// The header to write in front of the chunks
    #[must_use]
    pub const fn header(&self) -> &[u8; HEADER_SIZE] {
        &self.header
    }

    /// The chunk size
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Seals the `len` plaintext bytes at the start of `buf` in place and returns
    /// the sealed length (`len + TAG_SIZE`). A chunk that is not the last must
    /// hold exactly the chunk size; the last must hold less. `buf` needs
    /// `TAG_SIZE` spare bytes after the plaintext.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::ChunkLength`], [`ChunkedError::Finished`] after the last
    /// chunk, [`ChunkedError::TooManyChunks`] for a chunk that is not the last at
    /// position `u32::MAX` (refused before anything is sealed: the last chunk
    /// needs a position of its own), and [`ChunkedError::Failed`] for every call
    /// after a call that failed (nothing is sealed).
    pub fn seal_chunk(&mut self, buf: &mut [u8], len: usize, last: bool) -> Result<usize> {
        if self.failed {
            return Err(ChunkedError::Failed);
        }
        let r = self.seal_once(buf, len, last);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn seal_once(&mut self, buf: &mut [u8], len: usize, last: bool) -> Result<usize> {
        if self.finished {
            return Err(ChunkedError::Finished);
        }
        if !last && self.next == u32::MAX {
            return Err(ChunkedError::TooManyChunks);
        }
        let size = self.chunk_size as usize;
        let right_length = if last { len < size } else { len == size };
        if !right_length || buf.len() < len + TAG_SIZE {
            return Err(ChunkedError::ChunkLength);
        }
        let position = self.next;
        let mut b = SliceBuffer { buf, len };
        self.stream
            .encrypt_in_place(position, last, &self.aad, &mut b)
            .map_err(|_| ChunkedError::ChunkLength)?;
        if last {
            self.finished = true;
        } else {
            // below u32::MAX: checked before sealing
            self.next += 1;
        }
        Ok(len + TAG_SIZE)
    }
}

/// Opens a stream chunk by chunk in caller buffers (no `std`)
pub struct ChunkOpener {
    stream: StreamBE32<XChaCha20Poly1305>,
    aad: Vec<u8>,
    chunk_size: u32,
    next: u32,
    finished: bool,
    failed: bool,
}

impl ChunkOpener {
    /// Reads the header and asks `key_for_id` for the key of the recorded key id.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::Version`], [`ChunkedError::ChunkSize`] (checked before
    /// anything is allocated for the chunks), [`ChunkedError::Key`] or the
    /// error `key_for_id` returns.
    pub fn new(
        header: &[u8; HEADER_SIZE],
        key_for_id: impl FnOnce(u32) -> Result<Key>,
        aad: &[u8],
    ) -> Result<Self> {
        if header[0] != CHUNKED_VERSION {
            return Err(ChunkedError::Version(header[0]));
        }
        let key_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let chunk_size = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        check_chunk_size(chunk_size)?;
        let mut prefix = [0u8; NONCE_PREFIX_SIZE];
        prefix.copy_from_slice(&header[9..]);
        let key = key_for_id(key_id)?;
        let mut full = Vec::with_capacity(HEADER_SIZE + aad.len());
        full.extend_from_slice(header);
        full.extend_from_slice(aad);
        Ok(Self {
            stream: stream(&key, &prefix),
            aad: full,
            chunk_size,
            next: 0,
            finished: false,
            failed: false,
        })
    }

    /// The chunk size recorded in the header
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Whether the last chunk has been opened (the whole stream verified)
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Opens the `len` sealed bytes at the start of `buf` in place and returns
    /// the plaintext length. A chunk that is not the last is exactly
    /// `chunk size + TAG_SIZE` long; the last is shorter.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::ChunkLength`], [`ChunkedError::Tampered`],
    /// [`ChunkedError::Finished`] after the last chunk,
    /// [`ChunkedError::TooManyChunks`] for a chunk that is not the last at
    /// position `u32::MAX` (refused before anything is decrypted), and
    /// [`ChunkedError::Failed`] for every call after a call that failed.
    pub fn open_chunk(&mut self, buf: &mut [u8], len: usize, last: bool) -> Result<usize> {
        if self.failed {
            return Err(ChunkedError::Failed);
        }
        let r = self.open_once(buf, len, last);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn open_once(&mut self, buf: &mut [u8], len: usize, last: bool) -> Result<usize> {
        if self.finished {
            return Err(ChunkedError::Finished);
        }
        if !last && self.next == u32::MAX {
            return Err(ChunkedError::TooManyChunks);
        }
        let full = self.chunk_size as usize + TAG_SIZE;
        let right_length = if last {
            (TAG_SIZE..full).contains(&len)
        } else {
            len == full
        };
        if !right_length || buf.len() < len {
            return Err(ChunkedError::ChunkLength);
        }
        let position = self.next;
        let mut b = SliceBuffer { buf, len };
        self.stream
            .decrypt_in_place(position, last, &self.aad, &mut b)
            .map_err(|_| ChunkedError::Tampered { chunk: position })?;
        if last {
            self.finished = true;
        } else {
            // below u32::MAX: checked before opening
            self.next += 1;
        }
        Ok(len - TAG_SIZE)
    }
}

#[cfg(feature = "std")]
mod io;
#[cfg(feature = "std")]
pub use io::{open_to_end, ChunkedWriter, UnverifiedChunkedReader};

#[cfg(test)]
mod tests;
