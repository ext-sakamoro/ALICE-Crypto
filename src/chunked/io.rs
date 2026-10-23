//! `std` adapters: a `Write` that seals and a `Read` that opens

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use super::{ChunkOpener, ChunkSealer, ChunkedError, Result, HEADER_SIZE};
use crate::stream::{Key, TAG_SIZE};

/// Seals what is written to it into `inner`, one chunk at a time.
///
/// Call [`ChunkedWriter::finish`] to write the last chunk: a stream whose
/// writer was dropped (or abandoned with [`ChunkedWriter::into_unfinished`])
/// has no last chunk and does not open.
pub struct ChunkedWriter<W: Write> {
    inner: W,
    sealer: ChunkSealer,
    buf: Zeroizing<Vec<u8>>,
    filled: usize,
}

impl<W: Write> ChunkedWriter<W> {
    /// Writes the header to `inner` and returns the writer.
    ///
    /// # Errors
    ///
    /// As [`ChunkSealer::new`], and [`ChunkedError::Io`] when the header cannot be written.
    pub fn new(mut inner: W, key: &Key, key_id: u32, aad: &[u8], chunk_size: u32) -> Result<Self> {
        let sealer = ChunkSealer::new(key, key_id, aad, chunk_size)?;
        inner.write_all(sealer.header())?;
        let size = chunk_size as usize;
        Ok(Self {
            inner,
            sealer,
            buf: Zeroizing::new(vec![0u8; size + TAG_SIZE]),
            filled: 0,
        })
    }

    fn seal_and_write(&mut self, last: bool) -> Result<()> {
        let n = self.sealer.seal_chunk(&mut self.buf, self.filled, last)?;
        self.inner.write_all(&self.buf[..n])?;
        self.filled = 0;
        Ok(())
    }

    /// Seals the buffered rest as the last chunk, flushes and returns `inner`.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::Io`] when writing fails.
    pub fn finish(mut self) -> Result<W> {
        self.seal_and_write(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    /// Returns `inner` without writing the last chunk (the stream does not open)
    pub fn into_unfinished(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let size = self.sealer.chunk_size() as usize;
        let n = data.len().min(size - self.filled);
        self.buf[self.filled..self.filled + n].copy_from_slice(&data[..n]);
        self.filled += n;
        // a full chunk is sealed at once, so the last chunk is always shorter than a full one
        if self.filled == size {
            self.seal_and_write(false).map_err(to_io)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn to_io(e: ChunkedError) -> io::Error {
    match e {
        ChunkedError::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// Opens a chunked stream from `inner` and hands out the plaintext.
///
/// ⚠️ The plaintext read before the end of the stream is **unverified**: the
/// stream may still turn out to be cut short. Only [`Self::finish`] returning
/// `Ok` confirms the whole stream; use [`open_to_end`] when the whole value fits
/// in memory.
pub struct UnverifiedChunkedReader<R: Read> {
    inner: R,
    opener: ChunkOpener,
    /// sealed bytes read but not yet opened (at most a full chunk and one byte)
    pending: Zeroizing<Vec<u8>>,
    /// opened plaintext not yet handed out
    plain: Zeroizing<Vec<u8>>,
    plain_at: usize,
}

impl<R: Read> UnverifiedChunkedReader<R> {
    /// Reads the header from `inner`.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::Header`] when `inner` ends inside the header, and as
    /// [`ChunkOpener::new`].
    pub fn new(
        mut inner: R,
        key_for_id: impl FnOnce(u32) -> Result<Key>,
        aad: &[u8],
    ) -> Result<Self> {
        let mut header = [0u8; HEADER_SIZE];
        read_full(&mut inner, &mut header).and_then(|n| {
            if n == HEADER_SIZE {
                Ok(())
            } else {
                Err(ChunkedError::Header)
            }
        })?;
        let opener = ChunkOpener::new(&header, key_for_id, aad)?;
        let full = opener.chunk_size() as usize + TAG_SIZE;
        Ok(Self {
            inner,
            opener,
            pending: Zeroizing::new(Vec::with_capacity(full + 1)),
            plain: Zeroizing::new(Vec::with_capacity(full)),
            plain_at: 0,
        })
    }

    /// Opens the next chunk into `plain` (false once the stream ended)
    fn next_chunk(&mut self) -> Result<bool> {
        if self.opener.is_finished() {
            return Ok(false);
        }
        let full = self.opener.chunk_size() as usize + TAG_SIZE;
        // read up to a full chunk and one byte more: the byte tells whether this chunk is the last
        let have = self.pending.len();
        self.pending.resize(full + 1, 0);
        let got = read_full(&mut self.inner, &mut self.pending[have..])?;
        self.pending.truncate(have + got);
        let (len, last) = if self.pending.len() > full {
            (full, false)
        } else if self.pending.len() == full {
            // the last chunk is always shorter than a full one: the stream was cut after a full chunk
            return Err(ChunkedError::Truncated);
        } else if self.pending.is_empty() {
            return Err(ChunkedError::Truncated);
        } else {
            (self.pending.len(), true)
        };
        self.plain.clear();
        self.plain.extend_from_slice(&self.pending[..len]);
        let n = self.opener.open_chunk(&mut self.plain, len, last)?;
        self.plain.truncate(n);
        self.plain_at = 0;
        self.pending.drain(..len);
        Ok(true)
    }

    /// Reads the rest of the stream (discarding the plaintext) and returns
    /// `inner` once the last chunk verified.
    ///
    /// # Errors
    ///
    /// [`ChunkedError::Truncated`], [`ChunkedError::Tampered`] or
    /// [`ChunkedError::Io`] as found in the rest of the stream.
    pub fn finish(mut self) -> Result<R> {
        while self.next_chunk()? {}
        Ok(self.inner)
    }
}

impl<R: Read> Read for UnverifiedChunkedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.plain_at == self.plain.len() {
            if !self.next_chunk().map_err(to_io)? {
                return Ok(0);
            }
        }
        let n = out.len().min(self.plain.len() - self.plain_at);
        out[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        Ok(n)
    }
}

/// Reads into `buf` until it is full or `r` ends, returning the count
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(got)
}

/// Opens the whole stream and returns its plaintext only after every chunk,
/// the last included, verified.
///
/// # Errors
///
/// As [`UnverifiedChunkedReader`], and [`ChunkedError::TooLong`] as soon as the
/// plaintext exceeds `max_len` bytes.
pub fn open_to_end<R: Read>(
    inner: R,
    key_for_id: impl FnOnce(u32) -> Result<Key>,
    aad: &[u8],
    max_len: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut reader = UnverifiedChunkedReader::new(inner, key_for_id, aad)?;
    let mut out = Zeroizing::new(Vec::new());
    while reader.next_chunk()? {
        let total = (out.len() + reader.plain.len()) as u64;
        if total > max_len {
            return Err(ChunkedError::TooLong { limit: max_len });
        }
        extend_zeroizing(&mut out, &reader.plain, max_len);
    }
    Ok(out)
}

/// Appends `more` to `out` without leaving a copy behind: when `out` is full it
/// moves to a new allocation (double the capacity, at most `max_len` unless more
/// is needed) and the old one is zeroed as it is dropped, instead of growing by
/// reallocation (which frees the old block without zeroing it)
fn extend_zeroizing(out: &mut Zeroizing<Vec<u8>>, more: &[u8], max_len: u64) {
    let need = out.len() + more.len();
    if need > out.capacity() {
        let limit = usize::try_from(max_len).unwrap_or(usize::MAX).max(need);
        let capacity = out.capacity().saturating_mul(2).max(need).min(limit);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(out);
        *out = grown;
    }
    out.extend_from_slice(more);
}
