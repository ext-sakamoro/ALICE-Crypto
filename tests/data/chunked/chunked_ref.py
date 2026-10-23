#!/usr/bin/env python3
"""Reference writer for the chunked envelope (independent of the Rust crate).

Builds the STREAM-BE32 construction by hand on top of pycryptodome's
XChaCha20-Poly1305 (24-byte nonce) and prints the vectors that
`src/chunked/tests.rs` compares the crate against.

Layout written here:

* header (28 bytes): version 0x81, key id u32 big-endian, chunk size u32
  big-endian, nonce prefix (19 bytes)
* then the chunks: each is the plaintext chunk sealed with
  nonce = prefix || counter u32 big-endian || last flag (1 on the last chunk,
  0 otherwise) and associated data = header || caller associated data;
  every chunk but the last holds exactly `chunk size` plaintext bytes, the last
  holds the rest (possibly nothing)

Regenerate with:

  uv run --no-project --with pycryptodome python3 tests/data/chunked/chunked_ref.py \
      > tests/data/chunked/vectors.txt
"""
from __future__ import annotations

import struct

from Crypto.Cipher import ChaCha20_Poly1305

VERSION = 0x81
KEY = bytes(range(32))
KEY_ID = 7
AAD = b"alice-crypto chunked reference"
PREFIX = bytes(0xA0 + i for i in range(19))
CHUNK = 4096


def plaintext(n: int) -> bytes:
    return bytes((i * 7 + 3) % 256 for i in range(n))


def seal(pt: bytes, chunk: int) -> bytes:
    header = bytes([VERSION]) + struct.pack(">II", KEY_ID, chunk) + PREFIX
    out = bytearray(header)
    pieces = [pt[i : i + chunk] for i in range(0, len(pt), chunk)]
    # the last chunk is the remainder; a length that is a multiple of the chunk
    # size (or zero) ends with an empty last chunk
    if not pieces or len(pieces[-1]) == chunk:
        pieces.append(b"")
    for counter, piece in enumerate(pieces):
        last = counter == len(pieces) - 1
        nonce = PREFIX + struct.pack(">I", counter) + bytes([1 if last else 0])
        c = ChaCha20_Poly1305.new(key=KEY, nonce=nonce)
        c.update(header + AAD)
        ct, tag = c.encrypt_and_digest(piece)
        out += ct + tag
    return bytes(out)


def main() -> None:
    print(f"# key {KEY.hex()} key_id {KEY_ID} aad {AAD.hex()} prefix {PREFIX.hex()} chunk {CHUNK}")
    print("# name plaintext_len sealed_hex")
    for name, n in [
        ("empty", 0),
        ("one", 1),
        ("chunk_minus_one", CHUNK - 1),
        ("chunk", CHUNK),
        ("chunk_plus_one", CHUNK + 1),
        ("three_chunks", 3 * CHUNK),
    ]:
        print(name, n, seal(plaintext(n), CHUNK).hex())


if __name__ == "__main__":
    main()
