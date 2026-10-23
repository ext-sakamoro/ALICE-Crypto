#!/usr/bin/env python3
"""Reference writer for secret sharing and the shard byte form (independent of the Rust crate).

Shamir's scheme over GF(2^8) with the polynomial x^8 + x^4 + x^3 + x + 1 (0x11B), written here from its
definition: each secret byte s gets the polynomial f(x) = s + c1 x + ... + c(k-1) x^(k-1) with the fixed
coefficients below (a test needs repeatable shares; real shares use random ones), and shard x holds f(x) for
every byte. The shard byte form, version 1:

  [version = 1][threshold k][x][length of y, u32 little-endian][y][check]

where check is the first 16 bytes of the BLAKE3 hash (the BLAKE3 below is written from the specification and is
checked against official vectors of the hash mode before use) of everything before it.

Prints the vectors that `tests/sss_shard_oracle.rs` compares the crate against:

* `case <secret hex> <k> <n>` followed by n lines `shard <x> <encoding hex>`
* `bad <reason> <encoding hex>`: encodings the crate must refuse

Regenerate with:

  python3 tests/data/sss/sss_ref.py > tests/data/sss/vectors.txt
"""
from __future__ import annotations

import struct
import sys

# the hash-mode outputs of the official BLAKE3 test vectors for input lengths 0 and 1 (first 32 bytes)
OFFICIAL_HASH = [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
]

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH = 1, 2, 4, 8, 16
BLOCK, CHUNK = 64, 1024
M32 = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32
    s[d] = rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32
    s[d] = rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = rotr(s[b] ^ s[c], 7)


def compress(cv, block_words, counter, block_len, flags):
    s = cv[:8] + IV[:4] + [counter & M32, (counter >> 32) & M32, block_len, flags]
    m = list(block_words)
    for r in range(7):
        g(s, 0, 4, 8, 12, m[0], m[1]); g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5]); g(s, 3, 7, 11, 15, m[6], m[7])
        g(s, 0, 5, 10, 15, m[8], m[9]); g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13]); g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[PERM[i]] for i in range(16)]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def words(block):
    block = block + b"\0" * (BLOCK - len(block))
    return list(struct.unpack("<16I", block))


def chunk_output(key_words, chunk, counter, flags):
    """the (cv, block words, counter, len, flags) of a chunk's last block, before ROOT is known"""
    cv = key_words
    blocks = [chunk[i:i + BLOCK] for i in range(0, len(chunk), BLOCK)] or [b""]
    for i, b in enumerate(blocks):
        f = flags | (CHUNK_START if i == 0 else 0)
        if i == len(blocks) - 1:
            return (cv, words(b), counter, len(b), f | CHUNK_END)
        cv = compress(cv, words(b), counter, BLOCK, f)[:8]


def out_cv(o):
    cv, w, c, n, f = o
    return compress(cv, w, c, n, f)[:8]


def root_bytes(o, length=32):
    cv, w, _, n, f = o
    out = b""
    counter = 0
    while len(out) < length:
        out += struct.pack("<16I", *compress(cv, w, counter, n, f | ROOT))
        counter += 1
    return out[:length]


def blake3(data, key=None, length=32):
    key_words = list(struct.unpack("<8I", key)) if key is not None else IV
    flags = KEYED_HASH if key is not None else 0
    chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
    stack = []  # cv of complete subtrees, merged by the binary counter of chunks
    for idx, ch in enumerate(chunks):
        o = chunk_output(key_words, ch, idx, flags)
        if idx == len(chunks) - 1:
            # fold the stack from the right: the last chunk is never merged into a parent until the end
            while stack:
                o = (key_words, stack.pop() + out_cv(o), 0, BLOCK, flags | PARENT)
            return root_bytes(o, length)
        cv = out_cv(o)
        total = idx + 1
        while total & 1 == 0:
            cv = out_cv((key_words, stack.pop() + cv, 0, BLOCK, flags | PARENT))
            total >>= 1
        stack.append(cv)


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def coeff(byte_index, j):
    """the fixed coefficient c_j of the polynomial of byte `byte_index` (1 <= j < k)"""
    return (37 * byte_index + 101 * j + 7) % 256


def share(secret, k, x):
    y = []
    for i, s in enumerate(secret):
        acc, power = s, 1
        for j in range(1, k):
            power = gmul(power, x)
            acc ^= gmul(coeff(i, j), power)
        y.append(acc)
    return bytes(y)


def encode(k, x, y, version=1):
    head = bytes([version, k, x]) + struct.pack("<I", len(y)) + y
    return head + blake3(head)[:16]


def main():
    for n, want in OFFICIAL_HASH:
        if blake3(bytes(i % 251 for i in range(n))).hex() != want:
            sys.exit(f"BLAKE3 reference disagrees with the official hash vector for input length {n}")
    cases = [(b"Hello, ALICE!", 3, 5), (bytes(range(32)), 2, 2), (b"\x00", 2, 3), (bytes([0xFF] * 40), 5, 7)]
    for secret, k, n in cases:
        print(f"case {secret.hex()} {k} {n}")
        for x in range(1, n + 1):
            print(f"shard {x} {encode(k, x, share(secret, k, x)).hex()}")
    good = encode(3, 1, share(b"Hello, ALICE!", 3, 1))
    flipped = bytearray(good); flipped[9] ^= 1
    bad_check = bytearray(good); bad_check[-1] ^= 1
    print(f"bad version {encode(3, 1, b'abc', version=2).hex()}")
    print(f"bad threshold {encode(1, 1, b'abc').hex()}")
    print(f"bad x {encode(3, 0, b'abc').hex()}")
    print(f"bad empty {encode(3, 1, b'').hex()}")
    print(f"bad check {bytes(bad_check).hex()}")
    print(f"bad body {bytes(flipped).hex()}")
    print(f"bad truncated {good[:-1].hex()}")
    print(f"bad trailing {(good + b'\x00').hex()}")
    print(f"bad short {good[:6].hex()}")
    long_len = bytes([1, 3, 1]) + struct.pack("<I", 4) + b"abc"
    print(f"bad length {(long_len + blake3(long_len)[:16]).hex()}")


if __name__ == "__main__":
    main()
