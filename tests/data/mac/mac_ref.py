#!/usr/bin/env python3
"""Reference writer for the MAC (independent of the Rust crate).

BLAKE3 in keyed mode, written from the BLAKE3 specification below, is first checked against the
first 32 bytes of the `keyed_hash` outputs of the official BLAKE3 test vectors (test_vectors.json of
the BLAKE3 repository, key "whats the Elvish word for friend", input = the repeating bytes
0, 1, ..., 250); it exits non-zero on any mismatch. Then it prints the vectors that
`tests/mac_oracle.rs` compares the crate against:

* `official <input length> <tag>`: the official vectors themselves
* `plain <message length> <tag>`: `mac(key, message)` = BLAKE3 keyed_hash(key, message)
* `context <context hex or -> <message length> <tag>`: `mac_with_context(key, context, message)` =
  BLAKE3 keyed_hash(key, u64 little-endian length of context || context || message)

The key is the official vectors' key, and every message is the official repeating pattern.

Regenerate with:

  python3 tests/data/mac/mac_ref.py > tests/data/mac/vectors.txt
"""
from __future__ import annotations

import struct
import sys

KEY = b"whats the Elvish word for friend"
OFFICIAL = [
    (0, "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
    (1, "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"),
    (2, "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a"),
    (3, "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9"),
    (4, "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070"),
    (5, "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461"),
    (6, "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6d"),
    (7, "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a"),
    (8, "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600"),
    (63, "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae"),
    (64, "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"),
    (65, "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72"),
    (127, "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818"),
    (128, "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec"),
    (129, "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f"),
    (1023, "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e"),
    (1024, "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"),
    (1025, "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69"),
    (2048, "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1"),
    (2049, "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5"),
    (3072, "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770"),
    (3073, "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a"),
    (4096, "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0"),
    (4097, "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc"),
    (5120, "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20"),
    (5121, "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024"),
    (6144, "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1d"),
    (6145, "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539"),
    (7168, "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fc"),
    (7169, "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa511"),
    (8192, "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a"),
    (8193, "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5"),
    (16384, "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d"),
    (31744, "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419"),
    (102400, "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7"),
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


def pattern(n):
    return bytes(i % 251 for i in range(n))


def main():
    for n, want in OFFICIAL:
        got = blake3(pattern(n), KEY).hex()
        if got != want:
            sys.exit(f"BLAKE3 reference disagrees with the official vector for input length {n}")
    for n, want in OFFICIAL:
        print(f"official {n} {want}")
    for n in (0, 1, 64, 65, 1024, 1025, 2048, 3073):
        print(f"plain {n} {blake3(pattern(n), KEY).hex()}")
    for ctx, n in ((b"", 0), (b"alice-crypto mac test", 5), (b"ab", 1), (b"a", 2), (pattern(300), 1500), (b"", 1025)):
        tag = blake3(struct.pack("<Q", len(ctx)) + ctx + pattern(n), KEY).hex()
        print(f"context {ctx.hex() or '-'} {n} {tag}")


if __name__ == "__main__":
    main()
