#!/usr/bin/env python3
"""Extract the MLS primitive test vectors from their published sources.

None of the expected values comes from this crate. Each source is checked
against the SHA-256 pinned below before anything is read from it, and every
file written here is listed with its SHA-256 in MANIFEST, which
tests/mls_primitives_kat.rs checks before it reads a vector.

Sources (download each into a directory of its own, then pass the paths):

- RFC 5869 (HKDF), Appendix A.1-A.3 (the SHA-256 cases):
  https://www.rfc-editor.org/rfc/rfc5869.txt
- RFC 7748 (X25519), Sections 5.2 and 6.1:
  https://www.rfc-editor.org/rfc/rfc7748.txt
- RFC 9180 (HPKE), Appendix A.1.1, which the JSON test vectors must match:
  https://www.rfc-editor.org/rfc/rfc9180.txt
- HPKE test vectors in JSON (the record mode 0, KEM 0x0020, KDF 0x0001,
  AEAD 0x0001, all of its encryptions and exports):
  https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json
- NIST CAVP GCM (gcmEncryptExtIV128.rsp and gcmDecrypt128.rsp, the sections
  with a 96-bit IV and a 128-bit tag, which are what MLS uses):
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
- NIST CAVP SHA (SHA256ShortMsg.rsp, SHA256LongMsg.rsp, SHA256Monte.rsp,
  copied whole):
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip

Every file written has LF line ends and no trailing spaces (the sources'
CRLF and trailing spaces are dropped; nothing else changes).

usage: python3 -I tests/data/mls/extract.py <rfc5869.txt> <rfc7748.txt> <rfc9180.txt> \\
           <test-vectors.json> <gcm dir> <sha dir> [--check]
"""

import hashlib
import json
import pathlib
import re
import sys

OUT = pathlib.Path(__file__).resolve().parent

SOURCE_SHA256 = {
    "rfc5869.txt": "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c",
    "rfc7748.txt": "279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3",
    "rfc9180.txt": "f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6",
    "test-vectors.json": "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6",
}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_pinned(path: pathlib.Path, pins: dict) -> bytes:
    b = path.read_bytes()
    want = pins.get(path.name)
    if want is None:
        sys.exit(f"{path.name}: no pinned SHA-256")
    if sha(b) != want:
        sys.exit(f"{path.name}: SHA-256 {sha(b)}, pinned {want}")
    return b


def hexrun(lines, i):
    """The hex digits starting at the value on line i and continuing on the
    following lines while they hold hex only."""
    first = lines[i].split(":", 1)[1] if ":" in lines[i] else lines[i]
    first = first.split("=", 1)[1] if "=" in first else first
    out = re.sub(r"\(.*\)|0x|\s", "", first)
    j = i + 1
    while j < len(lines) and re.fullmatch(r"\s*[0-9a-f]+\s*(\(\d+ octets\))?\s*", lines[j]):
        out += re.sub(r"\(.*\)|\s", "", lines[j])
        j += 1
    return out


def rfc_pages(text: str) -> list:
    """The RFC's lines without page headers, footers and form feeds."""
    keep = []
    for line in text.replace("\f", "\n").splitlines():
        if re.match(r"^(RFC \d+ |Krawczyk|Langley|Barnes)", line):
            continue
        keep.append(line.rstrip())
    return keep


def hkdf(text: str) -> str:
    lines = rfc_pages(text)
    out = ["# RFC 5869 Appendix A.1-A.3: HKDF-SHA256 (IKM, salt, info, L, PRK, OKM)"]
    for case in ("A.1.  Test Case 1", "A.2.  Test Case 2", "A.3.  Test Case 3"):
        i = next(k for k, l in enumerate(lines) if l.startswith(case))
        rec = {}
        for k in range(i, i + 40):
            m = re.match(r"\s+(IKM|salt|info|L|PRK|OKM)\s+=", lines[k])
            if m and m.group(1) not in rec:
                name = m.group(1)
                if name == "L":
                    rec[name] = lines[k].split("=")[1].strip()
                elif "(0 octets)" in lines[k]:
                    rec[name] = ""
                else:
                    rec[name] = hexrun(lines, k)
        if sorted(rec) != sorted(["IKM", "salt", "info", "L", "PRK", "OKM"]):
            sys.exit(f"{case}: read {sorted(rec)}")
        if len(rec["OKM"]) != 2 * int(rec["L"]):
            sys.exit(f"{case}: OKM is not L bytes")
        out.append("")
        out += [f"{k} = {rec[k]}" for k in ("IKM", "salt", "info", "L", "PRK", "OKM")]
    return "\n".join(out) + "\n"


def x25519(text: str) -> str:
    lines = rfc_pages(text)

    def after(label, start):
        k = next(i for i in range(start, len(lines)) if lines[i].strip().startswith(label))
        return k, re.sub(r"\s", "", lines[k + 1])

    out = ["# RFC 7748: X25519(scalar, u) for the two vectors of Section 5.2,",
           "# the iterated function of Section 5.2 (k = u = 9 at the start), and",
           "# the Diffie-Hellman example of Section 6.1"]
    s = next(i for i, l in enumerate(lines) if l.startswith("5.2.  Test Vectors"))
    k = s
    for _ in range(2):
        k, scalar = after("Input scalar:", k)
        k, u = after("Input u-coordinate:", k)
        k, res = after("Output u-coordinate:", k)
        out += ["", f"scalar = {scalar}", f"u = {u}", f"out = {res}"]
    for n, label in ((1, "After one iteration:"), (1000, "After 1,000 iterations:"), (1000000, "After 1,000,000 iterations:")):
        k2, v = after(label, s)
        out += ["", f"iterations = {n}", f"k = {v}"]
    d = next(i for i, l in enumerate(lines) if l.startswith("6.1.  Curve25519"))
    names = [("Alice's private key, a:", "alice_private"), ("Alice's public key, X25519(a, 9):", "alice_public"),
             ("Bob's private key, b:", "bob_private"), ("Bob's public key, X25519(b, 9):", "bob_public"),
             ("Their shared secret, K:", "shared")]
    out.append("")
    for label, name in names:
        _, v = after(label, d)
        out.append(f"{name} = {v}")
    for line in out:
        m = re.match(r"\w+ = ([0-9a-f]+)$", line)
        if m and not line.startswith("iterations") and len(m.group(1)) != 64:
            sys.exit(f"x25519: {line}")
    return "\n".join(out) + "\n"


def hpke(raw: bytes, rfc_text: str) -> str:
    recs = [r for r in json.loads(raw) if r["mode"] == 0 and r["kem_id"] == 32 and r["kdf_id"] == 1 and r["aead_id"] == 1]
    if len(recs) != 1:
        sys.exit(f"hpke: {len(recs)} records for the suite")
    r = recs[0]
    # the RFC's printed values for the same suite must be the record's
    lines = rfc_pages(rfc_text)
    a = next(i for i, l in enumerate(lines) if l.startswith("A.1.1.  Base Setup Information"))
    b = next(i for i, l in enumerate(lines) if l.startswith("A.1.2.  PSK Setup Information"))
    sec = lines[a:b]
    checked = 0
    for field in ("info", "ikmE", "pkEm", "skEm", "ikmR", "pkRm", "skRm", "enc", "shared_secret",
                  "key_schedule_context", "secret", "key", "base_nonce", "exporter_secret"):
        k = next(i for i, l in enumerate(sec) if l.strip().startswith(field + ":"))
        v = sec[k].split(":", 1)[1].strip()
        j = k + 1
        while j < len(sec) and re.fullmatch(r"\s*[0-9a-f]+\s*", sec[j]) and not re.match(r"\s*\w+:", sec[j]):
            v += sec[j].strip()
            j += 1
        if v != r[field]:
            sys.exit(f"hpke: RFC {field} {v} != JSON {r[field]}")
        checked += 1
    rfc_cts = re.findall(r"sequence number: (\d+)\n(?:.*\n){3}\s+ct: ([0-9a-f]+)\n\s+([0-9a-f]+)", "\n".join(sec))
    for seq, c1, c2 in rfc_cts:
        if r["encryptions"][int(seq)]["ct"] != c1 + c2:
            sys.exit(f"hpke: RFC ct {seq} differs")
        checked += 1
    if checked != 14 + 6:
        sys.exit(f"hpke: compared {checked} RFC values")
    out = ["# RFC 9180 Appendix A.1.1 (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0001), from the",
           "# JSON test vectors; the setup, then each encryption (sequence numbers from 0), then",
           "# each export", ""]
    out += [f"{k} = {r[k]}" for k in ("info", "ikmE", "skEm", "pkEm", "ikmR", "skRm", "pkRm", "enc",
                                       "shared_secret", "key_schedule_context", "secret", "key",
                                       "base_nonce", "exporter_secret")]
    for seq, e in enumerate(r["encryptions"]):
        out += ["", f"seq = {seq}", f"aad = {e['aad']}", f"pt = {e['pt']}", f"nonce = {e['nonce']}", f"ct = {e['ct']}"]
    for x in r["exports"]:
        out += ["", f"exporter_context = {x['exporter_context']}", f"L = {x['L']}",
                f"exported_value = {x['exported_value']}"]
    return "\n".join(out) + "\n"


def gcm_sections(text: str, name: str) -> str:
    """The sections of a CAVP GCM file with a 96-bit IV and a 128-bit tag."""
    blocks = re.split(r"\n(?=\[Keylen = )", text)
    head = blocks[0]
    kept = [b for b in blocks[1:] if "[IVlen = 96]" in b and "[Taglen = 128]" in b and "[Keylen = 128]" in b]
    if len(kept) < 10:
        sys.exit(f"{name}: {len(kept)} sections")
    return (f"# {name}: the sections with Keylen = 128, IVlen = 96, Taglen = 128\n"
            + head.strip() + "\n\n" + "\n".join(b.strip() + "\n" for b in kept))


def normalize(text: str) -> str:
    return "".join(line.rstrip() + "\n" for line in text.replace("\r\n", "\n").split("\n")).rstrip("\n") + "\n"


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 6:
        sys.exit(__doc__)
    rfc5869, rfc7748, rfc9180, tv, gcm_dir, sha_dir = map(pathlib.Path, args)
    check = "--check" in sys.argv[1:]
    pins = dict(SOURCE_SHA256)
    pins.update(MEMBER_PINS)
    files = {
        "hkdf_sha256.txt": hkdf(read_pinned(rfc5869, pins).decode()),
        "x25519.txt": x25519(read_pinned(rfc7748, pins).decode()),
        "hpke_base_x25519_sha256_aes128gcm.txt": hpke(read_pinned(tv, pins), read_pinned(rfc9180, pins).decode()),
        "aes128gcm_encrypt.rsp": gcm_sections(read_pinned(gcm_dir / "gcmEncryptExtIV128.rsp", pins).decode(), "gcmEncryptExtIV128.rsp"),
        "aes128gcm_decrypt.rsp": gcm_sections(read_pinned(gcm_dir / "gcmDecrypt128.rsp", pins).decode(), "gcmDecrypt128.rsp"),
    }
    for n in ("SHA256ShortMsg.rsp", "SHA256LongMsg.rsp", "SHA256Monte.rsp"):
        files[n] = read_pinned(sha_dir / n, pins).decode()
    files = {n: normalize(b) for n, b in files.items()}
    manifest = "".join(f"{sha(files[n].encode())}  {n}\n" for n in sorted(files))
    files["MANIFEST"] = manifest
    bad = 0
    for n, body in files.items():
        p = OUT / n
        if check:
            if not p.exists() or p.read_text(encoding="utf-8") != body:
                print(f"{n}: differs from the extraction")
                bad += 1
        else:
            p.write_text(body, encoding="utf-8", newline="\n")
        print(f"{n}: {body.count(chr(10))} lines")
    if bad:
        sys.exit(1)


# SHA-256 of the archive members, as extracted from the pinned archives
# (gcmtestvectors.zip f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023,
#  shabytetestvectors.zip 929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8)
MEMBER_PINS = {
    "gcmEncryptExtIV128.rsp": "30156236f768b0d81e58a3e5bd3bd79ce294cf9ef0ba0a84cf7b869c89ebd9fd",
    "gcmDecrypt128.rsp": "0d1f98d0c9e176ede1f3e85484dd13de92c3436ca97df378ec3481e04c19a732",
    "SHA256ShortMsg.rsp": "75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c",
    "SHA256LongMsg.rsp": "6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974",
    "SHA256Monte.rsp": "29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9",
}

if __name__ == "__main__":
    main()
