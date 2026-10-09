# ALICE-Crypto

**Information-Theoretic Security Primitives for ALICE**

> "Encryption guarantees safety against time. Information theory guarantees safety against God."

## Core Primitives

### 1. Shamir's Secret Sharing (SSS)
**[Information-Theoretic Secure]**

Splits a secret into N shares. Mathematically impossible to reconstruct without K shares.

- **Math:** Galois Field GF(2^8) arithmetic using pure bit operations
- **Security:** Even with infinite computing power, possessing K-1 shares reveals **zero information** about the secret

### 2. BLAKE3 Hashing
**[High Performance]**

Cryptographic hashing faster than `memcpy`.

- **Parallelism:** Merkle tree based, fully SIMD accelerated
- **Use Case:** Content addressing for `ALICE-DB` and `ALICE-Zip`

### 3. XChaCha20-Poly1305
**[Stream Encryption]**

Extended nonce variant of ChaCha20.

- **No Hardware Lock:** Runs optimally on any CPU (Arm/x86/RISC-V)
- **Random nonces are safe:** the 192-bit extended nonce makes per-message
  random nonces collision-free in practice, so no counter has to be persisted
  across restarts — unlike AES-GCM's 96-bit nonce
- ⚠️ **Not nonce-misuse resistant.** Reusing a `(key, nonce)` pair on two
  different messages repeats the keystream and exposes the Poly1305 key. The
  extended nonce removes the need to *coordinate* nonces; it does not make
  reuse survivable. Use `Nonce::generate()` per message (this is what `seal`
  does) and never derive a nonce from a timestamp, a hash or a constant

## Installation

```toml
[dependencies]
alice-crypto = { version = "0.1" }
```

### Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | yes | Standard library support (enables OS RNG, std I/O) |
| `alloc` | no | Heap allocation without std (for embedded targets) |
| `ffi` | no | C-compatible cdylib exports (implies `std`) |

For `no_std` environments (embedded, RTOS, WASM):

```toml
[dependencies]
alice-crypto = { version = "0.1", default-features = false, features = ["alloc"] }
```

Bare-metal targets that `getrandom` does not support (e.g. `thumbv7em-none-eabihf`)
additionally need the `custom-rng` feature and a registered entropy source in the
final binary (`getrandom::register_custom_getrandom!`, see the getrandom docs):

```toml
[dependencies]
alice-crypto = { version = "0.1", default-features = false, features = ["alloc", "custom-rng"] }
```

## Usage

### Secret Sharing (SSS)

```rust
use alice_crypto::sss;

let secret = b"ALICE_MASTER_KEY_2026";

// Split into 5 shards, require 3 to unlock
// This is NOT encryption. It is mathematical disintegration.
let shards = sss::split(secret, 5, 3)?;

// ... Distribute shards to different P2P nodes ...

// Reconstruct from any 3 shards
let recovered = sss::recover(&[shards[0].clone(), shards[2].clone(), shards[4].clone()])?;
assert_eq!(secret, &recovered[..]);
```

### Hashing (BLAKE3)

```rust
use alice_crypto::hash;

let h = hash(b"data");
println!("{}", h); // 64 hex chars

// Incremental hashing
let mut hasher = alice_crypto::Hasher::new();
hasher.update(b"part1");
hasher.update(b"part2");
let h = hasher.finalize();

// Keyed hash (MAC)
let key = [0x42u8; 32];
let mac = alice_crypto::keyed_hash(&key, b"data");

// Key derivation
let key = alice_crypto::derive_key("ALICE context", b"input");
```

### Encryption (XChaCha20-Poly1305)

```rust
use alice_crypto::{Key, seal, open};

let key = Key::generate()?;
let plaintext = b"secret message";

// Encrypt (nonce auto-generated and prepended)
let sealed = seal(&key, plaintext)?;

// Decrypt
let opened = open(&key, &sealed)?;
assert_eq!(&opened, plaintext);
```

### Zero-Allocation In-Place Encryption

```rust
use alice_crypto::{Key, Nonce, encrypt_in_place, decrypt_in_place, TAG_SIZE};

let key = Key::generate()?;
let nonce = Nonce::generate()?;

// Buffer: plaintext + 16 bytes for auth tag
let mut buffer = [0u8; 128];
let plaintext = b"P2P packet data";
buffer[..plaintext.len()].copy_from_slice(plaintext);

// Encrypt in-place (zero heap allocation)
let ct_len = encrypt_in_place(&key, &nonce, &mut buffer, plaintext.len())?;

// Decrypt in-place
let pt_len = decrypt_in_place(&key, &nonce, &mut buffer[..ct_len])?;
```

### Zero-Allocation In-Place Encryption with Associated Data (AEAD)

Binds ciphertext to additional unencrypted metadata. Decryption fails if the associated data does not match.

```rust
use alice_crypto::{Key, Nonce, encrypt_in_place_aead, decrypt_in_place_aead, TAG_SIZE};

let key = Key::generate()?;
let nonce = Nonce::generate()?;
let aad = b"POST /api/v1/data"; // associated data (not encrypted)

let mut buffer = [0u8; 128];
let plaintext = b"request body";
buffer[..plaintext.len()].copy_from_slice(plaintext);

// Encrypt, binding ciphertext to `aad`
let ct_len = encrypt_in_place_aead(&key, &nonce, &mut buffer, plaintext.len(), aad)?;

// Decrypt — must supply the same `aad`, otherwise returns DecryptionFailed
let pt_len = decrypt_in_place_aead(&key, &nonce, &mut buffer[..ct_len], aad)?;
```

### Integration: SSS + Encryption

```rust
use alice_crypto::{sss, Key, seal, open};

// 1. Generate master key
let master_key = Key::generate()?;

// 2. Split master key into 5 shards (need 3 to recover)
let shards = sss::split(&master_key.0, 5, 3)?;

// 3. Encrypt data with master key
let encrypted = seal(&master_key, b"Top secret")?;

// 4. Distribute shards to different locations...
//    Even if 2 shards are compromised, the key is safe

// 5. Later: recover master key from any 3 shards
let recovered = sss::recover(&[shards[0].clone(), shards[2].clone(), shards[4].clone()])?;
let mut key_arr = [0u8; 32];
key_arr.copy_from_slice(&recovered);
let recovered_key = Key::from_bytes(key_arr);

// 6. Decrypt
let data = open(&recovered_key, &encrypted)?;
```

## Error Types

### `SssError`

Returned by `sss::split` and `sss::recover`.

| Variant | Cause |
|---------|-------|
| `ThresholdTooLow` | `k < 2` |
| `ThresholdTooHigh` | `k > n` |
| `TooManyShards` | `n == 0` or more than 255 shards passed to `recover` |
| `NotEnoughShards` | Empty shard slice passed to `recover` |
| `EmptySecret` | Zero-length secret passed to `split` |
| `DuplicateX` | Two shards share the same X coordinate |
| `RandomFailed` | OS RNG unavailable |

### `CipherError`

Returned by all `stream` module functions.

| Variant | Cause |
|---------|-------|
| `EncryptionFailed` | Cipher initialization or encryption error |
| `DecryptionFailed` | Authentication tag mismatch (wrong key, nonce, or tampered data) |
| `RandomFailed` | OS RNG unavailable (during `Key::generate` or `Nonce::generate`) |
| `BufferTooSmall` | Buffer does not have enough room for the auth tag |

## Deep Fried Specs

This implementation is optimized to the **physical and mathematical limits**.

### GF(2^8) Arithmetic (`gf256.rs`)

| Feature | Implementation |
|---------|----------------|
| Multiplication | 8-stage fully unrolled, **branchless** (constant-time) |
| Inverse | 11-step addition chain for a^254 (Fermat's little theorem) |
| Batch Inverse | Montgomery Batch Inversion (1 inv + 3K mul for K elements), multiplication count depends on the slice length only |
| Timing Attack | See **Timing behaviour** below — stated per operation, not as one blanket guarantee |

```rust
// Branchless multiplication (no branch prediction misses)
let mask = (-(((b >> i) & 1) as i8)) as u8;  // 0x00 or 0xFF
p ^= a & mask;
```

### Shamir's Secret Sharing (`sss.rs`)

| Feature | Implementation |
|---------|----------------|
| RNG | Buffered (1KB), syscalls reduced by **256x** |
| Coefficients | Stack-allocated `[GF; 255]` (zero heap in hot loop) |
| Polynomial Eval | Horner's method (K mul instead of 2K) |
| Lagrange Basis | Montgomery Batch Inversion (1 inv instead of K) |
| Reconstruction | 4-way ILP unrolled dot product (SIMD-friendly) |

**Performance:**
```
split():  L bytes → L/1024 syscalls (was L)
recover(): K shards → 1 inv + O(K²) mul (was K inv)
```

### XChaCha20-Poly1305 (`stream.rs`)

| Feature | Implementation |
|---------|----------------|
| Core API | Zero-allocation `*_in_place` functions |
| AEAD variant | `*_in_place_aead` with associated data binding |
| Convenience | `seal`/`open` wrap in-place core |
| Tag Size | 16 bytes (Poly1305) |
| Nonce Size | 24 bytes (extended, random-safe) |

## Security Model

| Threat | Protection |
|--------|------------|
| Quantum Computers | SSS is information-theoretic (unbreakable) |
| Server Compromise | Shards distributed across locations |
| Brute Force | XChaCha20 = 256-bit key space |
| Replay Attacks | 192-bit nonce with AEAD |
| Timing Attacks | Per-operation, see **Timing behaviour** |

## Differential privacy (`dp`)

Reproducibility and privacy look like opposites — a mechanism wants noise the
attacker cannot predict, an audit wants the same noise twice — and they stop
being opposites once the determinism is anchored to a **secret key** instead of
a public value like a clock:

```rust
use alice_crypto::dp::{dp_count, SecureRng};

let mut rng = SecureRng::from_key(key_from_your_key_store);
let noisy = dp_count(1_000, 1.0, &mut rng)?;   // count + Lap(1/epsilon)
```

- Every constructor takes a 32-byte key. The one that does not —
  `SecureRng::try_from_entropy()` — takes it from the OS and **fails** rather
  than falling back to anything guessable
- `dp_count` / `dp_sum` take ε and derive the Laplace scale themselves. ⚠️ An ε
  that is accepted and then ignored is worse than no ε at all, and taking the
  scale as a parameter is how that happens
- The keystream is RFC 8439 ChaCha20 (from the `chacha20` crate this crate
  already depended on, rather than a second hand-written copy), and the `ln` in
  the inverse transform is `alice-det-math`'s bit-exact one — so the same key
  gives the same noise on every platform, which is what a replay needs
- ⚠️ **Known limit:** floating-point inverse-transform sampling is subject to
  Mironov's 2012 attack, so the ε here is the value for ideal real arithmetic,
  not a machine-level guarantee. A snapping mechanism is not implemented yet and
  the module doc says so

## Timing behaviour

There is deliberately **no** single "all operations are constant-time" claim:
some operations legitimately depend on public inputs (slice lengths, iteration
counts, key identifiers) and some are delegated to `blake3` /
`chacha20poly1305`. The crate-level rustdoc carries the full table of what each
operation's running time may depend on; the short version is that the *value* of
a key, a share, a MAC tag or a field element must never affect it.

Two things follow from that, and both are checked:

- `Signature` does **not** derive `PartialEq`: a derived `==` compares the 32
  tag bytes front to back and stops at the first difference, which turns the
  number of matching leading bytes into a timing signal. The hand-written `impl`
  always scans all 32 bytes, the same comparison `verify` uses.
- `gf256::inv` / `div` / `batch_inv` take no early exit on an element's value.
  `inv_or_zero` / `div_or_zero` are the branch-free forms (`0` maps to `0`), and
  `batch_inv` detects "some input was zero" from the running product — GF(2^8)
  is a field, so that is equivalent and costs nothing — instead of testing each
  element and bailing out at the first one.

`scripts/constant_time_guard.py` enforces both statically (and fails when it has
nothing to compare, so it cannot pass by looking at zero files); it runs in
`security-audit.yml` and in `scripts/preflight.sh`. The behavioural half of the
contract is pinned by `tests/constant_time_contract.rs`. Neither is a proof:
instruction selection, compiler transformations and cache behaviour are not
measured.

## Key material handling

Secrets are zeroed on drop through `zeroize` (volatile writes plus a fence, so
the stores are not optimised away as dead): `SigningKey`, `VerifyingKey`,
`stream::Key`, `kdf::Prk`, `keystore::KeyEntry.key_data`, `sss::Shard.y`, and
`dp::SecureRng` (both its key and its 64-byte keystream buffer).
`sss::split` also clears the stack buffers that held the secret bytes and the
random polynomial coefficients before it returns.

Not zeroed, on purpose: nonces and key ids (public), and `Signature` (a MAC tag
is transmitted in the clear). Bytes a caller copies out via `as_bytes()` or a
`pub` field are the caller's to clear.

## Integration with ALICE Ecosystem

| Component | Use Case |
|-----------|----------|
| ALICE-DB | Encrypt master key, split with SSS |
| ALICE-Sync | Zero-alloc AEAD for P2P packet encryption |

## License

`AGPL-3.0-or-later OR LicenseRef-Commercial` — dual-licensed. Pick either.

| Option | Terms | Use it when |
|--------|-------|-------------|
| **AGPL-3.0-or-later** | [LICENSE-AGPL](LICENSE-AGPL) — free, no reporting obligation | Your project is itself AGPL-compatible open source, or you are only using it internally |
| **Commercial License** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — paid, removes the copyleft | Closed-source product, proprietary SaaS, edge / firmware distribution, plugin redistribution, or a platform NDA that forbids source disclosure |

AGPL is a strong copyleft: a product, firmware image, or service that links
`alice-crypto` and is distributed or served to users must be released under the AGPL
as well. That is intentional for the open ecosystem, and the Commercial
License exists for the cases where it is not something you are able to do.

Commercial licence enquiries: <contact@extoria.co.jp>

## Author

Moroya Sakamoto

---

*"Your secrets belong to mathematics, not corporations."*
