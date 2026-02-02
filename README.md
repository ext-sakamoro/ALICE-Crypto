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
- **Nonce-Misuse Resistance:** Safer than AES-GCM in P2P environments

## Installation

```toml
[dependencies]
alice-crypto = { version = "0.1", default-features = false }
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

## Deep Fried Specs

This implementation is optimized to the **physical and mathematical limits**.

### GF(2^8) Arithmetic (`gf256.rs`)

| Feature | Implementation |
|---------|----------------|
| Multiplication | 8-stage fully unrolled, **branchless** (constant-time) |
| Inverse | 11-step addition chain for a^254 (Fermat's little theorem) |
| Batch Inverse | Montgomery Batch Inversion (1 inv + 3K mul for K elements) |
| Timing Attack | **Resistant** (all operations constant-time) |

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
| Timing Attacks | Constant-time GF(2^8) operations |

## Integration with ALICE Ecosystem

| Component | Use Case |
|-----------|----------|
| ALICE-Auth | Backup Ed25519 seed with SSS |
| ALICE-DB | Encrypt master key, split with SSS |
| ALICE-Sync | Zero-alloc AEAD for P2P packet encryption |

## License

**GNU AGPLv3** (Affero General Public License v3.0)

This library is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation.

**Why AGPL for Crypto?**
While mathematical formulas are public domain, this specific **High-Performance Implementation (Deep Fried Rust)** is protected. If you use this library to provide a service (e.g., a Key Management System), you must release your source code.

For proprietary/commercial use (e.g., embedding in closed-source games or enterprise security appliances), please contact:
**https://extoria.co.jp/en**

## Author

Moroya Sakamoto

---

*"Your secrets belong to mathematics, not corporations."*
