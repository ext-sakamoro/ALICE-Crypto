# Contributing to ALICE-Crypto

## Prerequisites

- Rust stable (latest)
- No external system dependencies

## Build & Test

```bash
# Build (default features = std)
cargo build

# Build (no_std + alloc)
cargo build --no-default-features --features alloc

# Run all tests
cargo test

# Clippy
cargo clippy -- -W clippy::all

# Format check
cargo fmt -- --check

# Doc tests
cargo test --doc
```

## Architecture

ALICE-Crypto provides three independent cryptographic primitives:

| Module | Purpose | Key Property |
|--------|---------|-------------|
| `gf256` | Galois field arithmetic | Constant-time (timing attack resistant) |
| `sss` | Secret splitting | Information-theoretic security |
| `hash` | Content hashing | SIMD-accelerated (BLAKE3) |
| `stream` | Authenticated encryption | Zero-allocation in-place API |

### Security Invariants

- **All GF(2^8) operations MUST be constant-time** — no data-dependent branches
- **RNG failures MUST propagate as errors** — never fall back to weak randomness
- **In-place APIs MUST NOT allocate** — critical for P2P packet processing
- **Nonces MUST be unique per encryption** — `seal()` auto-generates; in-place API requires caller to manage

## Code Style

- `cargo fmt` before every commit
- No `clippy::all` warnings
- `#[inline(always)]` on all GF(2^8) leaf operations (called per-byte)
- All public types must have doc comments

## Commit Messages

Use English, imperative mood. No auto-signatures.

## License

AGPL-3.0. Copyright (c) 2026 Moroya Sakamoto.
