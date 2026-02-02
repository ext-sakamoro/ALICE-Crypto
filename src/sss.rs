//! Shamir's Secret Sharing over GF(2^8)
//!
//! Information-theoretically secure secret splitting.
//! K-1 shares reveal ZERO information about the secret.
//!
//! **Deep Fried Edition**:
//! - Split: Buffered RNG (minimized syscalls), Stack allocations only
//! - Recover: Montgomery Batch Inversion, O(K) reconstruction

use crate::gf256::{GF, batch_inv};

/// A share of the secret
#[derive(Clone, Debug)]
pub struct Shard {
    /// X coordinate (1-255, never 0)
    pub x: u8,
    /// Y values for each byte of the secret
    pub y: alloc::vec::Vec<u8>,
}

/// Error type for SSS operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SssError {
    ThresholdTooLow,
    ThresholdTooHigh,
    TooManyShards,
    NotEnoughShards,
    EmptySecret,
    DuplicateX,
    RandomFailed,
}

extern crate alloc;
use alloc::vec::Vec;

// RNG buffer size (reduce syscalls)
const RNG_BUF_SIZE: usize = 1024;

/// Split a secret into N shards, requiring K to recover.
///
/// # Security
/// - K-1 shards reveal **zero** information about the secret
/// - This is information-theoretic, not computational
///
/// # Deep Fried Optimizations
/// - **Buffered RNG**: Calls OS RNG only once per 1KB of data (vs per byte)
/// - **Zero Alloc Loop**: Uses stack memory for coefficients
///
/// # Example
/// ```
/// let secret = b"my_secret_key";
/// let shards = alice_crypto::sss::split(secret, 5, 3).unwrap();
/// // Distribute shards[0..5] to different locations
/// ```
pub fn split(secret: &[u8], n: u8, k: u8) -> Result<Vec<Shard>, SssError> {
    if secret.is_empty() { return Err(SssError::EmptySecret); }
    if k < 2 { return Err(SssError::ThresholdTooLow); }
    if k > n { return Err(SssError::ThresholdTooHigh); }
    if n == 0 { return Err(SssError::TooManyShards); }

    // Pre-allocate output shards
    let mut shards: Vec<Shard> = (1..=n)
        .map(|x| Shard { x, y: Vec::with_capacity(secret.len()) })
        .collect();

    // Random number generator buffer
    let mut rng_buf = [0u8; RNG_BUF_SIZE];
    let mut rng_idx = RNG_BUF_SIZE; // Force refill on first use

    // Stack-allocated coefficients buffer
    // Layout: [constant_term (secret), rand1, rand2, ..., rand_k-1]
    let mut coeffs = [GF::ZERO; 255];
    let k_usize = k as usize;
    let num_random = k_usize - 1;

    for &s in secret {
        // 1. Set constant term (secret byte)
        coeffs[0] = GF(s);

        // 2. Fill random coefficients (1 to k-1)
        // Using buffered RNG to avoid syscall overhead
        let mut needed = num_random;
        let mut filled = 0;

        while needed > 0 {
            // Refill buffer if empty
            if rng_idx >= RNG_BUF_SIZE {
                getrandom::getrandom(&mut rng_buf).map_err(|_| SssError::RandomFailed)?;
                rng_idx = 0;
            }

            // Copy what we can
            let available = RNG_BUF_SIZE - rng_idx;
            let to_copy = core::cmp::min(needed, available);

            for i in 0..to_copy {
                coeffs[1 + filled + i] = GF(rng_buf[rng_idx + i]);
            }

            rng_idx += to_copy;
            filled += to_copy;
            needed -= to_copy;
        }

        // 3. Evaluate polynomial for each shard
        // f(x) = coeffs[0] + coeffs[1]*x + ...
        for shard in &mut shards {
            let x = GF(shard.x);
            let y = eval_poly_stack(&coeffs[..k_usize], x);
            shard.y.push(y.0);
        }
    }

    Ok(shards)
}

/// Recover the secret from K or more shards.
///
/// Uses Lagrange interpolation at x=0.
/// Ultra Deep Fried: O(K² + L·K) with Montgomery Batch Inversion
pub fn recover(shards: &[Shard]) -> Result<Vec<u8>, SssError> {
    if shards.is_empty() { return Err(SssError::NotEnoughShards); }

    let k = shards.len();
    if k > 255 { return Err(SssError::TooManyShards); }

    // Check for duplicate X values O(K^2) check, tiny for K<255
    for i in 0..k {
        for j in (i + 1)..k {
            if shards[i].x == shards[j].x {
                return Err(SssError::DuplicateX);
            }
        }
    }

    // Extract X coordinates to stack array
    let mut x_coords = [GF::ZERO; 255];
    for (i, shard) in shards.iter().enumerate() {
        x_coords[i] = GF(shard.x);
    }

    // =======================================================================
    // Montgomery Batch Inversion for Lagrange basis
    // =======================================================================
    // L_i(0) = product of (xj / (xi - xj)) for j != i

    // 1. Compute denominators product for each i
    let mut denom_products = [GF::ONE; 255];
    for i in 0..k {
        let xi = x_coords[i];
        let mut prod = GF::ONE;
        for j in 0..k {
            if i != j {
                // xi - xj = xi + xj in GF(2^8) (XOR)
                prod = prod.mul(xi.add(x_coords[j]));
            }
        }
        denom_products[i] = prod;
    }

    // 2. Batch invert all K denominators (Only 1 division here!)
    let mut denom_inv = [GF::ZERO; 255];
    batch_inv(&denom_products[..k], &mut denom_inv[..k])
        .ok_or(SssError::DuplicateX)?;

    // 3. Compute final basis weights: w_i = (product_{j!=i} xj) * inv(product_{j!=i} (xi-xj))
    let mut basis = [GF::ZERO; 255];
    for i in 0..k {
        let mut numer_prod = GF::ONE;
        for j in 0..k {
            if i != j {
                numer_prod = numer_prod.mul(x_coords[j]);
            }
        }
        basis[i] = numer_prod.mul(denom_inv[i]);
    }

    // 4. Reconstruction Loop (The Hot Path)
    let len = shards[0].y.len();
    let mut secret = Vec::with_capacity(len);

    // Unroll 4 for ILP (Instruction Level Parallelism)
    for byte_idx in 0..len {
        let mut s0 = GF::ZERO;
        let mut s1 = GF::ZERO;
        let mut s2 = GF::ZERO;
        let mut s3 = GF::ZERO;

        let chunks = k / 4;
        let remainder = k % 4;

        // Vectorizable-friendly loop
        for c in 0..chunks {
            let base = c * 4;
            let y0 = GF(shards[base].y[byte_idx]);
            let y1 = GF(shards[base + 1].y[byte_idx]);
            let y2 = GF(shards[base + 2].y[byte_idx]);
            let y3 = GF(shards[base + 3].y[byte_idx]);

            s0 = s0.add(y0.mul(basis[base]));
            s1 = s1.add(y1.mul(basis[base + 1]));
            s2 = s2.add(y2.mul(basis[base + 2]));
            s3 = s3.add(y3.mul(basis[base + 3]));
        }

        // Handle remainder
        let base = chunks * 4;
        for i in 0..remainder {
            let yi = GF(shards[base + i].y[byte_idx]);
            s0 = s0.add(yi.mul(basis[base + i]));
        }

        // Sum reduction
        secret.push(s0.add(s1).add(s2).add(s3).0);
    }

    Ok(secret)
}

/// Horner's method for stack slice
#[inline(always)]
fn eval_poly_stack(coeffs: &[GF], x: GF) -> GF {
    let mut result = GF::ZERO;
    let mut i = coeffs.len();
    while i > 0 {
        i -= 1;
        result = coeffs[i].add(x.mul(result));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_recover() {
        let secret = b"Hello, ALICE!";
        let shards = split(secret, 5, 3).unwrap();
        assert_eq!(shards.len(), 5);

        // Recover with exactly K shards
        let recovered = recover(&[shards[0].clone(), shards[2].clone(), shards[4].clone()]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_different_combinations() {
        let secret = b"SecretKey123";
        let shards = split(secret, 5, 3).unwrap();

        // All combinations of 3 shards should work
        let r1 = recover(&[shards[0].clone(), shards[1].clone(), shards[2].clone()]).unwrap();
        let r2 = recover(&[shards[2].clone(), shards[3].clone(), shards[4].clone()]).unwrap();
        let r3 = recover(&[shards[0].clone(), shards[2].clone(), shards[4].clone()]).unwrap();

        assert_eq!(&r1, secret);
        assert_eq!(&r2, secret);
        assert_eq!(&r3, secret);
    }

    #[test]
    fn test_more_than_k_shards() {
        let secret = b"MoreShards";
        let shards = split(secret, 5, 3).unwrap();

        // 4 shards should also work
        let recovered = recover(&shards[0..4]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_threshold_too_low() {
        assert!(matches!(split(b"x", 5, 1), Err(SssError::ThresholdTooLow)));
    }

    #[test]
    fn test_threshold_too_high() {
        assert!(matches!(split(b"x", 3, 5), Err(SssError::ThresholdTooHigh)));
    }

    #[test]
    fn test_large_secret() {
        // Test with larger data to exercise buffered RNG
        let secret = vec![0xABu8; 2048];
        let shards = split(&secret, 5, 3).unwrap();
        let recovered = recover(&[shards[0].clone(), shards[2].clone(), shards[4].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }
}
