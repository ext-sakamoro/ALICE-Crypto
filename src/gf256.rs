//! Galois Field GF(2^8) arithmetic.
//!
//! No lookup tables. Pure bit operations.
//! Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)

/// GF(2^8) element
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct GF(pub u8);

impl GF {
    pub const ZERO: GF = GF(0);
    pub const ONE: GF = GF(1);

    #[inline(always)]
    pub const fn new(v: u8) -> Self { GF(v) }

    /// Addition in GF(2^8) = XOR
    #[inline(always)]
    pub const fn add(self, rhs: GF) -> GF { GF(self.0 ^ rhs.0) }

    /// Subtraction in GF(2^8) = XOR (same as add)
    #[inline(always)]
    pub const fn sub(self, rhs: GF) -> GF { self.add(rhs) }

    /// Multiplication in GF(2^8) using Russian Peasant algorithm
    /// Fully unrolled, branchless, constant-time (timing attack resistant)
    #[inline(always)]
    pub const fn mul(self, rhs: GF) -> GF {
        let mut a = self.0;
        let b = rhs.0;
        let mut p: u8 = 0;

        // Branchless: mask = 0xFF if bit set, 0x00 otherwise
        // -(x as i8) as u8: if x=1 → -1 → 0xFF, if x=0 → 0 → 0x00

        // Bit 0
        let m0 = (-((b & 0x01) as i8)) as u8;
        p ^= a & m0;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 1
        let m1 = (-(((b >> 1) & 1) as i8)) as u8;
        p ^= a & m1;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 2
        let m2 = (-(((b >> 2) & 1) as i8)) as u8;
        p ^= a & m2;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 3
        let m3 = (-(((b >> 3) & 1) as i8)) as u8;
        p ^= a & m3;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 4
        let m4 = (-(((b >> 4) & 1) as i8)) as u8;
        p ^= a & m4;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 5
        let m5 = (-(((b >> 5) & 1) as i8)) as u8;
        p ^= a & m5;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 6
        let m6 = (-(((b >> 6) & 1) as i8)) as u8;
        p ^= a & m6;
        let hi = (a >> 7) & 1;
        a = (a << 1) ^ (0x1B & (-(hi as i8)) as u8);

        // Bit 7 (no xtime needed after)
        let m7 = (-(((b >> 7) & 1) as i8)) as u8;
        p ^= a & m7;

        GF(p)
    }

    /// Multiplicative inverse using Fermat's little theorem
    /// a^(-1) = a^254 in GF(2^8)
    /// Fully unrolled addition chain (zero branches)
    #[inline(always)]
    pub const fn inv(self) -> Option<GF> {
        if self.0 == 0 { return None; }

        // Addition chain for a^254
        // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
        // = 2(1 + 2(1 + 2(1 + 2(1 + 2(1 + 2(1 + 2))))))
        let a = self;
        let a2 = a.mul(a);           // a^2
        let a3 = a2.mul(a);          // a^3
        let a6 = a3.mul(a3);         // a^6
        let a12 = a6.mul(a6);        // a^12
        let a15 = a12.mul(a3);       // a^15
        let a30 = a15.mul(a15);      // a^30
        let a60 = a30.mul(a30);      // a^60
        let a63 = a60.mul(a3);       // a^63
        let a126 = a63.mul(a63);     // a^126
        let a252 = a126.mul(a126);   // a^252
        let a254 = a252.mul(a2);     // a^254

        Some(a254)
    }

    /// Division: a / b = a * b^(-1)
    #[inline(always)]
    pub const fn div(self, rhs: GF) -> Option<GF> {
        match rhs.inv() {
            Some(inv) => Some(self.mul(inv)),
            None => None,
        }
    }
}

/// Montgomery Batch Inversion
/// Computes inverses of multiple elements with only ONE actual inversion.
///
/// Algorithm:
/// 1. Compute cumulative products: p[i] = a[0] * a[1] * ... * a[i]
/// 2. Compute inv(p[n-1]) once
/// 3. Derive individual inverses in reverse order
///
/// Cost: 1 inv() + 3*(n-1) mul() instead of n * inv()
/// For n=10: 1 + 27 = 28 mul-equivalents vs 10 * 11 = 110 mul-equivalents
///
/// Returns None if any input is zero.
#[inline]
pub fn batch_inv(inputs: &[GF], outputs: &mut [GF]) -> Option<()> {
    let n = inputs.len();
    if n == 0 { return Some(()); }
    if outputs.len() < n { return None; }

    // Check for zeros and compute cumulative products
    // Using outputs as scratch space for products
    outputs[0] = inputs[0];
    if inputs[0].0 == 0 { return None; }

    for i in 1..n {
        if inputs[i].0 == 0 { return None; }
        outputs[i] = outputs[i - 1].mul(inputs[i]);
    }

    // Single inversion of the total product
    let mut inv_acc = outputs[n - 1].inv()?;

    // Derive individual inverses in reverse
    for i in (1..n).rev() {
        // inv(a[i]) = inv_acc * products[i-1]
        outputs[i] = inv_acc.mul(outputs[i - 1]);
        // Update accumulator: inv_acc = inv_acc * a[i]
        inv_acc = inv_acc.mul(inputs[i]);
    }

    // First element
    outputs[0] = inv_acc;

    Some(())
}

/// Batch inversion with stack-allocated buffer (max 255 elements)
/// Returns the number of inverses computed.
#[inline]
pub fn batch_inv_stack<const N: usize>(
    inputs: &[GF],
    outputs: &mut [GF; N],
) -> Option<usize> {
    let n = inputs.len();
    if n == 0 { return Some(0); }
    if n > N { return None; }

    batch_inv(inputs, &mut outputs[..n])?;
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(GF(0x53).add(GF(0xCA)), GF(0x99));
    }

    #[test]
    fn test_mul() {
        assert_eq!(GF(0x53).mul(GF(0xCA)), GF(0x01));
        assert_eq!(GF(0x02).mul(GF(0x87)), GF(0x15));
    }

    #[test]
    fn test_inv() {
        for i in 1..=255u8 {
            let a = GF(i);
            let inv = a.inv().unwrap();
            assert_eq!(a.mul(inv), GF::ONE);
        }
    }

    #[test]
    fn test_zero_inv() {
        assert!(GF::ZERO.inv().is_none());
    }

    #[test]
    fn test_batch_inv() {
        let inputs = [GF(3), GF(5), GF(7), GF(11), GF(13)];
        let mut outputs = [GF::ZERO; 5];

        batch_inv(&inputs, &mut outputs).unwrap();

        // Verify each inverse
        for i in 0..5 {
            assert_eq!(inputs[i].mul(outputs[i]), GF::ONE);
        }
    }

    #[test]
    fn test_batch_inv_with_zero() {
        let inputs = [GF(3), GF(0), GF(7)];
        let mut outputs = [GF::ZERO; 3];

        // Should fail because of zero
        assert!(batch_inv(&inputs, &mut outputs).is_none());
    }
}
