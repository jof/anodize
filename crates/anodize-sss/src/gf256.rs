//! GF(2^8) arithmetic using the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
//!
//! All operations are constant-time with respect to their values: loops have
//! fixed iteration counts and all conditional logic uses arithmetic masking
//! instead of branches.  This prevents secret-dependent timing variation.
//!
//! **Verification**: constant-time properties cannot be tested via unit tests.
//! Use `cargo asm anodize_sss::gf256::mul` (or objdump) to confirm the
//! absence of conditional jumps (`je`, `jne`, `cmov` is fine) after each
//! change.  For stronger guarantees, consider ct-grind or dudect.

/// Addition in GF(256) is XOR.
#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is also XOR (additive inverse = identity in char-2 fields).
#[inline]
pub fn sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256) using Russian peasant / shift-and-add.
///
/// Branchless: conditional accumulation and reduction use arithmetic masks.
pub fn mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        // mask = 0xFFFF when b's low bit is 1, else 0x0000
        let mask = 0u16.wrapping_sub(b & 1);
        result ^= (a & mask) as u8;
        // reduce by the irreducible polynomial when bit 7 of a is set
        let reduce = 0u16.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (0x1B & reduce);
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256) via exponentiation: a^254 = a^{-1}.
///
/// Returns 0 for input 0 (0 raised to any power is 0 in GF(256), so the
/// exponentiation loop naturally produces the right answer without an
/// early-return branch).
pub fn inv(a: u8) -> u8 {
    // a^{-1} = a^{254} in GF(2^8)
    let mut result = a;
    for _ in 0..6 {
        result = mul(result, result);
        result = mul(result, a);
    }
    // After 6 rounds of square-and-multiply-by-a, we have a^{127}.
    // We need a^{254} = (a^{127})^2.
    mul(result, result)
}

/// Division in GF(256): a / b = a * b^{-1}. Panics if b == 0.
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    mul(a, inv(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
        }
    }

    #[test]
    fn mul_zero() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
        }
    }

    #[test]
    fn mul_commutative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn inv_roundtrip() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn inv_zero() {
        assert_eq!(inv(0), 0);
    }

    /// Exhaustive comparison against a branchy reference implementation.
    /// This validates that the branchless `mul` produces identical results
    /// for all 65 536 input pairs.
    #[test]
    fn mul_matches_branchy_reference() {
        fn mul_ref(a: u8, b: u8) -> u8 {
            let mut r: u8 = 0;
            let mut a = a as u16;
            let mut b = b;
            for _ in 0..8 {
                if b & 1 != 0 {
                    r ^= a as u8;
                }
                let carry = a & 0x80;
                a <<= 1;
                if carry != 0 {
                    a ^= 0x1B;
                }
                b >>= 1;
            }
            r
        }
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul_ref(a, b), "a={a}, b={b}");
            }
        }
    }

    #[test]
    fn div_roundtrip() {
        for a in 0..=255u8 {
            for b in 1..=255u8 {
                assert_eq!(mul(div(a, b), b), a);
            }
        }
    }
}
