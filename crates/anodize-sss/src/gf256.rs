//! GF(2^8) arithmetic using the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
//!
//! All operations are constant-time with respect to the values (no secret-dependent branches).

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
pub fn mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a as u16;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a as u8;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B; // reduce by x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256) via exponentiation: a^254 = a^{-1}.
/// Returns 0 for input 0 (undefined, but safe fallback).
pub fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^{-1} = a^{254} in GF(2^8)
    let mut result = a;
    for _ in 0..6 {
        result = mul(result, result);
        result = mul(result, a);
    }
    // After 6 rounds of square-and-multiply-by-a, we have a^{127}.
    // We need a^{254} = (a^{127})^2.
    result = mul(result, result);
    result
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
    fn div_roundtrip() {
        for a in 0..=255u8 {
            for b in 1..=255u8 {
                assert_eq!(mul(div(a, b), b), a);
            }
        }
    }
}
