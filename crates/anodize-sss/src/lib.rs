//! Shamir's Secret Sharing over GF(2^8) for Anodize ceremony PIN splitting.
//!
//! Provides (k, n) threshold secret sharing: any `k` shares reconstruct the
//! secret; fewer than `k` shares reveal no information about the secret.
//!
//! Each byte of the secret is split independently using a random polynomial
//! of degree `k - 1` in GF(256). Share indices start at 1 (x = 0 is reserved
//! for the secret itself).

pub mod gf256;
mod wordlist;

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub use wordlist::{decode_words, encode_words, is_valid_word, prefix_matches};

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SssError {
    #[error("threshold must be >= 2, got {0}")]
    ThresholdTooLow(u8),
    #[error("total must be >= threshold, got threshold={threshold}, total={total}")]
    TotalBelowThreshold { threshold: u8, total: u8 },
    #[error("total must be <= 255, got {0}")]
    TotalTooHigh(u8),
    #[error("empty secret")]
    EmptySecret,
    #[error("not enough shares: need {threshold}, got {got}")]
    NotEnoughShares { threshold: u8, got: usize },
    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),
    #[error("share {index} data length {got} != expected {expected}")]
    ShareLengthMismatch {
        index: u8,
        expected: usize,
        got: usize,
    },
    #[error("share checksum mismatch for index {0}")]
    ChecksumMismatch(u8),
    #[error("share commitment mismatch for index {0}")]
    CommitmentMismatch(u8),
    #[error("CSPRNG failure: {0}")]
    Rng(getrandom::Error),
    #[error("wordlist decode error: {0}")]
    WordlistDecode(String),
}

// ── Share ───────────────────────────────────────────────────────────────────

/// A single share of a split secret.
#[derive(Clone, Debug)]
pub struct Share {
    /// The x-coordinate (evaluation point), 1-indexed.
    pub index: u8,
    /// The y-values: one byte per byte of the original secret.
    pub data: Vec<u8>,
    /// CRC-8 checksum over `[index] || data` for transcription error detection.
    pub checksum: u8,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Share {
    /// Serialize to bytes: `index || data || checksum`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len() + 1);
        out.push(self.index);
        out.extend_from_slice(&self.data);
        out.push(self.checksum);
        out
    }

    /// Deserialize from bytes: `index || data || checksum`.
    /// `secret_len` is the expected length of the data portion.
    pub fn from_bytes(bytes: &[u8], secret_len: usize) -> Result<Self, SssError> {
        let expected_total = 1 + secret_len + 1;
        if bytes.len() != expected_total {
            return Err(SssError::ShareLengthMismatch {
                index: bytes.first().copied().unwrap_or(0),
                expected: expected_total,
                got: bytes.len(),
            });
        }
        let index = bytes[0];
        let data = bytes[1..1 + secret_len].to_vec();
        let checksum = bytes[1 + secret_len];
        let expected_checksum = crc8_compute(index, &data);
        if checksum != expected_checksum {
            return Err(SssError::ChecksumMismatch(index));
        }
        Ok(Share {
            index,
            data,
            checksum,
        })
    }

    /// Encode this share as a wordlist string for human transcription.
    pub fn to_words(&self) -> String {
        encode_words(&self.to_bytes())
    }

    /// Decode a share from a wordlist string.
    pub fn from_words(words: &str, secret_len: usize) -> Result<Self, SssError> {
        let bytes = decode_words(words).map_err(|e| SssError::WordlistDecode(e.to_string()))?;
        Self::from_bytes(&bytes, secret_len)
    }

    /// Compute the commitment hash for this share: SHA-256(index || custodian_name || data).
    pub fn commitment(&self, custodian_name: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([self.index]);
        h.update(custodian_name.as_bytes());
        h.update(&self.data);
        h.finalize().into()
    }
}

// ── CRC-8 ───────────────────────────────────────────────────────────────────

/// CRC-8/AUTOSAR (poly 0x2F) over `[index] || data`.
///
/// Branchless: the polynomial XOR uses an arithmetic mask instead of a branch.
fn crc8_compute(index: u8, data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &byte in std::iter::once(&index).chain(data.iter()) {
        crc ^= byte;
        for _ in 0..8 {
            // mask = 0xFF when MSB is set, else 0x00
            let mask = 0u8.wrapping_sub(crc >> 7);
            crc = (crc << 1) ^ (0x2F & mask);
        }
    }
    crc ^ 0xFF
}

// ── Split ───────────────────────────────────────────────────────────────────

/// Split `secret` into `total` shares with a threshold of `threshold`.
///
/// Returns one `Share` per share-holder. Any `threshold` shares can
/// reconstruct the secret via `reconstruct()`.
pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>, SssError> {
    if threshold < 2 {
        return Err(SssError::ThresholdTooLow(threshold));
    }
    if total < threshold {
        return Err(SssError::TotalBelowThreshold { threshold, total });
    }
    if total == 0 {
        return Err(SssError::TotalTooHigh(0));
    }
    if secret.is_empty() {
        return Err(SssError::EmptySecret);
    }

    let secret_len = secret.len();
    let coeff_count = (threshold - 1) as usize; // random coefficients per byte

    // Generate all random coefficients at once
    let mut rand_bytes = vec![0u8; secret_len * coeff_count];
    getrandom::getrandom(&mut rand_bytes).map_err(SssError::Rng)?;

    let mut shares: Vec<Share> = (1..=total)
        .map(|idx| Share {
            index: idx,
            data: Vec::with_capacity(secret_len),
            checksum: 0,
        })
        .collect();

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Coefficients: a_0 = secret_byte, a_1..a_{k-1} = random
        let coeff_offset = byte_idx * coeff_count;
        let coeffs = &rand_bytes[coeff_offset..coeff_offset + coeff_count];

        for share in shares.iter_mut() {
            let x = share.index;
            // Evaluate polynomial: a_0 + a_1*x + a_2*x^2 + ...
            let mut y = secret_byte;
            let mut x_pow = x; // x^1
            for &coeff in coeffs {
                y = gf256::add(y, gf256::mul(coeff, x_pow));
                x_pow = gf256::mul(x_pow, x);
            }
            share.data.push(y);
        }
    }

    // Compute checksums
    for share in shares.iter_mut() {
        share.checksum = crc8_compute(share.index, &share.data);
    }

    // Zeroize random coefficients
    rand_bytes.zeroize();

    Ok(shares)
}

// ── Reconstruct ─────────────────────────────────────────────────────────────

/// Reconstruct the secret from `threshold` or more shares using Lagrange
/// interpolation at x = 0.
pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<Vec<u8>, SssError> {
    if shares.len() < threshold as usize {
        return Err(SssError::NotEnoughShares {
            threshold,
            got: shares.len(),
        });
    }

    // Check for duplicate indices
    let mut seen = [false; 256];
    for share in shares {
        if seen[share.index as usize] {
            return Err(SssError::DuplicateIndex(share.index));
        }
        seen[share.index as usize] = true;
    }

    // All shares must have the same length
    let secret_len = shares[0].data.len();
    for share in &shares[1..] {
        if share.data.len() != secret_len {
            return Err(SssError::ShareLengthMismatch {
                index: share.index,
                expected: secret_len,
                got: share.data.len(),
            });
        }
    }

    // Use exactly `threshold` shares
    let active = &shares[..threshold as usize];

    let mut secret = vec![0u8; secret_len];

    for byte_idx in 0..secret_len {
        // Lagrange interpolation at x = 0
        let mut value = 0u8;

        for (i, share_i) in active.iter().enumerate() {
            let x_i = share_i.index;
            let y_i = share_i.data[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            // L_i(0) = prod_{j != i} (0 - x_j) / (x_i - x_j)
            //        = prod_{j != i} x_j / (x_i - x_j)
            //        (since subtraction = XOR = addition in GF(2^8))
            let mut basis = 1u8;
            for (j, share_j) in active.iter().enumerate() {
                if i == j {
                    continue;
                }
                let x_j = share_j.index;
                // numerator: x_j (since 0 - x_j = x_j in GF(256))
                // denominator: x_i - x_j = x_i ^ x_j
                basis = gf256::mul(basis, gf256::div(x_j, gf256::sub(x_i, x_j)));
            }

            value = gf256::add(value, gf256::mul(y_i, basis));
        }

        secret[byte_idx] = value;
    }

    Ok(secret)
}

// ── Commitment verification ─────────────────────────────────────────────────

/// Verify a share against its stored commitment.
/// Returns `Ok(())` if the commitment matches, `Err` otherwise.
pub fn verify_commitment(
    share: &Share,
    custodian_name: &str,
    expected_commitment: &[u8; 32],
) -> Result<(), SssError> {
    let actual = share.commitment(custodian_name);
    if actual != *expected_commitment {
        return Err(SssError::CommitmentMismatch(share.index));
    }
    Ok(())
}

/// Compute the PIN verification hash: SHA-256(pin_bytes).
pub fn pin_verify_hash(pin: &[u8]) -> [u8; 32] {
    Sha256::digest(pin).into()
}

/// Check a reconstructed PIN against the hex-encoded hash stored in STATE.JSON.
pub fn verify_pin_hash(pin: &[u8], expected_hex: &str) -> bool {
    hex::encode(pin_verify_hash(pin)) == expected_hex
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_reconstruct_2_of_3() {
        let secret = b"this-is-a-test-pin-32-bytes-long";
        let shares = split(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares reconstruct
        for i in 0..3 {
            for j in (i + 1)..3 {
                let pair = vec![shares[i].clone(), shares[j].clone()];
                let recovered = reconstruct(&pair, 2).unwrap();
                assert_eq!(recovered, secret, "failed with shares {i},{j}");
            }
        }
    }

    #[test]
    fn split_reconstruct_3_of_5() {
        let secret = b"another-secret-of-various-length!";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Any 3 shares reconstruct
        let combo = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = reconstruct(&combo, 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn insufficient_shares_fails() {
        let secret = b"test";
        let shares = split(secret, 2, 3).unwrap();
        let err = reconstruct(&shares[..1], 2).unwrap_err();
        assert!(matches!(err, SssError::NotEnoughShares { .. }));
    }

    #[test]
    fn single_share_reveals_nothing() {
        // With a random polynomial of degree 1, a single point gives no
        // information about the constant term. We verify this statistically:
        // run multiple splits and check that the same single share doesn't
        // consistently produce the same reconstruction.
        let secret = b"x";
        let mut reconstructions = std::collections::HashSet::new();
        for _ in 0..20 {
            let shares = split(secret, 2, 3).unwrap();
            // "Reconstruct" with 1 share by just reading the y-value — this is
            // NOT the secret, just the evaluation at that point.
            reconstructions.insert(shares[0].data[0]);
        }
        // With overwhelming probability, a single share's y-values vary
        assert!(reconstructions.len() > 1);
    }

    #[test]
    fn duplicate_index_rejected() {
        let secret = b"test";
        let shares = split(secret, 2, 3).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        let err = reconstruct(&dup, 2).unwrap_err();
        assert!(matches!(err, SssError::DuplicateIndex(_)));
    }

    #[test]
    fn checksum_catches_corruption() {
        let secret = b"test-secret-data";
        let shares = split(secret, 2, 3).unwrap();
        let bytes = shares[0].to_bytes();

        // Corrupt one data byte
        let mut corrupted = bytes.clone();
        corrupted[2] ^= 0x01;

        let err = Share::from_bytes(&corrupted, secret.len()).unwrap_err();
        assert!(matches!(err, SssError::ChecksumMismatch(_)));
    }

    #[test]
    fn share_byte_roundtrip() {
        let secret = b"roundtrip-test";
        let shares = split(secret, 2, 3).unwrap();
        for share in &shares {
            let bytes = share.to_bytes();
            let recovered = Share::from_bytes(&bytes, secret.len()).unwrap();
            assert_eq!(recovered.index, share.index);
            assert_eq!(recovered.data, share.data);
            assert_eq!(recovered.checksum, share.checksum);
        }
    }

    #[test]
    fn commitment_verification() {
        let secret = b"test";
        let shares = split(secret, 2, 3).unwrap();
        let names = ["Alice", "Bob", "Carol"];

        // Compute commitments
        let commitments: Vec<[u8; 32]> = shares
            .iter()
            .zip(names.iter())
            .map(|(s, n)| s.commitment(n))
            .collect();

        // Verify — correct name passes
        for (i, share) in shares.iter().enumerate() {
            assert!(verify_commitment(share, names[i], &commitments[i]).is_ok());
        }

        // Wrong name fails
        assert!(verify_commitment(&shares[0], "Eve", &commitments[0]).is_err());

        // Index spoofing: change index, recompute checksum — commitment still fails
        let mut spoofed = shares[0].clone();
        spoofed.index = shares[1].index;
        spoofed.checksum = crc8_compute(spoofed.index, &spoofed.data);
        assert!(verify_commitment(&spoofed, names[1], &commitments[1]).is_err());
    }

    #[test]
    fn pin_verify_hash_matches() {
        let pin = b"some-random-pin";
        let hash = pin_verify_hash(pin);

        let shares = split(pin, 2, 3).unwrap();
        let recovered = reconstruct(&[shares[0].clone(), shares[2].clone()], 2).unwrap();

        assert_eq!(pin_verify_hash(&recovered), hash);
    }

    #[test]
    fn wordlist_roundtrip() {
        let secret = b"wl-test-pin";
        let shares = split(secret, 2, 3).unwrap();
        for share in &shares {
            let words = share.to_words();
            let recovered = Share::from_words(&words, secret.len()).unwrap();
            assert_eq!(recovered.index, share.index);
            assert_eq!(recovered.data, share.data);
        }
    }

    #[test]
    fn threshold_too_low() {
        assert!(matches!(
            split(b"x", 1, 3),
            Err(SssError::ThresholdTooLow(1))
        ));
    }

    #[test]
    fn total_below_threshold() {
        assert!(matches!(
            split(b"x", 3, 2),
            Err(SssError::TotalBelowThreshold { .. })
        ));
    }

    #[test]
    fn empty_secret() {
        assert!(matches!(split(b"", 2, 3), Err(SssError::EmptySecret)));
    }

    #[test]
    fn all_share_combinations_2_of_3() {
        // Exhaustive: every pair out of 3 shares reconstructs correctly
        let secret = [0xDE, 0xAD, 0xBE, 0xEF];
        let shares = split(&secret, 2, 3).unwrap();
        let pairs = [(0, 1), (0, 2), (1, 2)];
        for (a, b) in pairs {
            let pair = vec![shares[a].clone(), shares[b].clone()];
            let r = reconstruct(&pair, 2).unwrap();
            assert_eq!(r, secret);
        }
    }

    #[test]
    fn large_secret() {
        // 64-byte secret (max practical PIN size)
        let mut secret = [0u8; 64];
        getrandom::getrandom(&mut secret).unwrap();
        let shares = split(&secret, 2, 3).unwrap();
        let r = reconstruct(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        assert_eq!(r, secret);
    }

    /// End-to-end recovery flow: mirrors what anodize-recover does.
    /// Generate PIN → split → wordlist encode → build commitments/hash →
    /// wordlist decode → verify commitments → reconstruct → verify hash.
    #[test]
    fn end_to_end_recovery_flow() {
        let names = ["Alice", "Bob", "Carol"];
        let threshold = 2u8;
        let total = 3u8;

        // Generate random 32-byte PIN (same as ceremony_ops).
        let mut pin_bytes = [0u8; 32];
        getrandom::getrandom(&mut pin_bytes).unwrap();

        // Split into shares.
        let shares = split(&pin_bytes, threshold, total).unwrap();

        // Build commitments and pin_verify_hash (same as STATE.JSON).
        let commitments: Vec<[u8; 32]> = shares
            .iter()
            .zip(names.iter())
            .map(|(s, n)| s.commitment(n))
            .collect();
        let expected_pin_hash = pin_verify_hash(&pin_bytes);

        // Encode shares to wordlists (simulating paper transcription).
        let wordlists: Vec<String> = shares.iter().map(|s| s.to_words()).collect();

        // Recovery: decode wordlists back, verify commitments, reconstruct.
        let mut recovered_shares = Vec::new();
        for (i, words) in wordlists.iter().enumerate().take(threshold as usize) {
            let share = Share::from_words(words, 32).unwrap();
            assert_eq!(share.index, shares[i].index);
            verify_commitment(&share, names[i], &commitments[i]).unwrap();
            recovered_shares.push(share);
        }

        let recovered = reconstruct(&recovered_shares, threshold).unwrap();
        assert_eq!(recovered, pin_bytes);
        assert_eq!(pin_verify_hash(&recovered), expected_pin_hash);

        // The hex-encoded PIN is what yubihsm-shell receives.
        let pin_hex = hex::encode(&recovered);
        assert_eq!(pin_hex.len(), 64);
        assert_eq!(pin_hex, hex::encode(&pin_bytes));
    }

    /// PIN rotation round-trip: mirrors the RekeyShares flow.
    /// Old PIN → reconstruct from old shares → generate NEW PIN → split new →
    /// distribute → verify all new shares → reconstruct new → confirm match →
    /// verify old and new PINs are distinct.
    #[test]
    fn pin_rotation_round_trip() {
        let old_names = ["Alice", "Bob", "Carol"];
        let new_names = ["Dave", "Eve", "Frank", "Grace"];
        let old_threshold = 2u8;
        let new_threshold = 3u8;

        // ── Step 1: establish old PIN (simulates prior InitRoot) ──
        let mut old_pin = [0u8; 32];
        getrandom::getrandom(&mut old_pin).unwrap();
        let old_shares = split(&old_pin, old_threshold, old_names.len() as u8).unwrap();
        let old_hash = pin_verify_hash(&old_pin);

        // ── Step 2: reconstruct old PIN from quorum ──
        let reconstructed_old =
            reconstruct(&old_shares[..old_threshold as usize], old_threshold).unwrap();
        assert_eq!(reconstructed_old, old_pin);
        assert!(verify_pin_hash(&reconstructed_old, &hex::encode(old_hash)));

        // ── Step 3: generate new random PIN ──
        let mut new_pin = [0u8; 32];
        getrandom::getrandom(&mut new_pin).unwrap();
        // New and old PINs must differ (probabilistic, but 2^256 collision is impossible)
        assert_ne!(old_pin, new_pin);

        // ── Step 4: split new PIN to new custodians ──
        let new_shares = split(&new_pin, new_threshold, new_names.len() as u8).unwrap();
        let new_commitments: Vec<[u8; 32]> = new_shares
            .iter()
            .zip(new_names.iter())
            .map(|(s, n)| s.commitment(n))
            .collect();
        let new_hash = pin_verify_hash(&new_pin);

        // ── Step 5: verify ALL new shares (simulate share verification phase) ──
        let wordlists: Vec<String> = new_shares.iter().map(|s| s.to_words()).collect();
        let mut verified_shares = Vec::new();
        for (i, words) in wordlists.iter().enumerate() {
            let share = Share::from_words(words, 32).unwrap();
            verify_commitment(&share, new_names[i], &new_commitments[i]).unwrap();
            verified_shares.push(share);
        }

        // ── Step 6: reconstruct new PIN from verified shares (round-trip check) ──
        let reconstructed_new =
            reconstruct(&verified_shares[..new_threshold as usize], new_threshold).unwrap();
        assert_eq!(reconstructed_new, new_pin, "round-trip check must pass");
        assert_eq!(
            hex::encode(pin_verify_hash(&reconstructed_new)),
            hex::encode(new_hash)
        );

        // ── Step 7: confirm old PIN hash no longer matches ──
        assert!(!verify_pin_hash(&reconstructed_new, &hex::encode(old_hash)));
        assert!(verify_pin_hash(&reconstructed_new, &hex::encode(new_hash)));

        // At this point, change_pin(old, new) would be called on the HSM.
    }
}
