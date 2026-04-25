use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("JSON parse error at record {seq}: {source}")]
    Json { seq: u64, source: serde_json::Error },
    #[error("hash chain broken at record {seq}: expected {expected}, got {actual}")]
    ChainBroken {
        seq: u64,
        expected: String,
        actual: String,
    },
    #[error("expected seq {expected} but found {actual}")]
    SeqMismatch { expected: u64, actual: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub timestamp: String,
    pub event: String,
    pub op_data: serde_json::Value,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Compute the SHA-256 genesis hash from a root CA certificate's DER bytes.
pub fn genesis_hash(root_cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(root_cert_der).into()
}

fn compute_entry_hash(
    seq: u64,
    timestamp: &str,
    event: &str,
    op_data: &serde_json::Value,
    prev_hash: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(timestamp.as_bytes());
    h.update(event.as_bytes());
    h.update(
        serde_json::to_string(op_data)
            .unwrap_or_default()
            .as_bytes(),
    );
    h.update(prev_hash.as_bytes());
    hex::encode(h.finalize())
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // RFC 3339 UTC without external deps: format as YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let (y, mo, d, h, mi, sec) = epoch_to_ymd_hms(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let sec = (secs % 60) as u32;
    let mins = secs / 60;
    let min = (mins % 60) as u32;
    let hours = mins / 60;
    let hour = (hours % 24) as u32;
    let days = hours / 24;

    // Days since 1970-01-01
    let mut year = 1970u32;
    let mut remaining = days;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    let day = remaining as u32 + 1;

    (year, month, day, hour, min, sec)
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

pub struct AuditLog {
    path: PathBuf,
    last_hash: String,
    next_seq: u64,
}

impl AuditLog {
    /// Create a new audit log. `genesis_hash` is SHA-256(root_cert_DER).
    pub fn create(path: &Path, genesis: &[u8; 32]) -> Result<Self, AuditError> {
        fs::File::create(path).map_err(|e| AuditError::Io {
            path: path.to_owned(),
            source: e,
        })?;
        Ok(Self {
            path: path.to_owned(),
            last_hash: hex::encode(genesis),
            next_seq: 0,
        })
    }

    /// Open an existing audit log, verify the full hash chain, and return it ready to append.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let file = fs::File::open(path).map_err(|e| AuditError::Io {
            path: path.to_owned(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        let mut last_hash = String::new();
        let mut next_seq = 0u64;

        for (line_idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| AuditError::Io {
                path: path.to_owned(),
                source: e,
            })?;
            if line.trim().is_empty() {
                continue;
            }

            let record: Record = serde_json::from_str(&line).map_err(|e| AuditError::Json {
                seq: line_idx as u64,
                source: e,
            })?;

            if record.seq != next_seq {
                return Err(AuditError::SeqMismatch {
                    expected: next_seq,
                    actual: record.seq,
                });
            }

            let expected_hash = compute_entry_hash(
                record.seq,
                &record.timestamp,
                &record.event,
                &record.op_data,
                &record.prev_hash,
            );
            if expected_hash != record.entry_hash {
                return Err(AuditError::ChainBroken {
                    seq: record.seq,
                    expected: expected_hash,
                    actual: record.entry_hash.clone(),
                });
            }

            last_hash = record.entry_hash;
            next_seq += 1;
        }

        Ok(Self {
            path: path.to_owned(),
            last_hash,
            next_seq,
        })
    }

    /// Append a new record to the log and return it.
    pub fn append(
        &mut self,
        event: &str,
        op_data: serde_json::Value,
    ) -> Result<Record, AuditError> {
        let seq = self.next_seq;
        let timestamp = now_rfc3339();
        let entry_hash = compute_entry_hash(seq, &timestamp, event, &op_data, &self.last_hash);

        let record = Record {
            seq,
            timestamp,
            event: event.to_owned(),
            op_data,
            prev_hash: self.last_hash.clone(),
            entry_hash: entry_hash.clone(),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;

        let mut line = serde_json::to_string(&record).expect("record is always serializable");
        line.push('\n');
        file.write_all(line.as_bytes())
            .map_err(|e| AuditError::Io {
                path: self.path.clone(),
                source: e,
            })?;

        self.last_hash = entry_hash;
        self.next_seq += 1;

        Ok(record)
    }
}

/// Walk the JSONL log, verify every entry hash and chain linkage, return the record count.
pub fn verify_log(path: &Path) -> Result<u64, AuditError> {
    let file = fs::File::open(path).map_err(|e| AuditError::Io {
        path: path.to_owned(),
        source: e,
    })?;
    let reader = BufReader::new(file);

    let mut count = 0u64;

    for line in reader.lines() {
        let line = line.map_err(|e| AuditError::Io {
            path: path.to_owned(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let record: Record = serde_json::from_str(&line).map_err(|e| AuditError::Json {
            seq: count,
            source: e,
        })?;

        if record.seq != count {
            return Err(AuditError::SeqMismatch {
                expected: count,
                actual: record.seq,
            });
        }

        let expected_hash = compute_entry_hash(
            record.seq,
            &record.timestamp,
            &record.event,
            &record.op_data,
            &record.prev_hash,
        );
        if expected_hash != record.entry_hash {
            return Err(AuditError::ChainBroken {
                seq: record.seq,
                expected: expected_hash,
                actual: record.entry_hash,
            });
        }

        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn genesis() -> [u8; 32] {
        genesis_hash(b"fake-root-cert-der")
    }

    #[test]
    fn hash_chain_arithmetic() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_owned();
        drop(f);

        let mut log = AuditLog::create(&path, &genesis()).unwrap();

        let r0 = log
            .append("key.generate", serde_json::json!({"key": "root"}))
            .unwrap();
        let r1 = log
            .append("cert.issue", serde_json::json!({"serial": 1}))
            .unwrap();
        let r2 = log
            .append("crl.issue", serde_json::json!({"count": 0}))
            .unwrap();

        assert_eq!(r0.seq, 0);
        assert_eq!(r1.seq, 1);
        assert_eq!(r2.seq, 2);

        // Each record's prev_hash is the prior record's entry_hash.
        assert_eq!(r0.prev_hash, hex::encode(genesis()));
        assert_eq!(r1.prev_hash, r0.entry_hash);
        assert_eq!(r2.prev_hash, r1.entry_hash);

        // Recompute to confirm.
        let expected = compute_entry_hash(0, &r0.timestamp, &r0.event, &r0.op_data, &r0.prev_hash);
        assert_eq!(r0.entry_hash, expected);

        assert_eq!(verify_log(&path).unwrap(), 3);
    }

    #[test]
    fn single_byte_corruption_detected() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_owned();
        drop(f);

        let mut log = AuditLog::create(&path, &genesis()).unwrap();
        log.append("event.a", serde_json::json!({})).unwrap();
        log.append("event.b", serde_json::json!({})).unwrap();

        // Flip one byte in the JSON (mid-file, in the entry_hash field of record 0).
        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Corrupt the first record's entry_hash by altering its last character.
        let corrupted_line = {
            let line = lines[0];
            let pos = line.rfind('"').unwrap();
            let mut bytes = line.as_bytes().to_vec();
            bytes[pos - 1] ^= 0x01;
            String::from_utf8(bytes).unwrap()
        };
        let new_contents = format!("{}\n{}\n", corrupted_line, lines[1]);
        fs::write(&path, &new_contents).unwrap();

        let err = verify_log(&path).unwrap_err();
        assert!(
            matches!(err, AuditError::ChainBroken { seq: 0, .. }),
            "expected ChainBroken at seq 0, got: {:?}",
            err
        );
    }

    #[test]
    fn roundtrip_serialize() {
        let record = Record {
            seq: 7,
            timestamp: "2026-01-02T03:04:05Z".to_owned(),
            event: "cert.issue".to_owned(),
            op_data: serde_json::json!({"subject": "CN=Test"}),
            prev_hash: "aabb".to_owned(),
            entry_hash: "ccdd".to_owned(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }
}
