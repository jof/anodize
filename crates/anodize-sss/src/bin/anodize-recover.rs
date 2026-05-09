//! Standalone CLI to reconstruct a YubiHSM PIN from a STATE.JSON file
//! and a quorum of Shamir's Secret Sharing wordlist shares.
//!
//! Usage:
//!     anodize-recover --state /path/to/STATE.JSON
//!
//! The tool interactively prompts for shares, verifies each against the
//! commitments in STATE.JSON, reconstructs the PIN, and prints the
//! hex string suitable for `yubihsm-shell --authkey 2 --password <output>`.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process;

use anodize_config::state::SessionState;
use anodize_sss::{reconstruct, verify_commitment, Share};
use sha2::{Digest, Sha256};

fn main() {
    let state_path = parse_args();

    // Load and validate STATE.JSON.
    let data = match std::fs::read(&state_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", state_path.display());
            process::exit(1);
        }
    };
    let state = match SessionState::from_json(&data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: invalid STATE.JSON: {e}");
            process::exit(1);
        }
    };

    let sss = &state.sss;
    let threshold = sss.threshold;
    let total = sss.total;
    // Share data length = total share bytes - 1 (index) - 1 (checksum).
    // The PIN is 32 bytes, so secret_len = 32.
    let secret_len = 32;

    eprintln!("Loaded STATE.JSON: {threshold}-of-{total} SSS scheme");
    eprintln!("Custodians:");
    for c in &sss.custodians {
        eprintln!("  #{} {}", c.index, c.name);
    }
    eprintln!();

    // Collect shares interactively.
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut collected: Vec<Share> = Vec::new();

    while collected.len() < threshold as usize {
        let remaining = threshold as usize - collected.len();
        eprint!("Enter share ({remaining} more needed), paste wordlist: ");
        io::stderr().flush().ok();

        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            eprintln!("\nerror: unexpected end of input");
            process::exit(1);
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Decode wordlist → Share.
        let share = match Share::from_words(line, secret_len) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  decode error: {e}");
                continue;
            }
        };

        // Look up custodian by index.
        let custodian_pos = sss.custodians.iter().position(|c| c.index == share.index);
        let custodian_pos = match custodian_pos {
            Some(p) => p,
            None => {
                eprintln!(
                    "  error: share index #{} not in custodian roster",
                    share.index
                );
                continue;
            }
        };
        let custodian = &sss.custodians[custodian_pos];

        // Reject duplicates.
        if collected.iter().any(|s| s.index == share.index) {
            eprintln!(
                "  error: share #{} ({}) already collected",
                share.index, custodian.name
            );
            continue;
        }

        // Verify commitment.
        let expected_hex = &sss.share_commitments[custodian_pos];
        let mut expected = [0u8; 32];
        if hex::decode_to_slice(expected_hex, &mut expected).is_err() {
            eprintln!(
                "  error: malformed commitment in STATE.JSON for #{}",
                share.index
            );
            continue;
        }
        if let Err(e) = verify_commitment(&share, &custodian.name, &expected) {
            eprintln!(
                "  COMMITMENT MISMATCH for #{} ({}): {e}",
                share.index, custodian.name
            );
            eprintln!("  Re-enter this share carefully.");
            continue;
        }

        eprintln!("  ✓ accepted #{} ({})", share.index, custodian.name);
        collected.push(share);
    }

    // Reconstruct PIN.
    let pin_bytes = match reconstruct(&collected, threshold) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: PIN reconstruction failed: {e}");
            process::exit(1);
        }
    };

    // Verify against pin_verify_hash.
    let pin_hash = hex::encode(Sha256::digest(&pin_bytes));
    if pin_hash != sss.pin_verify_hash {
        eprintln!("error: reconstructed PIN does not match pin_verify_hash");
        eprintln!("  expected: {}", sss.pin_verify_hash);
        eprintln!("  got:      {pin_hash}");
        eprintln!("Shares may be corrupted or from a different ceremony.");
        process::exit(1);
    }

    eprintln!();
    eprintln!("PIN verified. Use with: yubihsm-shell --authkey 2 --password <pin>");
    eprintln!();

    // Print the hex-encoded PIN to stdout (the only stdout output).
    println!("{}", hex::encode(&pin_bytes));
}

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();

    // Simple arg parsing: --state <path> or -s <path>
    let mut state_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--state" | "-s" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --state requires a path argument");
                    process::exit(1);
                }
                state_path = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                eprintln!("anodize-recover: reconstruct YubiHSM PIN from SSS shares");
                eprintln!();
                eprintln!("Usage: anodize-recover --state <STATE.JSON>");
                eprintln!();
                eprintln!("Interactively prompts for a quorum of wordlist shares,");
                eprintln!("reconstructs the PIN, and prints the hex string to stdout.");
                eprintln!("The output is suitable for yubihsm-shell --authkey 2 --password <pin>.");
                process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                eprintln!("Usage: anodize-recover --state <STATE.JSON>");
                process::exit(1);
            }
        }
        i += 1;
    }

    match state_path {
        Some(p) => p,
        None => {
            eprintln!("error: --state <path> is required");
            eprintln!("Usage: anodize-recover --state <STATE.JSON>");
            process::exit(1);
        }
    }
}
