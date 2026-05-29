//! YubiHSM multi-device research spike.
//!
//! Tests three things:
//!   1. Can we enumerate all connected YubiHSM 2 serials?
//!   2. Can we hold two Client sessions open simultaneously?
//!   3. Can we wrap-export from one and wrap-import into the other?
//!
//! Usage (on a machine with two YubiHSM 2 devices):
//!   yubihsm_enum                   # enumerate only
//!   yubihsm_enum --dual A B        # dual-connect test (serials as decimal)
//!   yubihsm_enum --roundtrip A B   # full wrap round-trip test

use std::env;
use std::process;

/// Wrap key ID used for the backup spike (matches planned constant).
const WRAP_KEY_ID: yubihsm::object::Id = 0x0200;

/// Temporary test signing key — distinct from the real SIGNING_KEY_ID (0x0100).
const TEST_KEY_ID: yubihsm::object::Id = 0x0FFF;

/// Factory-default auth key on a fresh YubiHSM 2.
const DEFAULT_AUTH_KEY_ID: yubihsm::object::Id = 1;
const DEFAULT_AUTH_PASSWORD: &[u8] = b"password";

fn main() {
    let args: Vec<String> = env::args().collect();

    // -- Step 1: always enumerate -----------------------------------------------
    println!("=== YubiHSM 2 Device Enumeration ===\n");
    let serials = enumerate();

    if serials.is_empty() {
        eprintln!("No YubiHSM 2 devices found. Exiting.");
        process::exit(1);
    }

    // -- Optional dual/roundtrip tests ------------------------------------------
    match args.get(1).map(|s| s.as_str()) {
        Some("--dual") => {
            let (a, b) = parse_serial_pair(&args);
            println!("\n=== Dual Connection Test ===\n");
            dual_connect(a, b);
        }
        Some("--roundtrip") => {
            let (a, b) = parse_serial_pair(&args);
            println!("\n=== Dual Connection Test ===\n");
            let (client_a, client_b) = dual_connect(a, b);
            println!("\n=== Wrap Round-Trip Test ===\n");
            wrap_roundtrip(&client_a, &client_b, a, b);
        }
        Some("--reset") => {
            println!("\n=== Factory Reset All Devices ===\n");
            factory_reset_all(&serials);
        }
        Some("--probe") => {
            // --probe PIN SERIAL
            let pin = args.get(2).unwrap_or_else(|| {
                eprintln!("Usage: yubihsm_enum --probe PIN SERIAL");
                process::exit(1);
            });
            let serial_str = format!(
                "{:0>10}",
                args.get(3).unwrap_or_else(|| {
                    eprintln!("Usage: yubihsm_enum --probe PIN SERIAL");
                    process::exit(1);
                })
            );
            let serial: yubihsm::device::SerialNumber = serial_str.parse().unwrap_or_else(|e| {
                eprintln!("Invalid serial: {e}");
                process::exit(1);
            });
            println!("\n=== Probe Device {serial} ===\n");
            probe_bootstrapped(serial, pin);
        }
        Some("--export-test") => {
            // --export-test PIN SERIAL_SRC SERIAL_DST
            let pin = args.get(2).unwrap_or_else(|| {
                eprintln!("Usage: yubihsm_enum --export-test PIN SERIAL_SRC SERIAL_DST");
                process::exit(1);
            });
            let src_str = format!(
                "{:0>10}",
                args.get(3).unwrap_or_else(|| {
                    eprintln!("Usage: yubihsm_enum --export-test PIN SERIAL_SRC SERIAL_DST");
                    process::exit(1);
                })
            );
            let dst_str = format!(
                "{:0>10}",
                args.get(4).unwrap_or_else(|| {
                    eprintln!("Usage: yubihsm_enum --export-test PIN SERIAL_SRC SERIAL_DST");
                    process::exit(1);
                })
            );
            let src: yubihsm::device::SerialNumber = src_str.parse().unwrap();
            let dst: yubihsm::device::SerialNumber = dst_str.parse().unwrap();
            println!("\n=== Export-Wrapped Test: {src} → {dst} ===\n");
            export_test(src, dst, pin);
        }
        Some(other) => {
            eprintln!("Unknown flag: {other}");
            eprintln!("Usage: yubihsm_enum [--dual|--roundtrip|--reset|--probe|--export-test] ...");
            process::exit(1);
        }
        None => {
            // Enumerate-only mode.
            if serials.len() >= 2 {
                println!(
                    "\nTip: run with --dual {} {} to test simultaneous connections",
                    serials[0], serials[1]
                );
            }
        }
    }
}

// ── Enumerate ──────────────────────────────────────────────────────────────────

fn enumerate() -> Vec<yubihsm::device::SerialNumber> {
    // Devices::serial_numbers() uses rusb internally to find all VID=1050 PID=0030.
    match yubihsm::connector::usb::Devices::serial_numbers() {
        Ok(serials) => {
            println!("Found {} device(s):", serials.len());
            for sn in &serials {
                println!("  Serial: {sn}");

                // Try connecting to get firmware version + auth status.
                let info = probe_device(*sn);
                if let Some((fw, auth_status)) = info {
                    println!("    Firmware:  {fw}");
                    println!("    Auth:      {auth_status}");
                } else {
                    println!("    (could not probe — device may be in use)");
                }
            }
            serials
        }
        Err(e) => {
            eprintln!("Enumeration failed: {e}");
            vec![]
        }
    }
}

/// Probe a single device by serial: try default auth, report firmware + auth state.
fn probe_device(serial: yubihsm::device::SerialNumber) -> Option<(String, &'static str)> {
    let cfg = yubihsm::UsbConfig {
        serial: Some(serial),
        ..Default::default()
    };
    let connector = yubihsm::Connector::usb(&cfg);

    // Try factory-default auth first.
    let default_creds =
        yubihsm::Credentials::from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_AUTH_PASSWORD);
    if let Ok(client) = yubihsm::Client::open(connector.clone(), default_creds, false) {
        let fw = device_firmware(&client);
        return Some((fw, "factory-default (key 1)"));
    }

    // Default auth failed — device may have been bootstrapped (anodize auth key 2).
    // We can't test key 2 without knowing the password, so just report.
    // Try re-opening with default creds just for device_info (some errors are transient).
    Some(("(auth failed — may be bootstrapped)".into(), "non-default"))
}

fn device_firmware(client: &yubihsm::Client) -> String {
    match client.device_info() {
        Ok(info) => format!(
            "{}.{}.{}",
            info.major_version, info.minor_version, info.build_version
        ),
        Err(e) => format!("(device_info error: {e})"),
    }
}

// ── Dual Connect ───────────────────────────────────────────────────────────────

/// Open authenticated sessions to two different YubiHSMs simultaneously.
/// Returns both clients on success.
fn dual_connect(
    serial_a: yubihsm::device::SerialNumber,
    serial_b: yubihsm::device::SerialNumber,
) -> (yubihsm::Client, yubihsm::Client) {
    println!("Opening client A (serial {serial_a})...");
    let client_a = open_client(serial_a);
    println!("  ✓ Client A connected");

    println!("Opening client B (serial {serial_b})...");
    let client_b = open_client(serial_b);
    println!("  ✓ Client B connected");

    // Verify both are independently functional.
    println!("\nPinging both devices...");
    client_a.echo(b"hello-a").expect("echo on client A failed");
    println!("  ✓ Client A echo OK");

    client_b.echo(b"hello-b").expect("echo on client B failed");
    println!("  ✓ Client B echo OK");

    println!("\n✓ Dual simultaneous connections work!");
    (client_a, client_b)
}

fn open_client(serial: yubihsm::device::SerialNumber) -> yubihsm::Client {
    let cfg = yubihsm::UsbConfig {
        serial: Some(serial),
        ..Default::default()
    };
    let connector = yubihsm::Connector::usb(&cfg);

    // Try default auth first (factory-fresh device).
    let creds = yubihsm::Credentials::from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_AUTH_PASSWORD);
    match yubihsm::Client::open(connector, creds, true) {
        Ok(client) => client,
        Err(e) => {
            eprintln!(
                "Failed to connect to serial {serial} with default auth: {e}\n\
                 If this device has been bootstrapped, this spike only supports\n\
                 factory-default auth (key 1, password 'password')."
            );
            process::exit(1);
        }
    }
}

// ── Wrap Round-Trip ────────────────────────────────────────────────────────────

fn wrap_roundtrip(
    client_a: &yubihsm::Client,
    client_b: &yubihsm::Client,
    serial_a: yubihsm::device::SerialNumber,
    serial_b: yubihsm::device::SerialNumber,
) {
    // 1. Generate a shared AES-256-CCM wrap key on both devices.
    println!("Generating shared wrap key (ID 0x{WRAP_KEY_ID:04X})...");
    let wrap_key_bytes = generate_wrap_key_bytes();
    put_wrap_key(client_a, &wrap_key_bytes, "A");
    put_wrap_key(client_b, &wrap_key_bytes, "B");
    println!("  ✓ Wrap key installed on both devices");

    // 2. Generate a test signing key on device A.
    println!("Generating test P-384 signing key (ID 0x{TEST_KEY_ID:04X}) on A...");
    cleanup_object(client_a, TEST_KEY_ID, yubihsm::object::Type::AsymmetricKey);
    client_a
        .generate_asymmetric_key(
            TEST_KEY_ID,
            "spike-test-key".parse().unwrap(),
            yubihsm::Domain::all(),
            yubihsm::Capability::SIGN_ECDSA | yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            yubihsm::asymmetric::Algorithm::EcP384,
        )
        .expect("generate test key on A");
    println!("  ✓ Test key generated on A");

    // 3. Get public key from A (before export).
    let pubkey_a = client_a
        .get_public_key(TEST_KEY_ID)
        .expect("get_public_key from A");
    println!("  Public key A: {} bytes", pubkey_a.as_ref().len());

    // 4. Export-wrapped from A.
    println!("Exporting wrapped key from A...");
    let wrapped = client_a
        .export_wrapped(
            WRAP_KEY_ID,
            yubihsm::object::Type::AsymmetricKey,
            TEST_KEY_ID,
        )
        .expect("export_wrapped from A");
    println!(
        "  ✓ Wrapped blob: nonce={:02x?}, ciphertext={} bytes",
        wrapped.nonce.0,
        wrapped.ciphertext.len()
    );

    // 5. Import-wrapped into B.
    println!("Importing wrapped key into B...");
    cleanup_object(client_b, TEST_KEY_ID, yubihsm::object::Type::AsymmetricKey);
    let handle = client_b
        .import_wrapped(WRAP_KEY_ID, wrapped)
        .expect("import_wrapped into B");
    println!(
        "  ✓ Imported as object ID 0x{:04X} type {:?}",
        handle.object_id, handle.object_type
    );

    // 6. Verify: compare public keys.
    println!("Verifying public keys match...");
    let pubkey_b = client_b
        .get_public_key(TEST_KEY_ID)
        .expect("get_public_key from B");

    if pubkey_a.as_ref() == pubkey_b.as_ref() {
        println!("  ✓ PUBLIC KEYS MATCH — backup verified!");
    } else {
        println!("  ✗ PUBLIC KEY MISMATCH — backup failed!");
        println!(
            "    A: {:02x?}",
            &pubkey_a.as_ref()[..core::cmp::min(32, pubkey_a.as_ref().len())]
        );
        println!(
            "    B: {:02x?}",
            &pubkey_b.as_ref()[..core::cmp::min(32, pubkey_b.as_ref().len())]
        );
    }

    // 7. Cleanup: remove test objects from both devices.
    println!("\nCleaning up test objects...");
    cleanup_object(client_a, TEST_KEY_ID, yubihsm::object::Type::AsymmetricKey);
    cleanup_object(client_b, TEST_KEY_ID, yubihsm::object::Type::AsymmetricKey);
    cleanup_object(client_a, WRAP_KEY_ID, yubihsm::object::Type::WrapKey);
    cleanup_object(client_b, WRAP_KEY_ID, yubihsm::object::Type::WrapKey);
    println!("  ✓ Cleanup complete");

    println!("\n=== Results ===");
    println!("  Enumeration:          ✓");
    println!("  Dual connections:     ✓");
    println!(
        "  Wrap round-trip:      {}",
        if pubkey_a.as_ref() == pubkey_b.as_ref() {
            "✓"
        } else {
            "✗ FAILED"
        }
    );
    println!("  Source serial:        {serial_a}");
    println!("  Dest serial:          {serial_b}");
}

fn generate_wrap_key_bytes() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("getrandom failed");
    key
}

fn put_wrap_key(client: &yubihsm::Client, key_bytes: &[u8; 32], label: &str) {
    // Delete any existing wrap key at this ID first.
    cleanup_object(client, WRAP_KEY_ID, yubihsm::object::Type::WrapKey);

    client
        .put_wrap_key(
            WRAP_KEY_ID,
            format!("spike-wrap-{label}").parse().unwrap(),
            yubihsm::Domain::all(),
            yubihsm::Capability::EXPORT_WRAPPED
                | yubihsm::Capability::IMPORT_WRAPPED
                | yubihsm::Capability::WRAP_DATA
                | yubihsm::Capability::UNWRAP_DATA,
            // Delegated capabilities: the wrap key must be allowed to wrap
            // objects that have these capabilities.
            yubihsm::Capability::all(),
            yubihsm::wrap::Algorithm::Aes256Ccm,
            key_bytes.to_vec(),
        )
        .unwrap_or_else(|e| panic!("put_wrap_key on {label}: {e}"));
}

fn cleanup_object(
    client: &yubihsm::Client,
    id: yubihsm::object::Id,
    obj_type: yubihsm::object::Type,
) {
    // Ignore errors (object may not exist).
    let _ = client.delete_object(id, obj_type);
}

// ── Factory Reset ─────────────────────────────────────────────────────────────

fn factory_reset_all(serials: &[yubihsm::device::SerialNumber]) {
    for serial in serials {
        print!("Resetting serial {serial}... ");
        let cfg = yubihsm::UsbConfig {
            serial: Some(*serial),
            ..Default::default()
        };

        // Try factory-default auth first.
        let connector = yubihsm::Connector::usb(&cfg);
        let creds = yubihsm::Credentials::from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_AUTH_PASSWORD);
        if let Ok(client) = yubihsm::Client::open(connector, creds, false) {
            // Free audit log entries first (required if force-audit filled the log).
            match client.get_log_entries() {
                Ok(entries) => {
                    if let Some(last) = entries.entries.last() {
                        let _ = client.set_log_index(last.item);
                        println!("freed {} audit log entries... ", entries.entries.len());
                    }
                }
                Err(e) => println!("(get_log_entries: {e})"),
            }
            match client.reset_device() {
                Ok(_) => println!("✓ reset"),
                Err(e) => println!("✗ reset failed: {e}"),
            }
            // Device needs time to reboot after reset
            std::thread::sleep(std::time::Duration::from_secs(3));
            continue;
        }

        // Factory auth failed — try anodize auth key (ID 2) with no password
        // (won't work without the real PIN, but try common dev passwords).
        // If nothing works, the device needs manual reset via yubihsm-shell.
        println!(
            "✗ cannot authenticate (device is bootstrapped — needs manual reset or known PIN)"
        );
    }
    println!("\nDone. Re-enumerate to verify:");
    // Brief delay then re-enumerate
    std::thread::sleep(std::time::Duration::from_secs(2));
    enumerate();
}

// ── Audit log drain ──────────────────────────────────────────────────────────

fn drain_audit_log(client: &yubihsm::Client, label: &str) {
    match client.get_log_entries() {
        Ok(entries) => {
            let count = entries.entries.len();
            if let Some(last) = entries.entries.last() {
                match client.set_log_index(last.item) {
                    Ok(_) => println!(
                        "  Drained {count} audit log entries on {label} (last={})",
                        last.item
                    ),
                    Err(e) => println!("  Warning: set_log_index failed on {label}: {e}"),
                }
            } else {
                println!("  Audit log empty on {label}");
            }
        }
        Err(e) => {
            println!("  get_log_entries failed on {label}: {e}");
            println!("  Attempting brute-force log index drain...");
            // Try setting log index to various values to unblock the HSM.
            for idx in (1u16..=512).rev() {
                if client.set_log_index(idx).is_ok() {
                    println!("  ✓ set_log_index({idx}) succeeded on {label}");
                    // Try again now that some space is freed
                    if let Ok(entries) = client.get_log_entries() {
                        if let Some(last) = entries.entries.last() {
                            let _ = client.set_log_index(last.item);
                            println!("  ✓ Fully drained on {label} (last={})", last.item);
                        }
                    }
                    return;
                }
            }
            println!("  ✗ Could not drain audit log on {label}");
        }
    }
}

// ── Probe bootstrapped device ─────────────────────────────────────────────────

fn open_with_pin(serial: yubihsm::device::SerialNumber, pin: &str) -> yubihsm::Client {
    let cfg = yubihsm::UsbConfig {
        serial: Some(serial),
        ..Default::default()
    };
    let connector = yubihsm::Connector::usb(&cfg);
    let creds = yubihsm::Credentials::from_password(2, pin.as_bytes());
    yubihsm::Client::open(connector, creds, true).unwrap_or_else(|e| {
        eprintln!("Failed to connect with anodize auth key 2: {e}");
        process::exit(1);
    })
}

fn probe_bootstrapped(serial: yubihsm::device::SerialNumber, pin: &str) {
    let client = open_with_pin(serial, pin);
    println!("Connected to {serial} with anodize auth key");

    // List all objects
    let objects = client.list_objects(&[]).unwrap_or_else(|e| {
        eprintln!("list_objects failed: {e}");
        process::exit(1);
    });
    println!("Objects ({}):", objects.len());
    for entry in &objects {
        println!(
            "  ID=0x{:04X}  type={:?}  seq={}",
            entry.object_id, entry.object_type, entry.sequence
        );
        // Get detailed info
        if let Ok(info) = client.get_object_info(entry.object_id, entry.object_type) {
            println!("    algorithm:    {:?}", info.algorithm);
            println!("    capabilities: {:?}", info.capabilities);
            println!("    delegated:    {:?}", info.delegated_capabilities);
            println!("    domains:      {:?}", info.domains);
            println!("    label:        {:?}", info.label);
            println!("    origin:       {:?}", info.origin);
        }
    }
}

fn export_test(src: yubihsm::device::SerialNumber, dst: yubihsm::device::SerialNumber, pin: &str) {
    // Open source, export, then drop client before opening dest (avoids USB contention).
    println!("Opening source {src}...");
    let client_src = open_with_pin(src, pin);
    drain_audit_log(&client_src, "source");

    // Check objects on source
    println!("--- Source {src} objects ---");
    let objects = client_src.list_objects(&[]).unwrap();
    for entry in &objects {
        println!(
            "  ID=0x{:04X}  type={:?}",
            entry.object_id, entry.object_type
        );
        if let Ok(info) = client_src.get_object_info(entry.object_id, entry.object_type) {
            println!(
                "    caps: {:?}  algo: {:?}",
                info.capabilities, info.algorithm
            );
        }
    }

    // Try get_public_key
    println!("\nget_public_key(0x0100)...");
    match client_src.get_public_key(0x0100) {
        Ok(pk) => println!("  ✓ {} bytes", pk.as_ref().len()),
        Err(e) => println!("  ✗ {e}"),
    }

    // Try export_wrapped
    println!("\nexport_wrapped(wrap=0x0200, key=0x0100)...");
    let wrapped = match client_src.export_wrapped(
        WRAP_KEY_ID,
        yubihsm::object::Type::AsymmetricKey,
        0x0100,
    ) {
        Ok(wrapped) => {
            println!(
                "  ✓ nonce={:02x?}, ciphertext={} bytes",
                wrapped.nonce.0,
                wrapped.ciphertext.len()
            );
            wrapped
        }
        Err(e) => {
            println!("  ✗ {e}");
            return;
        }
    };

    // Drop source client before opening dest
    drop(client_src);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Import into dest
    println!("\nOpening dest {dst}...");
    let client_dst = open_with_pin(dst, pin);
    println!("import_wrapped into {dst}...");
    let _ = client_dst.delete_object(0x0100, yubihsm::object::Type::AsymmetricKey);
    match client_dst.import_wrapped(WRAP_KEY_ID, wrapped) {
        Ok(handle) => println!("  ✓ imported as 0x{:04X}", handle.object_id),
        Err(e) => println!("  ✗ import_wrapped: {e}"),
    }
}

// ── CLI helpers ────────────────────────────────────────────────────────────────

fn parse_serial_pair(
    args: &[String],
) -> (yubihsm::device::SerialNumber, yubihsm::device::SerialNumber) {
    if args.len() < 4 {
        eprintln!("Usage: yubihsm_enum {} SERIAL_A SERIAL_B", args[1]);
        eprintln!("  Serials are decimal numbers (as shown by enumeration).");
        process::exit(1);
    }
    // SerialNumber requires exactly 10 decimal digits.
    let a_str = format!("{:0>10}", args[2]);
    let b_str = format!("{:0>10}", args[3]);
    let a: yubihsm::device::SerialNumber = a_str.parse().unwrap_or_else(|e| {
        eprintln!("Invalid serial '{}': {e}", args[2]);
        process::exit(1);
    });
    let b: yubihsm::device::SerialNumber = b_str.parse().unwrap_or_else(|e| {
        eprintln!("Invalid serial '{}': {e}", args[3]);
        process::exit(1);
    });
    if a == b {
        eprintln!("Source and dest serials must be different.");
        process::exit(1);
    }
    (a, b)
}
