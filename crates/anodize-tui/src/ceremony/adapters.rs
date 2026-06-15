//! Production adapters that back the ceremony effect traits with real
//! subsystems.
//!
//! - [`HsmVault`] / [`HsmSession`] — the real [`Vault`], wrapping
//!   `anodize-hsm` + `anodize-ca`.
//! - [`DiscArchive`] — the real [`Archive`], wrapping the `media` optical-disc
//!   layer + `anodize-audit`. The disc burn, which used to be an asynchronous
//!   cross-layer state machine (`Commit` → poll → `BurningDisc` → poll →
//!   `DiscDone`), is now an ordinary blocking call on the ceremony thread.
//!
//! The operator adapter (`ChannelOperator`) lives in [`super::harness`].

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

use anodize_config::HsmBackendKind;
use secrecy::SecretString;

use super::harness::Bridge;
use super::io::{
    Abort, Archive, BackupResult, BackupTarget, CrlPlan, DeviceInfo, HsmAuditEntry, HsmAuditLog,
    IntentCommitted, IntentEvent, IntermediateReq, MigrationFile, Pin, RecordCommitted,
    RecordSession, RootCertParams, Session, SignedCert, SignedCrl, Timestamp, Vault,
};
use super::prompt::Prompt;
use crate::media::{self, BurnProgress, IsoFile, SessionEntry};
use anodize_audit::{genesis_hash, AuditLog};
use anodize_config::state::{SessionState, STATE_FILENAME};
use anodize_hsm::{create_backend, create_inventory, open_session_any_recognized, HsmActor};

/// Real HSM-backed [`Vault`]. Holds just enough config to log in; the
/// reconstructed PIN arrives via [`Vault::login`], having already been verified
/// against `pin_verify_hash` by the operator adapter.
pub struct HsmVault {
    backend: HsmBackendKind,
    token_label: String,
    key_label: String,
    fleet_ids: Vec<String>,
}

impl HsmVault {
    pub fn new(
        backend: HsmBackendKind,
        token_label: impl Into<String>,
        key_label: impl Into<String>,
        fleet_ids: Vec<String>,
    ) -> Self {
        Self {
            backend,
            token_label: token_label.into(),
            key_label: key_label.into(),
            fleet_ids,
        }
    }
}

impl HsmVault {
    /// Roll back already-changed backup devices to the old PIN.
    fn rollback_backup_pins(
        backup: &dyn anodize_hsm::HsmBackup,
        changed: &[String],
        current_pin: &SecretString,
        target_pin: &SecretString,
    ) {
        for id in changed {
            if let Err(e) = backup.change_pin_on_device(id, current_pin, target_pin) {
                tracing::error!(device = %id, "rollback backup PIN failed: {e}");
            } else {
                tracing::info!(device = %id, "rolled back backup PIN");
            }
        }
    }

    /// Roll back the primary HSM to the old PIN.
    fn rollback_primary_pin(
        actor: &mut anodize_hsm::HsmActor,
        current: &SecretString,
        target: &SecretString,
    ) {
        use anodize_hsm::Hsm as _;
        if let Err(e) = actor.change_pin(current, target) {
            tracing::error!("rollback primary PIN failed: {e}");
        } else {
            tracing::info!("rolled back primary PIN");
        }
    }
}

impl Vault for HsmVault {
    fn login<'a>(&'a mut self, pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
        let pin: SecretString = pin;
        let backend =
            create_backend(self.backend).map_err(|e| Abort::new(format!("HSM backend: {e}")))?;

        let hsm = if self.fleet_ids.is_empty() {
            backend
                .open_session(&self.token_label, &pin)
                .map_err(|e| Abort::new(format!("HSM open/login failed: {e}")))?
        } else {
            let inventory = create_inventory(self.backend)
                .map_err(|e| Abort::new(format!("HSM inventory: {e}")))?;
            let id_refs: Vec<&str> = self.fleet_ids.iter().map(String::as_str).collect();
            let (device_id, hsm) =
                open_session_any_recognized(&*backend, &*inventory, &id_refs, &pin)
                    .map_err(|e| Abort::new(format!("Fleet login failed: {e}")))?;
            tracing::info!(device_id = %device_id, "ceremony: authenticated to fleet device");
            hsm
        };

        Ok(Box::new(HsmSession {
            actor: HsmActor::spawn(hsm),
            key_label: self.key_label.clone(),
            device: None,
        }))
    }

    fn bootstrap<'a>(&'a mut self, pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
        let pin: SecretString = pin;
        let backend =
            create_backend(self.backend).map_err(|e| Abort::new(format!("HSM backend: {e}")))?;

        // Find an uninitialised (or first available) token slot.
        let tokens = backend
            .list_tokens()
            .map_err(|e| Abort::new(format!("HSM enumerate failed: {e}")))?;
        let target = tokens
            .first()
            .ok_or_else(|| Abort::new("No HSM token slots found. Insert an HSM device."))?;

        let hsm = backend
            .bootstrap(target.slot_id, &pin, &pin, &self.token_label)
            .map_err(|e| Abort::new(format!("HSM bootstrap failed: {e}")))?;

        let device_id = if target.serial_number.is_empty() {
            self.token_label.clone()
        } else {
            target.serial_number.clone()
        };
        let model = if target.model.is_empty() {
            format!("{:?}", self.backend)
        } else {
            target.model.clone()
        };

        Ok(Box::new(HsmSession {
            actor: HsmActor::spawn(hsm),
            key_label: self.key_label.clone(),
            device: Some(DeviceInfo {
                device_id,
                model,
                backend: self.backend,
            }),
        }))
    }

    fn change_pin_fleet(
        &self,
        old_pin: &Pin,
        new_pin: &Pin,
        primary_device_id: &str,
    ) -> Result<Vec<String>, Abort> {
        let backup_impl = anodize_hsm::create_backup(self.backend)
            .map_err(|e| Abort::new(format!("Backup backend init: {e}")))?;

        let mut changed: Vec<String> = Vec::new();
        for device_id in &self.fleet_ids {
            if device_id == primary_device_id {
                continue;
            }
            tracing::info!(device = %device_id, "RekeyShares: changing PIN on fleet HSM");
            match backup_impl.change_pin_on_device(device_id, old_pin, new_pin) {
                Ok(()) => {
                    changed.push(device_id.clone());
                    tracing::info!(device = %device_id, "RekeyShares: fleet HSM PIN changed");
                }
                Err(e) => {
                    tracing::error!(
                        device = %device_id,
                        "RekeyShares: fleet PIN change failed: {e}, initiating rollback"
                    );
                    Self::rollback_backup_pins(&*backup_impl, &changed, new_pin, old_pin);
                    // Note: primary rollback must be done by the caller who owns the session.
                    return Err(Abort::new(format!(
                        "PIN change failed on fleet device {device_id}: {e}. \
                         All backup HSMs rolled back to old PIN. \
                         Primary HSM still has the new PIN — caller must roll back."
                    )));
                }
            }
        }
        if !changed.is_empty() {
            tracing::info!(count = changed.len(), devices = ?changed, "fleet PIN propagation complete");
        }
        Ok(changed)
    }

    fn verify_pin_rejected(&self, old_pin: &Pin) -> Result<(), Abort> {
        if self.fleet_ids.is_empty() {
            return Ok(());
        }
        let backend = create_backend(self.backend)
            .map_err(|e| Abort::new(format!("HSM backend for old-PIN check: {e}")))?;
        for device_id in &self.fleet_ids {
            match backend.open_session_by_id(device_id, old_pin) {
                Ok(_) => {
                    tracing::error!(device = %device_id, "old PIN still accepted!");
                    return Err(Abort::new(format!(
                        "CRITICAL: old PIN still accepted by fleet device {device_id}. \
                         The PIN rotation may not have taken effect."
                    )));
                }
                Err(_) => {
                    tracing::info!(device = %device_id, "old PIN correctly rejected");
                }
            }
        }
        tracing::info!(
            count = self.fleet_ids.len(),
            "old PIN rejected on all fleet devices"
        );
        Ok(())
    }

    fn discover_backup_targets(&self, pin: &Pin) -> Result<Vec<BackupTarget>, Abort> {
        let backup_impl = anodize_hsm::create_backup(self.backend)
            .map_err(|e| Abort::new(format!("Backup backend init: {e}")))?;
        let targets = backup_impl
            .enumerate_backup_targets(Some(pin))
            .map_err(|e| Abort::new(format!("Device enumeration failed: {e}")))?;
        Ok(targets
            .into_iter()
            .map(|t| BackupTarget {
                identifier: t.identifier,
                description: t.description,
                has_wrap_key: t.has_wrap_key,
                has_signing_key: t.has_signing_key,
                needs_bootstrap: t.needs_bootstrap,
            })
            .collect())
    }

    fn pair_devices(&self, src: &str, dst: &str, pin: &Pin) -> Result<String, Abort> {
        let backup_impl = anodize_hsm::create_backup(self.backend)
            .map_err(|e| Abort::new(format!("Backup backend init: {e}")))?;
        backup_impl
            .pair_devices(src, dst, pin)
            .map_err(|e| Abort::new(format!("Pair devices failed: {e}")))
    }

    fn backup_key(&self, src: &str, dst: &str, pin: &Pin) -> Result<BackupResult, Abort> {
        let backup_impl = anodize_hsm::create_backup(self.backend)
            .map_err(|e| Abort::new(format!("Backup backend init: {e}")))?;
        let result = backup_impl
            .backup_key(src, dst, pin, "")
            .map_err(|e| Abort::new(format!("Backup key failed: {e}")))?;
        Ok(BackupResult {
            source_id: result.source_id,
            dest_id: result.dest_id,
            public_keys_match: result.public_keys_match,
        })
    }
}

/// An authenticated HSM session. Dropping it drops the [`HsmActor`], which ends
/// the actor thread and closes the underlying session — the RAII logout.
pub struct HsmSession {
    actor: HsmActor,
    key_label: String,
    device: Option<DeviceInfo>,
}

impl Session for HsmSession {
    fn issue_crl(&mut self, plan: &CrlPlan, when: Timestamp) -> Result<SignedCrl, Abort> {
        use crate::helpers::{
            hex_serial_to_bytes, mechanism_error_msg, parse_rfc3339_to_system_time,
        };
        use anodize_ca::{issue_crl, P384HsmSigner};
        use anodize_hsm::Hsm as _;
        use der::Decode;
        use x509_cert::certificate::Certificate;

        let root_key = self
            .actor
            .find_key(&self.key_label)
            .map_err(|e| Abort::new(format!("Root key not found: {e}")))?;
        let signer = P384HsmSigner::new(self.actor.clone(), root_key)
            .map_err(|e| Abort::new(format!("Signer error: {e}")))?;

        let root_cert = Certificate::from_der(&plan.root_cert_der)
            .map_err(|e| Abort::new(format!("Root cert DER decode: {e}")))?;

        let revoked: Vec<(
            x509_cert::serial_number::SerialNumber,
            std::time::SystemTime,
            Option<anodize_ca::CrlReason>,
        )> = plan
            .revocation_list
            .iter()
            .filter_map(|e| {
                let serial_bytes = hex_serial_to_bytes(&e.serial)?;
                let sn = x509_cert::serial_number::SerialNumber::new(&serial_bytes).ok()?;
                let t = parse_rfc3339_to_system_time(&e.revocation_time)
                    .unwrap_or_else(std::time::SystemTime::now);
                let reason = e
                    .reason
                    .as_deref()
                    .map(anodize_ca::reason_str_to_crl_reason);
                Some((sn, t, reason))
            })
            .collect();

        let next_update = when + std::time::Duration::from_secs(365 * 24 * 3600);

        let crl_der = issue_crl(&signer, &root_cert, &revoked, next_update, plan.crl_number)
            .map_err(|e| Abort::new(mechanism_error_msg("CRL signing failed", &e)))?;

        Ok(SignedCrl::new(crl_der))
    }

    fn sign_intermediate(
        &mut self,
        req: &IntermediateReq,
        _when: Timestamp,
    ) -> Result<SignedCert, Abort> {
        use crate::helpers::mechanism_error_msg;
        use anodize_ca::{sign_intermediate_csr, CaError, P384HsmSigner};
        use anodize_hsm::Hsm as _;
        use der::{Decode, Encode};
        use x509_cert::certificate::Certificate;

        let root_key = self
            .actor
            .find_key(&self.key_label)
            .map_err(|e| Abort::new(format!("Root key not found: {e}")))?;
        let signer = P384HsmSigner::new(self.actor.clone(), root_key)
            .map_err(|e| Abort::new(format!("Signer error: {e}")))?;
        let root_cert = Certificate::from_der(&req.root_cert_der)
            .map_err(|e| Abort::new(format!("Root cert DER decode: {e}")))?;

        let cert = sign_intermediate_csr(
            &signer,
            &root_cert,
            &req.csr_der,
            req.path_len,
            req.validity_days,
            req.cdp_url.as_deref(),
            &req.existing_serials,
        )
        .map_err(|e| {
            Abort::new(match e {
                CaError::CsrSignatureInvalid => {
                    "CSR signature verification failed \u{2014} CSR may be corrupt".to_string()
                }
                CaError::CsrAlgorithmUnsupported(alg) => format!(
                    "CSR uses unsupported signature algorithm ({alg}). \
                     Accepted: ECDSA P-256/SHA-256 or P-384/SHA-384."
                ),
                CaError::CsrExtensionRejected(oid) => {
                    format!("CSR contains rejected extension OID: {oid}")
                }
                other => mechanism_error_msg("CSR signing failed", &other),
            })
        })?;
        let der = cert
            .to_der()
            .map_err(|e| Abort::new(format!("DER encode failed: {e}")))?;
        Ok(SignedCert::new(der))
    }

    fn generate_root_key(&mut self) -> Result<(), Abort> {
        use anodize_hsm::{Hsm as _, KeySpec};
        self.actor
            .generate_keypair(&self.key_label, KeySpec::EcdsaP384)
            .map_err(|e| Abort::new(format!("Root key generation failed: {e}")))?;
        Ok(())
    }

    fn build_root_cert(
        &mut self,
        params: &RootCertParams,
        _when: Timestamp,
    ) -> Result<SignedCert, Abort> {
        use anodize_ca::{build_root_cert, P384HsmSigner};
        use anodize_hsm::Hsm as _;
        use der::Encode;

        let root_key = self
            .actor
            .find_key(&self.key_label)
            .map_err(|e| Abort::new(format!("Root key not found after keygen: {e}")))?;
        let signer = P384HsmSigner::new(self.actor.clone(), root_key)
            .map_err(|e| Abort::new(format!("Signer error: {e}")))?;

        let cert = build_root_cert(
            &signer,
            &params.common_name,
            &params.organization,
            &params.country,
            params.validity_days,
        )
        .map_err(|e| Abort::new(format!("Root cert build failed: {e}")))?;

        let der = cert
            .to_der()
            .map_err(|e| Abort::new(format!("DER encode failed: {e}")))?;
        Ok(SignedCert::new(der))
    }

    fn device_info(&self) -> Option<DeviceInfo> {
        self.device.clone()
    }

    fn record_audit_seq(&mut self) -> Option<u64> {
        use anodize_hsm::Hsm as _;
        match self.actor.get_audit_log() {
            Ok(snapshot) => {
                let last = snapshot.entries.last()?;
                let seq = last.item as u64;
                if let Err(e) = self.actor.drain_audit_log(last.item) {
                    tracing::warn!(seq = last.item, "drain_audit_log failed: {e}");
                }
                Some(seq)
            }
            Err(e) => {
                tracing::warn!("could not read HSM audit log: {e}");
                None
            }
        }
    }

    fn change_pin(&mut self, old_pin: &Pin, new_pin: &Pin) -> Result<(), Abort> {
        use anodize_hsm::Hsm as _;
        // Drain the audit log first — YubiHSM force-audit mode blocks all
        // operations once the 62-entry ring buffer is full.
        if let Ok(snapshot) = self.actor.get_audit_log() {
            if let Some(last) = snapshot.entries.last() {
                let _ = self.actor.drain_audit_log(last.item);
            }
        }
        self.actor
            .change_pin(old_pin, new_pin)
            .map_err(|e| Abort::new(format!("HSM change_pin failed: {e}")))
    }

    fn get_hsm_audit_log(&mut self) -> Result<HsmAuditLog, Abort> {
        use anodize_hsm::Hsm as _;
        let snapshot = self
            .actor
            .get_audit_log()
            .map_err(|e| Abort::new(format!("HSM audit log fetch failed: {e}")))?;
        Ok(HsmAuditLog {
            unlogged_boot_events: snapshot.unlogged_boot_events,
            unlogged_auth_events: snapshot.unlogged_auth_events,
            entries: snapshot
                .entries
                .iter()
                .map(|e| HsmAuditEntry {
                    item: e.item,
                    command: e.command,
                    session_key: e.session_key,
                    target_key: e.target_key,
                    second_key: e.second_key,
                    result: e.result,
                    tick: e.tick,
                    digest: e.digest,
                })
                .collect(),
        })
    }
}

// ── DiscArchive ──────────────────────────────────────────────────────────────

/// Real append-only [`Archive`]: write-once optical disc (via `media`) plus the
/// shuttle USB. Runs entirely on the ceremony thread, so each burn is a
/// blocking call — the old `Commit`/`BurningDisc`/`DiscDone` ping-pong is gone.
pub struct DiscArchive<'a> {
    bridge: &'a Bridge,
    dev: Option<PathBuf>,
    prior_sessions: Vec<SessionEntry>,
    shuttle_mount: PathBuf,
    staging: PathBuf,
    profile_bytes: Vec<u8>,
    timestamp: SystemTime,
    sessions_remaining: Option<u16>,
    /// Base STATE.JSON to update when a record session carries a `StateDelta`.
    base_state: Option<SessionState>,
}

impl<'a> DiscArchive<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bridge: &'a Bridge,
        dev: Option<PathBuf>,
        prior_sessions: Vec<SessionEntry>,
        shuttle_mount: PathBuf,
        staging: PathBuf,
        profile_bytes: Vec<u8>,
        timestamp: SystemTime,
        sessions_remaining: Option<u16>,
        base_state: Option<SessionState>,
    ) -> Self {
        Self {
            bridge,
            dev,
            prior_sessions,
            shuttle_mount,
            staging,
            profile_bytes,
            timestamp,
            sessions_remaining,
            base_state,
        }
    }

    fn log_path(&self) -> PathBuf {
        self.staging.join("audit.log")
    }

    /// Blocking disc burn. Emits a single `Burning` prompt (the spinner animates
    /// from the main thread's ticks) and drains the background writer's progress
    /// channel to completion. On success the burned session becomes a prior
    /// session for the next burn (the superset invariant).
    fn burn(&mut self, session: SessionEntry) -> Result<String, Abort> {
        let dev = self
            .dev
            .clone()
            .ok_or_else(|| Abort::new("No optical device \u{2014} cannot burn"))?;
        // Apply the superset backfill up front so the bytes we burn and the
        // session we retain as a prior are one and the same. `write_session`
        // backfills a private clone on its writer thread; if we retained the
        // un-backfilled `session` here, the next burn in this ceremony would
        // carry forward from an impoverished prior (an AUDIT.LOG-only intent
        // session) and silently drop earlier artifacts — violating the
        // superset invariant. Backfill is idempotent, so the writer
        // re-applying it against the same prior is a no-op.
        let session = superset_session(&self.prior_sessions, session);
        let dir = session.dir_name.clone();
        let mut burn_log: Vec<String> = Vec::new();
        self.bridge.tell(Prompt::Burning {
            what: dir.clone(),
            log: burn_log.clone(),
        });

        let (tx, rx) = mpsc::channel();
        media::write_session(&dev, &self.prior_sessions, session.clone(), false, tx);
        loop {
            match rx.recv() {
                Ok(BurnProgress::Step(s)) => {
                    tracing::info!(step = %s, "disc burn");
                    self.bridge.log(format!("[burn {dir}] {s}"));
                    burn_log.push(s);
                    self.bridge.tell(Prompt::Burning {
                        what: dir.clone(),
                        log: burn_log.clone(),
                    });
                }
                Ok(BurnProgress::Done(Ok(()))) => break,
                Ok(BurnProgress::Done(Err(e))) => {
                    return Err(Abort::new(format!("Disc burn failed: {e:#}")))
                }
                Err(_) => return Err(Abort::new("Burn progress channel closed unexpectedly")),
            }
        }
        self.prior_sessions.push(session);
        Ok(dir)
    }
}

/// Return `session` as it will be persisted to disc: the immediately preceding
/// session's files carried forward (the superset invariant). The burned image
/// and the prior retained for the next burn MUST both derive from this value —
/// see [`DiscArchive::burn`].
fn superset_session(prior_sessions: &[SessionEntry], mut session: SessionEntry) -> SessionEntry {
    if let Some(prev) = prior_sessions.last() {
        media::backfill_session(prev, &mut session);
    }
    session
}

/// Assemble the intent session: create the audit-log chain anchored to the
/// profile genesis, append the intent event, and bundle the partial log as
/// `AUDIT.LOG`. No disc I/O — unit-testable against a tmpdir.
fn assemble_intent_session(
    staging: &std::path::Path,
    profile_bytes: &[u8],
    timestamp: SystemTime,
    event: &IntentEvent,
) -> Result<SessionEntry, Abort> {
    std::fs::create_dir_all(staging)
        .map_err(|e| Abort::new(format!("Cannot create staging dir: {e}")))?;
    let log_path = staging.join("audit.log");
    let genesis = genesis_hash(profile_bytes);
    let mut log = AuditLog::create(&log_path, &genesis)
        .map_err(|e| Abort::new(format!("Audit log create failed: {e}")))?;
    log.append(&event.name, event.data.clone())
        .map_err(|e| Abort::new(format!("Audit intent append failed: {e}")))?;
    drop(log);
    let log_bytes =
        std::fs::read(&log_path).map_err(|e| Abort::new(format!("Cannot read audit log: {e}")))?;
    Ok(SessionEntry {
        dir_name: media::session_dir_name(timestamp) + "-intent",
        timestamp,
        files: vec![IsoFile {
            name: "AUDIT.LOG".into(),
            data: log_bytes,
        }],
    })
}

/// Assemble the record session: append the record event to the existing audit
/// log (verifying the chain on open), then bundle the full log, artifacts, and
/// (if a `StateDelta` is present) the updated STATE.JSON anchored to the new
/// audit-chain head.
fn assemble_record_session(
    staging: &std::path::Path,
    timestamp: SystemTime,
    base_state: Option<&SessionState>,
    record: &RecordSession,
) -> Result<SessionEntry, Abort> {
    let log_path = staging.join("audit.log");
    let mut log = AuditLog::open(&log_path)
        .map_err(|e| Abort::new(format!("Audit log open/verify failed: {e}")))?;
    for (name, data) in &record.audit_events {
        log.append(name, data.clone())
            .map_err(|e| Abort::new(format!("Audit record append failed: {e}")))?;
    }
    drop(log);
    let log_bytes =
        std::fs::read(&log_path).map_err(|e| Abort::new(format!("Cannot read audit log: {e}")))?;

    let mut files = vec![IsoFile {
        name: "AUDIT.LOG".into(),
        data: log_bytes.clone(),
    }];
    for artifact in &record.artifacts {
        files.push(IsoFile {
            name: artifact.name.clone(),
            data: artifact.bytes.clone(),
        });
    }

    // Fold the requested STATE.JSON update onto the base state, anchoring it to
    // the just-written audit-chain head.
    if let Some(delta) = record.state.as_ref() {
        // Fresh state (InitRoot) takes precedence over delta-on-base.
        let state = if let Some(fresh) = &delta.fresh_state {
            let mut s = fresh.clone();
            s.last_audit_hash = last_entry_hash(&log_bytes);
            if let Some(seq) = delta.hsm_log_seq {
                s.last_hsm_log_seq = Some(seq);
            }
            Some(s)
        } else {
            base_state.map(|base| {
                let mut s = base.clone();
                s.last_audit_hash = last_entry_hash(&log_bytes);
                if let Some(n) = delta.crl_number {
                    s.crl_number = n;
                }
                if !delta.revocation_list.is_empty() {
                    s.revocation_list = delta.revocation_list.clone();
                }
                if let Some(seq) = delta.hsm_log_seq {
                    s.last_hsm_log_seq = Some(seq);
                }
                if let Some(ref sss) = delta.sss {
                    s.sss = sss.clone();
                }
                if let Some(ref fleet) = delta.fleet {
                    s.fleet = fleet.clone();
                }
                s
            })
        };
        if let Some(s) = state {
            files.push(IsoFile {
                name: STATE_FILENAME.into(),
                data: s.to_json(),
            });
        }
    }

    Ok(SessionEntry {
        dir_name: media::session_dir_name(timestamp) + "-record",
        timestamp,
        files,
    })
}

/// Extract the `entry_hash` of the last non-empty line of an audit log.
fn last_entry_hash(log_bytes: &[u8]) -> String {
    log_bytes
        .split(|&b| b == b'\n')
        .rev()
        .find(|line| !line.is_empty())
        .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .and_then(|v| {
            v.get("entry_hash")
                .and_then(|h| h.as_str().map(String::from))
        })
        .unwrap_or_default()
}

impl Archive for DiscArchive<'_> {
    fn commit_intent(&mut self, event: IntentEvent) -> Result<IntentCommitted, Abort> {
        if self.sessions_remaining.map(|r| r < 2).unwrap_or(false) {
            return Err(Abort::new(
                "Disc full \u{2014} cannot write intent session. Insert a new disc.",
            ));
        }
        self.bridge
            .log(format!("Committing intent: {}", event.name));
        let session =
            assemble_intent_session(&self.staging, &self.profile_bytes, self.timestamp, &event)?;
        let dir = self.burn(session)?;
        self.bridge.log(format!("Intent committed: {dir}"));
        Ok(IntentCommitted::new(dir))
    }

    fn commit_record(
        &mut self,
        _intent: IntentCommitted,
        record: RecordSession,
    ) -> Result<RecordCommitted, Abort> {
        self.bridge.log("Committing record session…");
        let session = assemble_record_session(
            &self.staging,
            self.timestamp,
            self.base_state.as_ref(),
            &record,
        )?;
        let dir = self.burn(session)?;
        self.bridge.log(format!("Record committed: {dir}"));
        Ok(RecordCommitted::new(dir))
    }

    fn export_shuttle(
        &mut self,
        _record: &RecordCommitted,
        files: &[(&str, &[u8])],
    ) -> Result<(), Abort> {
        self.bridge.log("Exporting artifacts to shuttle…");
        media::verify_shuttle_mount(&self.shuttle_mount)
            .map_err(|e| Abort::new(format!("Shuttle USB not available: {e:#}")))?;
        for (name, bytes) in files {
            self.bridge.log(format!("  shuttle: {name}"));
            media::write_and_sync(&self.shuttle_mount.join(name), bytes)
                .map_err(|e| Abort::new(format!("Shuttle write {name} failed: {e:#}")))?;
        }
        let log_bytes = std::fs::read(self.staging.join("audit.log"))
            .map_err(|e| Abort::new(format!("Audit log read failed: {e}")))?;
        self.bridge.log("  shuttle: audit.log");
        media::write_and_sync(&self.shuttle_mount.join("audit.log"), &log_bytes)
            .map_err(|e| Abort::new(format!("Audit log copy to shuttle failed: {e:#}")))?;
        self.bridge.log("Shuttle export complete.");
        Ok(())
    }

    fn write_shuttle_direct(&mut self, files: &[(&str, &[u8])]) -> Result<(), Abort> {
        media::verify_shuttle_mount(&self.shuttle_mount)
            .map_err(|e| Abort::new(format!("Shuttle USB not available: {e:#}")))?;
        for (name, bytes) in files {
            media::write_and_sync(&self.shuttle_mount.join(name), bytes)
                .map_err(|e| Abort::new(format!("Shuttle write {name} failed: {e:#}")))?;
        }
        Ok(())
    }

    fn write_migration(&mut self, files: &[MigrationFile]) -> Result<(), Abort> {
        let session = SessionEntry {
            dir_name: media::session_dir_name(self.timestamp) + "-migrate",
            timestamp: self.timestamp,
            files: files
                .iter()
                .map(|f| IsoFile {
                    name: f.name.clone(),
                    data: f.data.clone(),
                })
                .collect(),
        };
        self.burn(session)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::io::{Artifact, StateDelta};

    fn tmpdir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("anodize-archive-test-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn intent_then_record_builds_a_verifiable_audit_chain() {
        let staging = tmpdir("chain");
        let ts = SystemTime::now();

        let intent = assemble_intent_session(
            &staging,
            b"profile-toml-bytes",
            ts,
            &IntentEvent {
                name: "crl.intent".into(),
                data: serde_json::json!({ "operation": "issue-crl" }),
            },
        )
        .expect("assemble intent");

        assert!(intent.dir_name.ends_with("-intent"));
        assert_eq!(intent.files.len(), 1);
        assert_eq!(intent.files[0].name, "AUDIT.LOG");

        let record = assemble_record_session(
            &staging,
            ts,
            None,
            &RecordSession {
                audit_events: vec![("crl.issue".into(), serde_json::json!({ "crl_number": 7 }))],
                artifacts: vec![Artifact {
                    name: "ROOT.CRL".into(),
                    bytes: vec![0xDE, 0xAD],
                }],
                state: None,
            },
        )
        .expect("assemble record");

        assert!(record.dir_name.ends_with("-record"));
        let names: Vec<&str> = record.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["AUDIT.LOG", "ROOT.CRL"]);

        // The on-disk log must still open + verify (genesis -> intent -> record).
        AuditLog::open(&staging.join("audit.log")).expect("audit chain verifies");

        std::fs::remove_dir_all(&staging).ok();
    }

    #[test]
    fn record_without_intent_fails_chain_open() {
        // Without a prior intent (no genesis log), assembling a record must fail
        // rather than silently produce an unanchored chain.
        let staging = tmpdir("no-intent");
        let err = assemble_record_session(
            &staging,
            SystemTime::now(),
            None,
            &RecordSession {
                audit_events: vec![("crl.issue".into(), serde_json::json!({}))],
                artifacts: vec![],
                state: None,
            },
        );
        assert!(err.is_err());
        std::fs::remove_dir_all(&staging).ok();
    }

    fn sample_state() -> SessionState {
        SessionState {
            version: 1,
            root_cert_sha256: "ab".repeat(32),
            root_cert_der_b64: String::new(),
            sss: anodize_config::state::SssMetadata {
                generation: 1,
                threshold: 2,
                total: 2,
                custodians: vec![
                    anodize_config::state::Custodian {
                        name: "Alice".into(),
                        index: 1,
                    },
                    anodize_config::state::Custodian {
                        name: "Bob".into(),
                        index: 2,
                    },
                ],
                pin_verify_hash: "ab".repeat(32),
                share_commitments: vec!["c1".into(), "c2".into()],
            },
            revocation_list: vec![],
            crl_number: 1,
            last_audit_hash: "old-hash".into(),
            last_hsm_log_seq: None,
            fleet: anodize_config::state::HsmFleet::default(),
        }
    }

    #[test]
    fn record_with_state_delta_writes_updated_state_json() {
        let staging = tmpdir("state");
        let ts = SystemTime::now();
        assemble_intent_session(
            &staging,
            b"profile",
            ts,
            &IntentEvent {
                name: "crl.intent".into(),
                data: serde_json::json!({}),
            },
        )
        .expect("intent");

        let base = sample_state();
        let record = assemble_record_session(
            &staging,
            ts,
            Some(&base),
            &RecordSession {
                audit_events: vec![("crl.issue".into(), serde_json::json!({ "crl_number": 5 }))],
                artifacts: vec![],
                state: Some(StateDelta {
                    crl_number: Some(5),
                    revocation_list: vec![],
                    hsm_log_seq: Some(42),
                    fresh_state: None,
                    sss: None,
                    fleet: None,
                }),
            },
        )
        .expect("record");

        let state_file = record
            .files
            .iter()
            .find(|f| f.name == STATE_FILENAME)
            .expect("STATE.JSON present");
        let parsed = SessionState::from_json(&state_file.data).expect("valid STATE.JSON");
        assert_eq!(parsed.crl_number, 5);
        assert_eq!(parsed.last_hsm_log_seq, Some(42));
        assert_ne!(
            parsed.last_audit_hash, "old-hash",
            "audit head must advance"
        );

        std::fs::remove_dir_all(&staging).ok();
    }

    /// Regression: a record burn that follows an intent burn within one
    /// ceremony must still carry forward artifacts written by a *prior*
    /// ceremony. The earlier bug had `burn()` retain the un-backfilled session,
    /// so after the AUDIT.LOG-only intent burn the in-memory prior was
    /// impoverished, and the record burn backfilled from it and dropped
    /// ROOT.CRT/ROOT.CRL. `superset_session` (used by `burn` for both the
    /// burned image and the retained prior) must keep the chain a true
    /// superset across the intent → record boundary.
    #[test]
    fn retained_prior_stays_superset_across_intent_then_record() {
        let file = |n: &str, d: &[u8]| IsoFile {
            name: n.into(),
            data: d.to_vec(),
        };
        let ts = SystemTime::now();
        // A prior ceremony (InitRoot) already burned the root artifacts.
        let first = superset_session(
            &[],
            SessionEntry {
                dir_name: "t0-record".into(),
                timestamp: ts,
                files: vec![
                    file("AUDIT.LOG", b"log0"),
                    file("ROOT.CRT", b"rootcert"),
                    file("ROOT.CRL", b"rootcrl"),
                    file("STATE.JSON", b"state0"),
                ],
            },
        );

        // This ceremony's intent session carries only a fresh AUDIT.LOG.
        let second = superset_session(
            std::slice::from_ref(&first),
            SessionEntry {
                dir_name: "t1-intent".into(),
                timestamp: ts,
                files: vec![file("AUDIT.LOG", b"log1")],
            },
        );

        let prior: Vec<SessionEntry> = vec![first, second];

        // This ceremony's record session adds a new artifact + fresh STATE.JSON.
        let record = superset_session(
            &prior,
            SessionEntry {
                dir_name: "t1-record".into(),
                timestamp: ts,
                files: vec![
                    file("AUDIT.LOG", b"log2"),
                    file("INTERMEDIATE.CRT", b"inter"),
                    file("STATE.JSON", b"state1"),
                ],
            },
        );

        let names: Vec<&str> = record.files.iter().map(|f| f.name.as_str()).collect();
        for required in [
            "ROOT.CRT",
            "ROOT.CRL",
            "INTERMEDIATE.CRT",
            "STATE.JSON",
            "AUDIT.LOG",
        ] {
            assert!(
                names.contains(&required),
                "record session must retain {required}; got {names:?}"
            );
        }
        // The carried-forward artifacts must keep the prior session's bytes.
        let root = record.files.iter().find(|f| f.name == "ROOT.CRT").unwrap();
        assert_eq!(root.data, b"rootcert");
    }
}
