//! Disc Inspector — read-only examination of the audit disc state.
//!
//! Primary navigation is session/track selection. A banner shows disc-level
//! summary; the scrollable area lists sessions. Enter drills into a session's
//! files, certs, STATE.JSON, and AUDIT.LOG. Cert detail is shown in a modal.

use crossterm::event::{KeyCode, KeyEvent};
use der::{Decode, Encode};
use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;

use crate::app::{CeremonyData, DiscContext};
use crate::media::SessionEntry;

// ── View state machine ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorView {
    /// Top-level: banner + session list.
    SessionList,
    /// Drill-in: contents of a single session.
    SessionDetail,
    /// Modal overlay: full X.509 cert details.
    CertModal,
}

/// Deferred action returned by `handle_key` so the caller can resolve borrows
/// before calling populate methods that need `&App`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    None,
    Refresh,
    PopulateDetail,
    PopulateCertModal,
}

/// Persistent state for the disc inspector sub-screen.
pub struct DiscInspectorState {
    pub view: InspectorView,
    /// Highlighted row in the session list.
    pub selected_session: usize,
    /// Highlighted cert within session detail (0-indexed among .CRT files).
    pub selected_cert: usize,
    /// Vertical scroll offset for the main content area.
    pub scroll: u16,

    // Cached render data (rebuilt on entry / navigation).
    pub banner_lines: Vec<String>,
    pub list_lines: Vec<String>,
    pub detail_lines: Vec<String>,
    pub cert_modal_lines: Vec<String>,
    /// Number of sessions on disc (for bounds checking).
    pub session_count: usize,
    /// Number of certs in the currently-viewed session detail.
    pub cert_count: usize,
    /// DER blobs of certs in the current session (parallel to cert rows).
    cert_ders: Vec<Vec<u8>>,
}

impl DiscInspectorState {
    pub fn new() -> Self {
        Self {
            view: InspectorView::SessionList,
            selected_session: 0,
            selected_cert: 0,
            scroll: 0,
            banner_lines: Vec::new(),
            list_lines: Vec::new(),
            detail_lines: Vec::new(),
            cert_modal_lines: Vec::new(),
            session_count: 0,
            cert_count: 0,
            cert_ders: Vec::new(),
        }
    }

    /// Set the cert DER blobs (used by App after borrow split).  
    pub fn set_cert_ders(&mut self, ders: Vec<Vec<u8>>) {
        self.cert_ders = ders;
    }

    /// Number of cached cert DERs.
    pub fn cert_der_count(&self) -> usize {
        self.cert_ders.len()
    }

    /// Access a cert DER by index.
    pub fn cert_der(&self, idx: usize) -> &[u8] {
        &self.cert_ders[idx]
    }

    // ── Key handling ────────────────────────────────────────────────────────

    /// Determine what action the key implies without borrowing App.
    /// Returns (consumed, needs_populate) where needs_populate indicates
    /// the caller should call the appropriate populate_* method afterwards.
    pub fn handle_key(&mut self, key: KeyEvent) -> (bool, KeyAction) {
        match self.view {
            InspectorView::SessionList => self.handle_session_list_key(key),
            InspectorView::SessionDetail => self.handle_session_detail_key(key),
            InspectorView::CertModal => self.handle_cert_modal_key(key),
        }
    }

    fn handle_session_list_key(&mut self, key: KeyEvent) -> (bool, KeyAction) {
        match key.code {
            KeyCode::Esc => (false, KeyAction::None), // let caller handle (back to util menu)
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_session = self.selected_session.saturating_sub(1);
                self.scroll = 0;
                (true, KeyAction::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.session_count > 0 {
                    self.selected_session = (self.selected_session + 1).min(self.session_count - 1);
                }
                self.scroll = 0;
                (true, KeyAction::None)
            }
            KeyCode::Enter => {
                if self.session_count > 0 {
                    self.view = InspectorView::SessionDetail;
                    (true, KeyAction::PopulateDetail)
                } else {
                    (true, KeyAction::None)
                }
            }
            KeyCode::Char('r') => (true, KeyAction::Refresh),
            _ => (true, KeyAction::None),
        }
    }

    fn handle_session_detail_key(&mut self, key: KeyEvent) -> (bool, KeyAction) {
        match key.code {
            KeyCode::Esc => {
                self.view = InspectorView::SessionList;
                self.scroll = 0;
                (true, KeyAction::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                (true, KeyAction::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                (true, KeyAction::None)
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(10);
                (true, KeyAction::None)
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(10);
                (true, KeyAction::None)
            }
            // Number keys select a cert (1-indexed display, 0-indexed internal)
            KeyCode::Char(c @ '1'..='9') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < self.cert_count {
                    self.selected_cert = idx;
                    self.view = InspectorView::CertModal;
                    (true, KeyAction::PopulateCertModal)
                } else {
                    (true, KeyAction::None)
                }
            }
            _ => (true, KeyAction::None),
        }
    }

    fn handle_cert_modal_key(&mut self, key: KeyEvent) -> (bool, KeyAction) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.view = InspectorView::SessionDetail;
                self.scroll = 0;
                (true, KeyAction::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                (true, KeyAction::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                (true, KeyAction::None)
            }
            _ => (true, KeyAction::None),
        }
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        // Split: banner (fixed) + main content (fill)
        let banner_height = (self.banner_lines.len() as u16 + 2).min(area.height / 3);
        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(banner_height), Constraint::Min(4)])
            .split(area);

        // Banner
        let banner_block = Block::default()
            .borders(Borders::ALL)
            .title("Disc Summary")
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let banner_para = Paragraph::new(Text::from(self.banner_lines.join("\n")))
            .block(banner_block)
            .wrap(Wrap { trim: false });
        frame.render_widget(banner_para, chunks[0]);

        // Main content
        match self.view {
            InspectorView::SessionList => self.render_session_list(frame, chunks[1]),
            InspectorView::SessionDetail => self.render_session_detail(frame, chunks[1]),
            InspectorView::CertModal => {
                // Render detail underneath, then modal on top
                self.render_session_detail(frame, chunks[1]);
                self.render_cert_modal(frame, area);
            }
        }
    }

    fn render_session_list(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Sessions  [j/k] navigate  [Enter] inspect  [r] refresh  [Esc] back")
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);

        if self.session_count == 0 {
            let para = Paragraph::new("  No sessions on disc.")
                .block(block)
                .wrap(Wrap { trim: false });
            frame.render_widget(para, area);
            return;
        }

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Build styled lines with highlight on selected row
        let mut lines: Vec<Line> = Vec::with_capacity(self.list_lines.len());
        // Header line
        lines.push(Line::from(Span::styled(
            "   #  Dir name                           Type      Files  Size",
            Style::default().add_modifier(Modifier::BOLD),
        )));

        for (i, text) in self.list_lines.iter().enumerate() {
            let style = if i == self.selected_session {
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(text.as_str(), style)));
        }

        let para = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(para, inner);
    }

    fn render_session_detail(&self, frame: &mut Frame, area: Rect) {
        let title = if self.selected_session < self.session_count {
            format!(
                "Session {}  [1-9] cert detail  [j/k] scroll  [Esc] back",
                self.selected_session + 1
            )
        } else {
            "Session Detail  [Esc] back".into()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let para = Paragraph::new(Text::from(self.detail_lines.join("\n")))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(para, area);
    }

    fn render_cert_modal(&self, frame: &mut Frame, outer: Rect) {
        let width = 72u16.min(outer.width.saturating_sub(4));
        let height = (self.cert_modal_lines.len() as u16 + 4).min(outer.height.saturating_sub(4));
        let modal_area = centered_rect(width, height, outer);

        frame.render_widget(Clear, modal_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::MODAL_BORDER_CYAN)
            .title("Certificate Detail")
            .title_style(crate::theme::MODAL_TITLE_CYAN);
        let inner = block.inner(modal_area);
        frame.render_widget(block, modal_area);

        let para = Paragraph::new(Text::from(self.cert_modal_lines.join("\n")))
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(para, inner);
    }
}

// ── Gather functions ────────────────────────────────────────────────────────

pub fn gather_banner_from(disc: &DiscContext, data: &CeremonyData) -> Vec<String> {
    let mut lines = Vec::new();

    // Media / capacity
    if let Some(rem) = disc.sessions_remaining {
        let used = disc.prior_sessions.len();
        let total = used as u16 + rem;
        lines.push(format!(
            "  Sessions: {used} used, {rem} remaining (max {total})"
        ));
    } else {
        lines.push(format!(
            "  Sessions: {} on disc (capacity unknown)",
            disc.prior_sessions.len()
        ));
    }

    if let Some(ref dev) = disc.optical_dev {
        lines.push(format!("  Device: {}", dev.display()));
    }

    // Audit chain
    let chain_ok = crate::helpers::verify_audit_chain(&disc.prior_sessions);
    lines.push(format!(
        "  Audit chain: {}",
        if chain_ok { "OK" } else { "BROKEN" }
    ));

    // SSS / custodians
    if let Some(ref state) = disc.session_state {
        let sss = &state.sss;
        let names: Vec<&str> = sss.custodians.iter().map(|c| c.name.as_str()).collect();
        lines.push(format!(
            "  SSS: {}-of-{}  custodians: {}",
            sss.threshold,
            sss.total,
            names.join(", ")
        ));
        lines.push(format!(
            "  PIN verify hash: {}...",
            &state.sss.pin_verify_hash[..16]
        ));
        lines.push(format!(
            "  CRL number: {}  revocations: {}",
            state.crl_number,
            state.revocation_list.len()
        ));
    }

    // Root cert fingerprint
    if let Some(ref fp) = data.fingerprint {
        lines.push(format!("  Root cert: {fp}"));
    }

    lines
}

pub fn gather_session_list_from(disc: &DiscContext) -> Vec<String> {
    disc.prior_sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let session_type = if s.dir_name.ends_with("-intent") {
                "intent"
            } else if s.dir_name.ends_with("-record") {
                "record"
            } else {
                ""
            };
            let file_count = s.files.len();
            let total_bytes: usize = s.files.iter().map(|f| f.data.len()).sum();
            let size_display = if total_bytes >= 1024 * 1024 {
                format!("{} MiB", total_bytes / (1024 * 1024))
            } else if total_bytes >= 1024 {
                format!("{} KiB", total_bytes / 1024)
            } else {
                format!("{total_bytes} B")
            };
            format!(
                "  {:<3} {:<35} {:<9} {:<5} {}",
                i + 1,
                s.dir_name,
                session_type,
                file_count,
                size_display
            )
        })
        .collect()
}

/// Returns (display lines, cert DER blobs) for the selected session.
pub fn gather_session_detail_pub(
    session: &SessionEntry,
    _revocations: &[anodize_config::RevocationEntry],
) -> (Vec<String>, Vec<Vec<u8>>) {
    let mut lines = Vec::new();
    let mut cert_ders: Vec<Vec<u8>> = Vec::new();

    lines.push(format!("  Directory: {}", session.dir_name));
    lines.push(String::new());

    // Files table
    lines.push("  Files:".into());
    for f in &session.files {
        let size = if f.data.len() >= 1024 {
            format!("{} KiB", f.data.len() / 1024)
        } else {
            format!("{} B", f.data.len())
        };
        lines.push(format!("    {:<16} {}", f.name, size));
    }
    lines.push(String::new());

    // Certificates
    let crt_files: Vec<_> = session
        .files
        .iter()
        .filter(|f| f.name.ends_with(".CRT"))
        .collect();

    if !crt_files.is_empty() {
        lines.push("  Certificates:".into());
        for (i, f) in crt_files.iter().enumerate() {
            let summary = match Certificate::from_der(&f.data) {
                Ok(cert) => {
                    let subject = cert.tbs_certificate.subject.to_string();
                    let serial = format_serial(&cert.tbs_certificate.serial_number);
                    let not_after = format_time(&cert.tbs_certificate.validity.not_after);
                    format!(
                        "[{}] {}: {}  serial={}  expires={}",
                        i + 1,
                        f.name,
                        subject,
                        serial,
                        not_after
                    )
                }
                Err(e) => format!("[{}] {}: (parse error: {e})", i + 1, f.name),
            };
            lines.push(format!("    {summary}"));
            cert_ders.push(f.data.clone());
        }
        lines.push("    (press [1]-[9] to view certificate detail)".into());
        lines.push(String::new());
    }

    // STATE.JSON
    if let Some(state_file) = session.files.iter().find(|f| f.name == "STATE.JSON") {
        lines.push("  STATE.JSON:".into());
        match anodize_config::state::SessionState::from_json(&state_file.data) {
            Ok(state) => {
                let sss = &state.sss;
                lines.push(format!("    Version: {}", state.version));
                lines.push(format!(
                    "    Root cert SHA-256: {}...{}",
                    &state.root_cert_sha256[..8],
                    &state.root_cert_sha256[56..]
                ));
                lines.push(format!("    SSS: {}-of-{}", sss.threshold, sss.total));
                for c in &sss.custodians {
                    lines.push(format!("      #{}: {}", c.index, c.name));
                }
                lines.push(format!(
                    "    PIN verify hash: {}...{}",
                    &sss.pin_verify_hash[..8],
                    &sss.pin_verify_hash[56..]
                ));
                lines.push(format!("    CRL number: {}", state.crl_number));
                lines.push(format!("    Revocations: {}", state.revocation_list.len()));
                for r in &state.revocation_list {
                    let reason = r.reason.as_deref().unwrap_or("unspecified");
                    lines.push(format!(
                        "      serial={} at {} reason={}",
                        r.serial, r.revocation_time, reason
                    ));
                }
            }
            Err(e) => {
                lines.push(format!("    (parse error: {e})"));
            }
        }
        lines.push(String::new());
    }

    // AUDIT.LOG
    if let Some(audit_file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
        lines.push("  AUDIT.LOG:".into());
        let content = String::from_utf8_lossy(&audit_file.data);
        for line in content.lines() {
            match serde_json::from_str::<anodize_audit::Record>(line) {
                Ok(rec) => {
                    lines.push(format!(
                        "    #{:<4} {} {}",
                        rec.seq, rec.timestamp, rec.event
                    ));
                    if !rec.op_data.is_null()
                        && rec.op_data != serde_json::Value::Object(Default::default())
                    {
                        if let Ok(pretty) = serde_json::to_string(&rec.op_data) {
                            lines.push(format!("           {pretty}"));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!("    (parse error: {e})"));
                }
            }
        }
        lines.push(String::new());
    }

    (lines, cert_ders)
}

pub fn gather_cert_detail_pub(
    der: &[u8],
    revocations: &[anodize_config::RevocationEntry],
) -> Vec<String> {
    let mut lines = Vec::new();

    let cert = match Certificate::from_der(der) {
        Ok(c) => c,
        Err(e) => {
            lines.push(format!("  DER parse error: {e}"));
            return lines;
        }
    };

    let tbs = &cert.tbs_certificate;

    lines.push(format!("  Subject:   {}", tbs.subject));
    lines.push(format!("  Issuer:    {}", tbs.issuer));
    lines.push(format!(
        "  Serial:    {}",
        format_serial(&tbs.serial_number)
    ));
    lines.push(format!("  Version:   {:?}", tbs.version));
    lines.push(String::new());

    // Validity
    lines.push(format!(
        "  Not Before: {}",
        format_time(&tbs.validity.not_before)
    ));
    lines.push(format!(
        "  Not After:  {}",
        format_time(&tbs.validity.not_after)
    ));
    lines.push(String::new());

    // Key algorithm
    lines.push(format!(
        "  Signature Algorithm: {}",
        cert.signature_algorithm.oid
    ));
    lines.push(format!(
        "  Public Key Algorithm: {}",
        tbs.subject_public_key_info.algorithm.oid
    ));
    if let Some(ref params) = tbs.subject_public_key_info.algorithm.parameters {
        if let Ok(oid) = der::asn1::ObjectIdentifier::from_der(&params.to_der().unwrap_or_default())
        {
            lines.push(format!("  Key Curve: {}", oid_name(oid)));
        }
    }
    lines.push(String::new());

    // Fingerprint
    let hash = Sha256::digest(der);
    let fp: String = hash
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(":");
    lines.push(format!("  SHA-256 Fingerprint:"));
    lines.push(format!("    {fp}"));
    lines.push(String::new());

    // Extensions
    if let Some(ref exts) = tbs.extensions {
        lines.push("  Extensions:".into());
        for ext in exts.iter() {
            let critical = if ext.critical { " [critical]" } else { "" };
            let oid = ext.extn_id;
            let name = extension_name(oid);
            lines.push(format!("    {name} ({oid}){critical}"));

            // Parse well-known extensions
            match oid.to_string().as_str() {
                // BasicConstraints
                "2.5.29.19" => {
                    if let Ok(bc) = <x509_cert::ext::pkix::BasicConstraints as Decode>::from_der(
                        ext.extn_value.as_bytes(),
                    ) {
                        lines.push(format!(
                            "      CA: {}  pathLen: {}",
                            bc.ca,
                            bc.path_len_constraint
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "none".into())
                        ));
                    }
                }
                // SubjectKeyIdentifier
                "2.5.29.14" => {
                    let hex: String = ext
                        .extn_value
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    lines.push(format!("      {hex}"));
                }
                _ => {}
            }
        }
        lines.push(String::new());
    }

    // Revocation status
    let serial_hex = crate::helpers::serial_to_hex(&tbs.serial_number);
    if let Some(rev) = revocations.iter().find(|r| r.serial == serial_hex) {
        let reason = rev.reason.as_deref().unwrap_or("unspecified");
        lines.push(format!(
            "  REVOKED: serial={} at {} reason={}",
            rev.serial, rev.revocation_time, reason
        ));
    } else {
        lines.push("  Revocation status: not revoked".into());
    }

    lines.push(String::new());
    lines.push("  [Esc] close".into());

    lines
}

// ── Formatting helpers ──────────────────────────────────────────────────────

fn format_serial(sn: &x509_cert::serial_number::SerialNumber) -> String {
    let bytes = sn.as_bytes();
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_time(t: &x509_cert::time::Time) -> String {
    // Time implements Display via the x509-cert crate
    format!("{t}")
}

fn oid_name(oid: der::asn1::ObjectIdentifier) -> &'static str {
    match oid.to_string().as_str() {
        "1.2.840.10045.3.1.7" => "P-256 (secp256r1)",
        "1.3.132.0.34" => "P-384 (secp384r1)",
        "1.3.132.0.35" => "P-521 (secp521r1)",
        _ => "unknown",
    }
}

fn extension_name(oid: der::asn1::ObjectIdentifier) -> &'static str {
    match oid.to_string().as_str() {
        "2.5.29.19" => "BasicConstraints",
        "2.5.29.15" => "KeyUsage",
        "2.5.29.14" => "SubjectKeyIdentifier",
        "2.5.29.35" => "AuthorityKeyIdentifier",
        "2.5.29.31" => "CRLDistributionPoints",
        "2.5.29.32" => "CertificatePolicies",
        "2.5.29.37" => "ExtendedKeyUsage",
        _ => "Unknown",
    }
}

/// Center a rect of given size within an outer area.
fn centered_rect(width: u16, height: u16, outer: Rect) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(outer);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{CeremonyData, DiscContext};
    use crate::media::iso9660::IsoFile;
    use anodize_config::state::{Custodian, SessionState, SssMetadata};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::time::SystemTime;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn dummy_disc(sessions: Vec<SessionEntry>) -> DiscContext {
        DiscContext {
            optical_dev: Some("/dev/sr0".into()),
            prior_sessions: sessions,
            burn_rx: None,
            sessions_remaining: Some(10),
            intent_session_dir_name: None,
            pending_key_action: None,
            pending_intent_session: None,
            session_state: Some(SessionState {
                version: 1,
                root_cert_sha256: "abcdef".into(),
                root_cert_der_b64: String::new(),
                sss: SssMetadata {
                    threshold: 2,
                    total: 3,
                    custodians: vec![
                        Custodian {
                            name: "alice".into(),
                            index: 1,
                        },
                        Custodian {
                            name: "bob".into(),
                            index: 2,
                        },
                        Custodian {
                            name: "carol".into(),
                            index: 3,
                        },
                    ],
                    pin_verify_hash:
                        "f73b80fd9f9e0bfa08a38ddf04e1fb3b141c0a0da0722ccc53965c1b547e179a".into(),
                    share_commitments: vec![],
                },
                revocation_list: vec![],
                crl_number: 5,
                last_audit_hash: "deadbeef".into(),
                last_hsm_log_seq: None,
            }),
        }
    }

    fn dummy_data() -> CeremonyData {
        CeremonyData {
            cert_der: None,
            fingerprint: Some("AA:BB:CC".into()),
            crl_der: None,
            root_cert_der: None,
            csr_der: None,
            csr_subject_display: None,
            selected_profile_idx: None,
            revocation_list: vec![],
            crl_number: None,
            revoke_serial_buf: String::new(),
            revoke_reason_buf: String::new(),
            revoke_phase: 0,
            cert_list: Vec::new(),
            cert_list_cursor: 0,
            migrate_sessions: vec![],
            migrate_chain_ok: false,
            migrate_total_bytes: 0,
            migrate_source_fingerprint: None,
            cert_preview_lines: Vec::new(),
            validate_report_lines: Vec::new(),
            validate_has_hsm: false,
            validate_findings: Vec::new(),
        }
    }

    fn make_session(name: &str, files: Vec<IsoFile>) -> SessionEntry {
        SessionEntry {
            dir_name: name.to_string(),
            timestamp: SystemTime::now(),
            files,
        }
    }

    // ── Helper function tests ────────────────────────────────────────────

    #[test]
    fn test_oid_name_known() {
        let oid = der::asn1::ObjectIdentifier::new("1.2.840.10045.3.1.7").unwrap();
        assert_eq!(oid_name(oid), "P-256 (secp256r1)");
    }

    #[test]
    fn test_oid_name_unknown() {
        let oid = der::asn1::ObjectIdentifier::new("1.2.3.4.5").unwrap();
        assert_eq!(oid_name(oid), "unknown");
    }

    #[test]
    fn test_extension_name_known() {
        let oid = der::asn1::ObjectIdentifier::new("2.5.29.19").unwrap();
        assert_eq!(extension_name(oid), "BasicConstraints");
    }

    #[test]
    fn test_extension_name_unknown() {
        let oid = der::asn1::ObjectIdentifier::new("9.9.9.9").unwrap();
        assert_eq!(extension_name(oid), "Unknown");
    }

    // ── Key handling state machine ──────────────────────────────────────

    #[test]
    fn test_session_list_navigation() {
        let mut state = DiscInspectorState::new();
        state.session_count = 5;

        // Down moves selection
        let (consumed, action) = state.handle_key(key(KeyCode::Down));
        assert!(consumed);
        assert_eq!(action, KeyAction::None);
        assert_eq!(state.selected_session, 1);

        // 'j' also moves down
        let (consumed, _) = state.handle_key(key(KeyCode::Char('j')));
        assert!(consumed);
        assert_eq!(state.selected_session, 2);

        // Up moves back
        let (consumed, _) = state.handle_key(key(KeyCode::Up));
        assert!(consumed);
        assert_eq!(state.selected_session, 1);

        // 'k' also moves up
        let (consumed, _) = state.handle_key(key(KeyCode::Char('k')));
        assert!(consumed);
        assert_eq!(state.selected_session, 0);

        // Can't go above 0
        let (consumed, _) = state.handle_key(key(KeyCode::Up));
        assert!(consumed);
        assert_eq!(state.selected_session, 0);
    }

    #[test]
    fn test_session_list_bounds() {
        let mut state = DiscInspectorState::new();
        state.session_count = 2;

        // Navigate to last
        state.handle_key(key(KeyCode::Down));
        assert_eq!(state.selected_session, 1);

        // Can't go past last
        state.handle_key(key(KeyCode::Down));
        assert_eq!(state.selected_session, 1);
    }

    #[test]
    fn test_enter_drills_into_detail() {
        let mut state = DiscInspectorState::new();
        state.session_count = 3;

        let (consumed, action) = state.handle_key(key(KeyCode::Enter));
        assert!(consumed);
        assert_eq!(action, KeyAction::PopulateDetail);
        assert_eq!(state.view, InspectorView::SessionDetail);
    }

    #[test]
    fn test_enter_noop_on_empty() {
        let mut state = DiscInspectorState::new();
        state.session_count = 0;

        let (consumed, action) = state.handle_key(key(KeyCode::Enter));
        assert!(consumed);
        assert_eq!(action, KeyAction::None);
        assert_eq!(state.view, InspectorView::SessionList);
    }

    #[test]
    fn test_esc_not_consumed_in_session_list() {
        let mut state = DiscInspectorState::new();
        let (consumed, _) = state.handle_key(key(KeyCode::Esc));
        assert!(!consumed);
    }

    #[test]
    fn test_detail_esc_returns_to_list() {
        let mut state = DiscInspectorState::new();
        state.view = InspectorView::SessionDetail;

        let (consumed, _) = state.handle_key(key(KeyCode::Esc));
        assert!(consumed);
        assert_eq!(state.view, InspectorView::SessionList);
    }

    #[test]
    fn test_detail_scroll() {
        let mut state = DiscInspectorState::new();
        state.view = InspectorView::SessionDetail;

        state.handle_key(key(KeyCode::Down));
        assert_eq!(state.scroll, 1);
        state.handle_key(key(KeyCode::Down));
        assert_eq!(state.scroll, 2);
        state.handle_key(key(KeyCode::Up));
        assert_eq!(state.scroll, 1);
    }

    #[test]
    fn test_detail_cert_selection() {
        let mut state = DiscInspectorState::new();
        state.view = InspectorView::SessionDetail;
        state.cert_count = 3;

        let (consumed, action) = state.handle_key(key(KeyCode::Char('1')));
        assert!(consumed);
        assert_eq!(action, KeyAction::PopulateCertModal);
        assert_eq!(state.selected_cert, 0);
        assert_eq!(state.view, InspectorView::CertModal);
    }

    #[test]
    fn test_detail_cert_selection_out_of_range() {
        let mut state = DiscInspectorState::new();
        state.view = InspectorView::SessionDetail;
        state.cert_count = 1;

        let (consumed, action) = state.handle_key(key(KeyCode::Char('5')));
        assert!(consumed);
        assert_eq!(action, KeyAction::None);
        assert_eq!(state.view, InspectorView::SessionDetail);
    }

    #[test]
    fn test_cert_modal_esc_returns_to_detail() {
        let mut state = DiscInspectorState::new();
        state.view = InspectorView::CertModal;

        let (consumed, _) = state.handle_key(key(KeyCode::Esc));
        assert!(consumed);
        assert_eq!(state.view, InspectorView::SessionDetail);
    }

    #[test]
    fn test_refresh_from_session_list() {
        let mut state = DiscInspectorState::new();
        let (consumed, action) = state.handle_key(key(KeyCode::Char('r')));
        assert!(consumed);
        assert_eq!(action, KeyAction::Refresh);
    }

    // ── Gather function tests ───────────────────────────────────────────

    #[test]
    fn test_gather_banner_sessions_info() {
        let sessions = vec![
            make_session("20250101T000000_000000000Z-intent", vec![]),
            make_session("20250101T000000_000000000Z-record", vec![]),
        ];
        let disc = dummy_disc(sessions);
        let data = dummy_data();
        let lines = gather_banner_from(&disc, &data);

        assert!(lines.iter().any(|l| l.contains("2 used")));
        assert!(lines.iter().any(|l| l.contains("10 remaining")));
        assert!(lines.iter().any(|l| l.contains("/dev/sr0")));
        assert!(lines.iter().any(|l| l.contains("2-of-3")));
        assert!(lines.iter().any(|l| l.contains("alice")));
        assert!(lines.iter().any(|l| l.contains("bob")));
        assert!(lines.iter().any(|l| l.contains("carol")));
        assert!(lines.iter().any(|l| l.contains("CRL number: 5")));
        assert!(lines.iter().any(|l| l.contains("AA:BB:CC")));
    }

    #[test]
    fn test_gather_banner_no_sessions_remaining() {
        let mut disc = dummy_disc(vec![]);
        disc.sessions_remaining = None;
        let data = dummy_data();
        let lines = gather_banner_from(&disc, &data);
        assert!(lines.iter().any(|l| l.contains("capacity unknown")));
    }

    #[test]
    fn test_gather_session_list() {
        let sessions = vec![
            make_session(
                "20250101T000000_000000000Z-intent",
                vec![IsoFile {
                    name: "AUDIT.LOG".into(),
                    data: vec![0; 512],
                }],
            ),
            make_session(
                "20250101T000000_000000000Z-record",
                vec![
                    IsoFile {
                        name: "ROOT.CRT".into(),
                        data: vec![0; 1024],
                    },
                    IsoFile {
                        name: "STATE.JSON".into(),
                        data: vec![0; 256],
                    },
                ],
            ),
        ];
        let disc = dummy_disc(sessions);
        let lines = gather_session_list_from(&disc);

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("intent"));
        assert!(lines[0].contains("1 ")); // 1 file
        assert!(lines[1].contains("record"));
        assert!(lines[1].contains("2 ")); // 2 files
    }

    #[test]
    fn test_gather_session_detail_files() {
        let session = make_session(
            "test-session",
            vec![
                IsoFile {
                    name: "AUDIT.LOG".into(),
                    data: vec![0; 200],
                },
                IsoFile {
                    name: "STATE.JSON".into(),
                    data: vec![0; 100],
                },
            ],
        );
        let (lines, cert_ders) = gather_session_detail_pub(&session, &[]);

        assert!(lines.iter().any(|l| l.contains("test-session")));
        assert!(lines.iter().any(|l| l.contains("AUDIT.LOG")));
        assert!(lines.iter().any(|l| l.contains("STATE.JSON")));
        assert!(cert_ders.is_empty());
    }

    #[test]
    fn test_gather_cert_detail_bad_der() {
        let lines = gather_cert_detail_pub(&[0xFF, 0xFF], &[]);
        assert!(lines.iter().any(|l| l.contains("DER parse error")));
    }

    #[test]
    fn test_gather_session_detail_with_crt() {
        // A .CRT file with bad DER should still show up in cert list with parse error
        let session = make_session(
            "cert-session",
            vec![IsoFile {
                name: "ROOT.CRT".into(),
                data: vec![0xFF, 0xFE],
            }],
        );
        let (lines, cert_ders) = gather_session_detail_pub(&session, &[]);

        assert_eq!(cert_ders.len(), 1);
        // Should contain the cert section header
        assert!(lines.iter().any(|l| l.contains("Certificates:")));
        // Should show parse error inline
        assert!(lines.iter().any(|l| l.contains("parse error")));
    }
}
