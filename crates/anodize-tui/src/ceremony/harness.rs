//! The coroutine-over-thread runtime.
//!
//! A ceremony script is a blocking, top-to-bottom function. To let it "suspend"
//! whenever it needs the operator, we run it on its own thread and give it a
//! [`Bridge`]: each operator interaction sends a [`Prompt`] over a **rendezvous**
//! channel (capacity 0) and blocks until the main thread sends back a
//! [`Response`]. Because the prompt channel is unbuffered and every exchange is
//! a strict request/response, exactly one side runs at any instant — the thread
//! is just a stack for a coroutine. No locks, no shared mutable state, and the
//! disc-burn lifecycle becomes ordinary inline blocking calls instead of a
//! cross-layer state machine.
//!
//! The main thread holds a [`CeremonyHandle`]: it `poll`s for the current
//! prompt (to render it) and `answer`s it from key input. Quitting mid-ceremony
//! is just delivering [`Response::Abort`] to the outstanding prompt — the script
//! unwinds through `?`, its RAII guards drop (HSM logout, PIN zeroization), and
//! the thread exits.

use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

use secrecy::SecretString;

use anodize_config::state::SssMetadata;

use super::io::{Abort, Choice, CustodianResult, Operator, Pin, Timestamp};
use super::prompt::{Prompt, Response};

/// The script-side endpoint: send a prompt, block for the response.
///
/// Channel-backed adapters ([`ChannelOperator`], and the future `ChannelArchive`)
/// are built from a shared `&Bridge`.
pub struct Bridge {
    prompt_tx: SyncSender<Prompt>,
    response_rx: Receiver<Response>,
    ceremony_log: Mutex<Vec<String>>,
}

impl Bridge {
    /// Send a prompt and block until the operator answers.
    pub fn ask(&self, prompt: Prompt) -> Result<Response, Abort> {
        self.prompt_tx
            .send(prompt)
            .map_err(|_| Abort::new("UI disconnected"))?;
        self.response_rx
            .recv()
            .map_err(|_| Abort::new("UI disconnected"))
    }

    /// Send an informational prompt that expects no response.
    pub fn tell(&self, prompt: Prompt) {
        let _ = self.prompt_tx.send(prompt);
    }

    /// Append a line to the ceremony log buffer.
    pub fn log(&self, msg: impl Into<String>) {
        if let Ok(mut v) = self.ceremony_log.lock() {
            v.push(msg.into());
        }
    }

    /// Drain and return all accumulated ceremony log lines.
    pub fn drain_log(&self) -> Vec<String> {
        self.ceremony_log
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

/// Main-thread handle to a running ceremony thread.
pub struct CeremonyHandle {
    prompt_rx: Receiver<Prompt>,
    response_tx: Sender<Response>,
    join: Option<JoinHandle<()>>,
}

impl CeremonyHandle {
    /// Spawn a ceremony. `body` runs on a new thread, receives a [`Bridge`] for
    /// building channel-backed adapters, and returns the terminal [`Prompt`]
    /// ([`Prompt::Done`] or [`Prompt::Aborted`]) which is delivered to the main
    /// thread as the final prompt.
    pub fn spawn<F>(body: F) -> Self
    where
        F: FnOnce(Bridge) -> Prompt + Send + 'static,
    {
        let (prompt_tx, prompt_rx) = sync_channel::<Prompt>(0);
        let (response_tx, response_rx) = channel::<Response>();
        let bridge = Bridge {
            prompt_tx: prompt_tx.clone(),
            response_rx,
            ceremony_log: Mutex::new(Vec::new()),
        };
        let join = thread::spawn(move || {
            let terminal = body(bridge);
            let _ = prompt_tx.send(terminal);
        });
        Self {
            prompt_rx,
            response_tx,
            join: Some(join),
        }
    }

    /// Non-blocking: take the next pending prompt, if any. Used by the TUI tick.
    pub fn poll(&self) -> Option<Prompt> {
        self.prompt_rx.try_recv().ok()
    }

    /// Blocking: wait for the next prompt. Used by simple drivers and tests.
    pub fn recv(&self) -> Option<Prompt> {
        self.prompt_rx.recv().ok()
    }

    /// Answer the outstanding prompt.
    pub fn answer(&self, response: Response) {
        let _ = self.response_tx.send(response);
    }

    /// Join the ceremony thread (call after a terminal prompt).
    pub fn join(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Reconstruct the HSM PIN from collected shares and verify it against the
/// commitment hash in `STATE.JSON`. Lives in the adapter layer because turning
/// shares into a PIN is an operator concern; logging the PIN into the HSM is the
/// [`super::io::Vault`]'s job.
pub fn reconstruct_pin(sss: &SssMetadata, shares: &[anodize_sss::Share]) -> Result<Pin, Abort> {
    let bytes = anodize_sss::reconstruct(shares, sss.threshold)
        .map_err(|e| Abort::new(format!("PIN reconstruction failed: {e}")))?;
    if !anodize_sss::verify_pin_hash(&bytes, &sss.pin_verify_hash) {
        return Err(Abort::new(
            "PIN verify hash mismatch — shares may be corrupted.",
        ));
    }
    Ok(SecretString::new(hex::encode(&bytes)))
}

/// Channel-backed [`Operator`]: turns trait calls into [`Prompt`]s and maps the
/// [`Response`] back into typed results.
pub struct ChannelOperator<'a> {
    bridge: &'a Bridge,
}

impl<'a> ChannelOperator<'a> {
    pub fn new(bridge: &'a Bridge) -> Self {
        Self { bridge }
    }
}

impl Operator for ChannelOperator<'_> {
    fn choose(&mut self, title: &str, body: &[String], options: &[Choice]) -> Result<usize, Abort> {
        match self.bridge.ask(Prompt::Choose {
            title: title.into(),
            body: body.to_vec(),
            options: options.to_vec(),
        })? {
            Response::Choice(i) => Ok(i),
            Response::Abort => Err(Abort::new("operator aborted")),
            _ => Err(Abort::new("unexpected response to Choose")),
        }
    }

    fn confirm(&mut self, title: &str, body: &[String]) -> Result<(), Abort> {
        match self.bridge.ask(Prompt::Confirm {
            title: title.into(),
            body: body.to_vec(),
        })? {
            Response::Confirm => Ok(()),
            Response::Abort => Err(Abort::new("operator declined")),
            _ => Err(Abort::new("unexpected response to Confirm")),
        }
    }

    fn collect_quorum(&mut self, sss: &SssMetadata) -> Result<Pin, Abort> {
        match self
            .bridge
            .ask(Prompt::CollectShares { sss: sss.clone() })?
        {
            Response::Shares(shares) => reconstruct_pin(sss, &shares),
            Response::Abort => Err(Abort::new("quorum aborted")),
            _ => Err(Abort::new("unexpected response to CollectShares")),
        }
    }

    fn reconfirm_clock(&mut self) -> Result<Timestamp, Abort> {
        let rfc3339 = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .ok()
            .and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| "unknown".into());
        match self.bridge.ask(Prompt::ReconfirmClock { rfc3339 })? {
            Response::Ack => Ok(std::time::SystemTime::now()),
            Response::Abort => Err(Abort::new("clock not confirmed")),
            _ => Err(Abort::new("unexpected response to ReconfirmClock")),
        }
    }

    fn prompt_text(&mut self, title: &str, label: &str) -> Result<String, Abort> {
        match self.bridge.ask(Prompt::TextInput {
            title: title.into(),
            label: label.into(),
        })? {
            Response::Text(s) => Ok(s),
            Response::Abort => Err(Abort::new("text input aborted")),
            _ => Err(Abort::new("unexpected response to TextInput")),
        }
    }

    fn setup_custodians(&mut self, title: &str) -> Result<CustodianResult, Abort> {
        match self.bridge.ask(Prompt::CustodianSetup {
            title: title.into(),
        })? {
            Response::Custodians { names, threshold } => Ok(CustodianResult { names, threshold }),
            Response::Abort => Err(Abort::new("custodian setup aborted")),
            _ => Err(Abort::new("unexpected response to CustodianSetup")),
        }
    }

    fn reveal_shares(
        &mut self,
        shares: &[anodize_sss::Share],
        names: &[String],
        generation: u64,
    ) -> Result<(), Abort> {
        match self.bridge.ask(Prompt::RevealShares {
            shares: shares.to_vec(),
            names: names.to_vec(),
            generation,
        })? {
            Response::Ack => Ok(()),
            Response::Abort => Err(Abort::new("share reveal aborted")),
            _ => Err(Abort::new("unexpected response to RevealShares")),
        }
    }

    fn verify_shares(&mut self, sss: &SssMetadata) -> Result<(), Abort> {
        match self.bridge.ask(Prompt::VerifyShares { sss: sss.clone() })? {
            Response::Ack => Ok(()),
            Response::Abort => Err(Abort::new("share verification aborted")),
            _ => Err(Abort::new("unexpected response to VerifyShares")),
        }
    }

    fn wait_for_disc_swap(&mut self, session_count: usize) -> Result<(), Abort> {
        match self.bridge.ask(Prompt::WaitDiscSwap { session_count })? {
            Response::Ack => Ok(()),
            Response::Abort => Err(Abort::new("disc swap aborted")),
            _ => Err(Abort::new("unexpected response to WaitDiscSwap")),
        }
    }

    fn review(&mut self, title: &str, body: &[String]) {
        // Review is non-abortable — any response proceeds.
        let _ = self.bridge.ask(Prompt::Review {
            title: title.into(),
            body: body.to_vec(),
        });
    }

    fn note(&mut self, msg: &str) {
        self.bridge.log(msg);
        self.bridge.tell(Prompt::Note(msg.into()));
    }
}

// ── harness test: drive the real script across real threads ──────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::io::*;
    use crate::ceremony::scripts::issue_crl::issue_crl;
    use anodize_config::state::Custodian;

    /// HSM double that accepts any PIN and returns a canned CRL.
    struct FakeVault;
    struct FakeSession;
    impl Vault for FakeVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            Ok(Box::new(FakeSession))
        }
    }
    impl Session for FakeSession {
        fn issue_crl(&mut self, _: &CrlPlan, _: Timestamp) -> Result<SignedCrl, Abort> {
            Ok(SignedCrl::new(vec![0xCA, 0xFE]))
        }
    }

    /// Archive double that performs no real burn.
    #[derive(Default)]
    struct FakeArchive;
    impl Archive for FakeArchive {
        fn commit_intent(&mut self, _: IntentEvent) -> Result<IntentCommitted, Abort> {
            Ok(IntentCommitted::new("intent"))
        }
        fn commit_record(
            &mut self,
            _: IntentCommitted,
            _: RecordSession,
        ) -> Result<RecordCommitted, Abort> {
            Ok(RecordCommitted::new("record"))
        }
        fn export_shuttle(
            &mut self,
            _: &RecordCommitted,
            _: &[(&str, &[u8])],
        ) -> Result<(), Abort> {
            Ok(())
        }
    }

    fn env_with_real_shares() -> (Env<CrlPlan>, Vec<anodize_sss::Share>) {
        let pin_bytes = [0x11u8; 32];
        let shares = anodize_sss::split(&pin_bytes, 2, 2).expect("split");
        let sss = SssMetadata {
            generation: 1,
            threshold: 2,
            total: 2,
            custodians: vec![
                Custodian {
                    name: "Alice".into(),
                    index: 1,
                },
                Custodian {
                    name: "Bob".into(),
                    index: 2,
                },
            ],
            pin_verify_hash: hex::encode(anodize_sss::pin_verify_hash(&pin_bytes)),
            share_commitments: vec![],
        };
        let env = Env {
            sss,
            plan: CrlPlan {
                crl_number: 9,
                revocation_list: vec![],
                root_cert_der: vec![0x30, 0x00],
            },
        };
        (env, shares)
    }

    #[test]
    fn coroutine_drives_issue_crl_to_completion() {
        let (env, shares) = env_with_real_shares();

        let handle = CeremonyHandle::spawn(move |bridge| {
            let mut op = ChannelOperator::new(&bridge);
            let mut vault = FakeVault;
            let mut arc = FakeArchive;
            match issue_crl(&mut op, &mut vault, &mut arc, &env) {
                Ok(o) => Prompt::Done(o),
                Err(e) => Prompt::Aborted(e.0),
            }
        });

        // Main-thread driver: answer each prompt in lock-step.
        let headline = loop {
            match handle.recv().expect("prompt stream ended early") {
                Prompt::Confirm { .. } => handle.answer(Response::Confirm),
                Prompt::CollectShares { .. } => handle.answer(Response::Shares(shares.clone())),
                Prompt::ReconfirmClock { .. } => handle.answer(Response::Ack),
                Prompt::Note(_) | Prompt::Burning { .. } => { /* no response */ }
                Prompt::Choose { .. } => handle.answer(Response::Choice(0)),
                Prompt::TextInput { .. } => handle.answer(Response::Text(String::new())),
                Prompt::CustodianSetup { .. } => handle.answer(Response::Custodians {
                    names: vec!["Alice".into(), "Bob".into()],
                    threshold: 2,
                }),
                Prompt::RevealShares { .. } => handle.answer(Response::Ack),
                Prompt::VerifyShares { .. } => handle.answer(Response::Ack),
                Prompt::WaitDiscSwap { .. } => handle.answer(Response::Ack),
                Prompt::Review { .. } => handle.answer(Response::Confirm),
                Prompt::Done(o) => break o.headline,
                Prompt::Aborted(e) => panic!("unexpected abort: {e}"),
            }
        };
        handle.join();
        assert!(headline.contains("CRL #9"), "got: {headline}");
    }

    #[test]
    fn quitting_at_quorum_aborts_cleanly() {
        let (env, _shares) = env_with_real_shares();

        let handle = CeremonyHandle::spawn(move |bridge| {
            let mut op = ChannelOperator::new(&bridge);
            let mut vault = FakeVault;
            let mut arc = FakeArchive;
            match issue_crl(&mut op, &mut vault, &mut arc, &env) {
                Ok(o) => Prompt::Done(o),
                Err(e) => Prompt::Aborted(e.0),
            }
        });

        // Confirm the plan, then quit at the quorum prompt.
        let msg = loop {
            match handle.recv().expect("prompt stream ended early") {
                Prompt::Confirm { .. } => handle.answer(Response::Confirm),
                Prompt::CollectShares { .. } => handle.answer(Response::Abort),
                Prompt::Note(_) | Prompt::Burning { .. } => {}
                Prompt::CustodianSetup { .. } => handle.answer(Response::Custodians {
                    names: vec!["Alice".into(), "Bob".into()],
                    threshold: 2,
                }),
                Prompt::RevealShares { .. } => handle.answer(Response::Ack),
                Prompt::VerifyShares { .. } => handle.answer(Response::Ack),
                Prompt::WaitDiscSwap { .. } => handle.answer(Response::Ack),
                Prompt::Review { .. } => handle.answer(Response::Confirm),
                Prompt::Done(_) => panic!("should have aborted"),
                Prompt::Aborted(e) => break e,
                other => panic!("unexpected prompt: {other:?}"),
            }
        };
        handle.join();
        assert!(msg.contains("quorum aborted"), "got: {msg}");
    }
}
