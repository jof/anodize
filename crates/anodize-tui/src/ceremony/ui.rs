//! The render layer for the ceremony engine: a pure function of the current
//! [`Prompt`], plus a key→[`Response`] mapping. There is no phase enum and no
//! per-operation rendering code — every ceremony reuses this one renderer.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::components::custodian_setup::CustodianSetup;
use crate::components::share_input::ShareInput;
use crate::components::share_reveal::ShareReveal;

use super::prompt::{Prompt, Response};

const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

/// Map a key to a [`Response`] for the current prompt, or `None` if the key is
/// not meaningful here. For [`Prompt::CollectShares`] the key is fed to the
/// share-input component, and a [`Response::Shares`] is produced once quorum is
/// reached.
pub fn key_to_response(
    prompt: &Prompt,
    key: KeyEvent,
    share_input: &mut Option<ShareInput>,
    custodian_setup: &mut Option<CustodianSetup>,
    share_reveal: &mut Option<ShareReveal>,
    text_buf: &mut String,
) -> Option<Response> {
    match prompt {
        Prompt::Confirm { .. } => match key.code {
            KeyCode::Char('1') | KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                Some(Response::Confirm)
            }
            KeyCode::Esc => Some(Response::Abort),
            _ => None,
        },
        Prompt::Review { .. } => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Enter => {
                Some(Response::Confirm)
            }
            // Scroll keys are consumed by CeremonyRun, not here.
            _ => None,
        },
        Prompt::ReconfirmClock { .. } => match key.code {
            KeyCode::Char('1') | KeyCode::Enter => Some(Response::Ack),
            KeyCode::Esc => Some(Response::Abort),
            _ => None,
        },
        Prompt::Choose { options, .. } => match key.code {
            KeyCode::Char(c) => options
                .iter()
                .position(|o| o.key == c)
                .map(Response::Choice),
            KeyCode::Esc => Some(Response::Abort),
            _ => None,
        },
        Prompt::CollectShares { .. } => {
            if key.code == KeyCode::Esc {
                return Some(Response::Abort);
            }
            let si = share_input.as_mut()?;
            si.handle_key(key);
            if si.is_complete() {
                let shares = si.collected.iter().map(|c| c.share.clone()).collect();
                Some(Response::Shares(shares))
            } else {
                None
            }
        }
        Prompt::TextInput { .. } => match key.code {
            KeyCode::Enter => Some(Response::Text(std::mem::take(text_buf))),
            KeyCode::Esc => Some(Response::Abort),
            KeyCode::Backspace => {
                text_buf.pop();
                None
            }
            KeyCode::Char(c) => {
                text_buf.push(c);
                None
            }
            _ => None,
        },
        Prompt::CustodianSetup { .. } => {
            if key.code == KeyCode::Esc {
                return Some(Response::Abort);
            }
            let cs = custodian_setup.as_mut()?;
            cs.handle_key(key);
            if cs.confirmed {
                Some(Response::Custodians {
                    names: cs.names.clone(),
                    threshold: cs.threshold,
                })
            } else if cs.aborted {
                Some(Response::Abort)
            } else {
                None
            }
        }
        Prompt::RevealShares { .. } => {
            if key.code == KeyCode::Esc {
                return Some(Response::Abort);
            }
            let sr = share_reveal.as_mut()?;
            if sr.handle_key(key) {
                // handle_key returns true once the "all revealed" screen gets Enter
                Some(Response::Ack)
            } else {
                None
            }
        }
        Prompt::VerifyShares { .. } => {
            if key.code == KeyCode::Esc {
                return Some(Response::Abort);
            }
            let si = share_input.as_mut()?;
            si.handle_key(key);
            if si.is_complete() {
                Some(Response::Ack)
            } else {
                None
            }
        }
        Prompt::WaitDiscSwap { .. } => match key.code {
            KeyCode::Char('1') | KeyCode::Enter => Some(Response::Ack),
            KeyCode::Esc => Some(Response::Abort),
            _ => None,
        },
        // No operator input expected; the burn is not interruptible mid-write.
        Prompt::Note(_) | Prompt::Burning { .. } => None,
        // Terminal screens: any key returns to the menu (handled by the App).
        Prompt::Done(_) | Prompt::Aborted(_) => None,
    }
}

/// Render the content area for the current prompt. `spinner` is a frame counter
/// the App advances on each tick so the burn animation moves.
#[allow(clippy::too_many_arguments)]
pub fn render_prompt(
    frame: &mut Frame,
    area: Rect,
    prompt: &Prompt,
    share_input: Option<&ShareInput>,
    custodian_setup: Option<&CustodianSetup>,
    share_reveal: Option<&ShareReveal>,
    text_buf: &str,
    spinner: usize,
    review_scroll: u16,
) {
    match prompt {
        Prompt::Confirm { title, body } => {
            let mut lines = body_lines(body);
            lines.push(Line::from(""));
            lines.push(hint("[1] Proceed    [Esc] Cancel"));
            boxed(frame, area, title, lines, crate::theme::MODAL_BORDER_YELLOW);
        }
        Prompt::Review { title, body } => {
            let mut lines = body_lines(body);
            lines.push(Line::from(""));
            lines.push(hint("[\u{2191}/\u{2193}] Scroll    [Esc/Q] Done"));
            let block = Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .style(crate::theme::BLOCK)
                .border_style(crate::theme::MODAL_BORDER_CYAN)
                .title_style(crate::theme::TITLE);
            let para = Paragraph::new(lines)
                .block(block)
                .alignment(Alignment::Left)
                .wrap(Wrap { trim: false })
                .scroll((review_scroll, 0));
            frame.render_widget(para, area);
        }
        Prompt::ReconfirmClock { rfc3339 } => {
            let lines = vec![
                Line::from(""),
                Line::from("  HSM unlocked. Confirm the system clock is correct before signing."),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  Current time:  {rfc3339}"),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                hint("[1] Clock is correct — proceed    [Esc] Abort"),
            ];
            boxed(
                frame,
                area,
                "Clock Re-confirm",
                lines,
                crate::theme::MODAL_BORDER_YELLOW,
            );
        }
        Prompt::Choose {
            title,
            body,
            options,
        } => {
            let mut lines = body_lines(body);
            lines.push(Line::from(""));
            for opt in options {
                lines.push(Line::from(format!("  [{}]  {}", opt.key, opt.label)));
            }
            lines.push(Line::from(""));
            lines.push(hint("[n] Select    [Esc] Cancel"));
            boxed(frame, area, title, lines, crate::theme::MODAL_BORDER_CYAN);
        }
        Prompt::TextInput { title, label } => {
            let lines = vec![
                Line::from(""),
                Line::from(format!("  {label}")),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  > {text_buf}\u{2588}"),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(""),
                hint("[Enter] Confirm    [Esc] Cancel"),
            ];
            boxed(frame, area, title, lines, crate::theme::MODAL_BORDER_CYAN);
        }
        Prompt::CollectShares { .. } => {
            if let Some(si) = share_input {
                si.render(frame, area);
            } else {
                boxed(
                    frame,
                    area,
                    "Quorum",
                    vec![Line::from("  Preparing share input\u{2026}")],
                    crate::theme::MODAL_BORDER_CYAN,
                );
            }
        }
        Prompt::Burning { what, log } => {
            let s = SPINNER[spinner % SPINNER.len()];
            let mut lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {s}  Writing session to disc\u{2026}"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("  {what}")),
            ];
            // Fill available height: subtract borders (2) + 3 fixed lines above
            let max_log = (area.height as usize).saturating_sub(5);
            for l in log.iter().rev().take(max_log).rev() {
                lines.push(Line::from(Span::styled(
                    format!("    {l}"),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            boxed(
                frame,
                area,
                "Burning Disc",
                lines,
                crate::theme::MODAL_BORDER_YELLOW,
            );
        }
        Prompt::CustodianSetup { .. } => {
            if let Some(cs) = custodian_setup {
                cs.render(frame, area);
            }
        }
        Prompt::RevealShares { .. } => {
            if let Some(sr) = share_reveal {
                sr.render(frame, area);
            }
        }
        Prompt::VerifyShares { .. } => {
            if let Some(si) = share_input {
                si.render(frame, area);
            }
        }
        Prompt::WaitDiscSwap { session_count } => {
            let lines = vec![
                Line::from(""),
                Line::from(format!(
                    "  Ready to copy {session_count} session(s) to new disc."
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  1. Eject the source disc.",
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(Span::styled(
                    "  2. Insert a blank write-once disc.",
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                hint("[1] Target disc ready \u{2014} proceed    [Esc] Abort"),
            ];
            boxed(
                frame,
                area,
                "Disc Migration \u{2014} Swap Disc",
                lines,
                crate::theme::MODAL_BORDER_YELLOW,
            );
        }
        Prompt::Note(msg) => {
            boxed(
                frame,
                area,
                "Working",
                vec![Line::from(""), Line::from(format!("  {msg}"))],
                crate::theme::BORDER,
            );
        }
        Prompt::Done(outcome) => {
            let mut lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  \u{2713} {}", outcome.headline),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];
            for d in &outcome.detail {
                lines.push(Line::from(format!("  {d}")));
            }
            lines.push(Line::from(""));
            lines.push(hint("[Esc] Return to menu"));
            boxed(
                frame,
                area,
                "Ceremony Complete",
                lines,
                crate::theme::MODAL_BORDER_CYAN,
            );
        }
        Prompt::Aborted(reason) => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  \u{2717} Aborted: {reason}"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                hint("[Esc] Return to menu"),
            ];
            boxed(
                frame,
                area,
                "Ceremony Aborted",
                lines,
                crate::theme::MODAL_BORDER_YELLOW,
            );
        }
    }
}

fn body_lines(body: &[String]) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    for b in body {
        lines.push(Line::from(format!("  {b}")));
    }
    lines
}

fn hint(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {text}"),
        Style::default().fg(Color::DarkGray),
    ))
}

fn boxed(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>, border: Style) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
        .style(crate::theme::BLOCK)
        .border_style(border)
        .title_style(crate::theme::TITLE);
    let para = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::io::{Choice, Outcome};
    use ratatui::{backend::TestBackend, Terminal};

    fn render_one(prompt: &Prompt) {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render_prompt(f, f.area(), prompt, None, None, None, "", 0, 0))
            .unwrap();
    }

    #[test]
    fn every_prompt_variant_renders_without_panic() {
        render_one(&Prompt::Confirm {
            title: "Sign and write CRL".into(),
            body: vec!["CRL number: 7".into()],
        });
        render_one(&Prompt::Review {
            title: "Validation Report".into(),
            body: vec!["PASS: disc_status".into()],
        });
        render_one(&Prompt::ReconfirmClock {
            rfc3339: "2026-01-01T00:00:00Z".into(),
        });
        render_one(&Prompt::Choose {
            title: "Pick a profile".into(),
            body: vec![],
            options: vec![Choice {
                key: '1',
                label: "TLS server".into(),
            }],
        });
        render_one(&Prompt::CollectShares {
            sss: anodize_config::state::SssMetadata {
                generation: 1,
                threshold: 2,
                total: 2,
                custodians: vec![],
                pin_verify_hash: String::new(),
                share_commitments: vec![],
            },
        });
        render_one(&Prompt::Burning {
            what: "20260101-record".into(),
            log: vec!["Opening /dev/sr0".into()],
        });
        render_one(&Prompt::Note("CRL signed.".into()));
        render_one(&Prompt::Done(Outcome {
            headline: "CRL #7 written".into(),
            detail: vec!["Revoked entries: 0".into()],
        }));
        render_one(&Prompt::Aborted("operator declined".into()));
        render_one(&Prompt::WaitDiscSwap { session_count: 5 });
    }
}
