use super::dialog::{ConfirmDialog, DialogAction};
use crate::integration::{RequestApproval, RequestSet, WrapperRequest};
use crate::output::escape_control_bytes;
use crossterm::event::KeyCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Approve,
    Reject,
}

#[derive(Clone, Debug)]
pub(super) struct WrapperReview {
    pub(super) items: Vec<WrapperRequest>,
    pub(super) decisions: Vec<Option<Decision>>,
    pub(super) selected: usize,
    pub(super) previously_approved: Vec<RequestApproval>,
    pub(super) feedback: String,
    pub(super) disclosure: Option<String>,
    pub(super) detail_scroll: u16,
    required_detail_scroll: u16,
    phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Browse,
    Confirm { open: bool, dialog: ConfirmDialog },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WrapperAction {
    Stay,
    PrepareApprove,
    Complete,
    Cancel,
}

impl WrapperReview {
    pub(super) fn new(
        requests: &RequestSet,
        previously_approved: &[RequestApproval],
    ) -> Option<Self> {
        (!requests.items.is_empty()).then(|| Self {
            items: requests.items.clone(),
            decisions: vec![None; requests.items.len()],
            selected: 0,
            previously_approved: previously_approved.to_vec(),
            feedback: String::new(),
            disclosure: None,
            detail_scroll: 0,
            required_detail_scroll: 0,
            phase: Phase::Browse,
        })
    }

    pub(super) fn handle_key(&mut self, code: KeyCode) -> WrapperAction {
        let disclosure_reviewed = self.disclosure_reviewed();
        match &mut self.phase {
            Phase::Confirm { open, dialog } => {
                let open = *open;
                if matches!(
                    code,
                    KeyCode::PageUp
                        | KeyCode::PageDown
                        | KeyCode::Home
                        | KeyCode::End
                ) {
                    self.scroll(code);
                    return WrapperAction::Stay;
                }
                return match dialog.handle_key(code) {
                    DialogAction::Confirm if disclosure_reviewed => {
                        self.decisions[self.selected] = Some(Decision::Approve);
                        self.phase = Phase::Browse;
                        self.feedback = if open {
                            "OPEN staged access marked APPROVE.".into()
                        } else {
                            "Staged access marked APPROVE.".into()
                        };
                        WrapperAction::Stay
                    }
                    DialogAction::Confirm => {
                        self.feedback = "Review through the final disclosure line before approval.".into();
                        WrapperAction::Stay
                    }
                    DialogAction::Cancel => {
                        self.phase = Phase::Browse;
                        self.feedback =
                            "Approval cancelled; no decision recorded.".into();
                        WrapperAction::Stay
                    }
                    DialogAction::Stay => WrapperAction::Stay,
                };
            }
            Phase::Browse => {}
        }
        match code {
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                self.feedback.clear();
                self.disclosure = None;
                self.detail_scroll = 0;
            }
            KeyCode::Down => {
                self.selected =
                    (self.selected + 1).min(self.items.len().saturating_sub(1));
                self.feedback.clear();
                self.disclosure = None;
                self.detail_scroll = 0;
            }
            KeyCode::Char('a' | 'A' | 'y' | 'Y') => {
                return WrapperAction::PrepareApprove;
            }
            KeyCode::Char('r' | 'R' | 'n' | 'N') => {
                self.decisions[self.selected] = Some(Decision::Reject);
                self.feedback = "Staged access marked REJECT.".into();
            }
            KeyCode::PageUp | KeyCode::PageDown => self.scroll(code),
            KeyCode::Home => self.detail_scroll = 0,
            KeyCode::End => self.detail_scroll = self.required_detail_scroll,
            KeyCode::Enter if self.decisions.iter().all(Option::is_some) => {
                return WrapperAction::Complete;
            }
            KeyCode::Enter => {
                self.feedback =
                    "Every request needs an explicit APPROVE or REJECT decision.".into();
            }
            KeyCode::Esc | KeyCode::Char('q') => return WrapperAction::Cancel,
            _ => {}
        }
        WrapperAction::Stay
    }

    fn scroll(&mut self, code: KeyCode) {
        self.detail_scroll = match code {
            KeyCode::PageUp => self.detail_scroll.saturating_sub(3),
            KeyCode::PageDown => self
                .detail_scroll
                .saturating_add(3)
                .min(self.required_detail_scroll),
            KeyCode::Home => 0,
            KeyCode::End => self.required_detail_scroll,
            _ => self.detail_scroll,
        };
    }

    pub(super) fn begin_approval(&mut self, disclosure: String, open: bool) {
        self.disclosure = Some(disclosure);
        self.detail_scroll = 0;
        self.required_detail_scroll = 0;
        self.feedback.clear();
        self.phase = Phase::Confirm {
            open,
            dialog: ConfirmDialog::new(
                if open {
                    "Approve OPEN request?"
                } else {
                    "Approve request?"
                },
                if open {
                    "This wrapper request removes an important isolation boundary."
                } else {
                    "This grants the fully disclosed, constrained access to the requesting integration."
                },
                if open {
                    "Approve OPEN"
                } else {
                    "Approve access"
                },
            ),
        };
    }

    pub(super) fn set_required_detail_scroll(&mut self, required: u16) {
        self.required_detail_scroll = required;
        self.detail_scroll = self.detail_scroll.min(required);
    }

    fn disclosure_reviewed(&self) -> bool {
        self.detail_scroll >= self.required_detail_scroll
    }

    pub(super) fn approval_prompt(&self) -> Option<String> {
        match &self.phase {
            Phase::Browse => None,
            Phase::Confirm { .. } => Some(
                "Choose explicitly in the confirmation dialog; Cancel is selected by default."
                    .into(),
            ),
        }
    }

    pub(super) fn confirmation_dialog(&self) -> Option<&ConfirmDialog> {
        match &self.phase {
            Phase::Confirm { dialog, .. } => Some(dialog),
            Phase::Browse => None,
        }
    }

    pub(super) fn approved(&self) -> Vec<RequestApproval> {
        self.items
            .iter()
            .zip(&self.decisions)
            .filter(|(_, decision)| **decision == Some(Decision::Approve))
            .map(|(request, _)| request.approval.clone())
            .collect()
    }

    pub(super) fn selected_request(&self) -> &WrapperRequest {
        &self.items[self.selected]
    }

    pub(super) fn was_approved(&self, request: &WrapperRequest) -> bool {
        self.previously_approved.contains(&request.approval)
    }
}

pub(super) fn resource_label(request: &WrapperRequest) -> String {
    let approval = &request.approval;
    if approval.kind == "secret" {
        return format!(
            "Secret variable {} bound to {} (value hidden)",
            escape_control_bytes(&approval.value),
            escape_control_bytes(
                approval.host.as_deref().unwrap_or("invalid host")
            )
        );
    }
    let value = match approval.port {
        Some(port) => {
            format!("{}:{port}", escape_control_bytes(&approval.value))
        }
        None => escape_control_bytes(&approval.value),
    };
    format!("{} {value}", escape_control_bytes(&approval.kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::{RequestApproval, WrapperRequest};

    fn request(kind: &str, value: &str, host: Option<&str>) -> WrapperRequest {
        WrapperRequest {
            approval: RequestApproval {
                requester: "ai-memory".into(),
                kind: kind.into(),
                value: value.into(),
                host: host.map(str::to_string),
                writable: None,
                port: None,
            },
            reason: "needed for project memory".into(),
        }
    }

    #[test]
    fn completion_requires_an_explicit_decision_for_every_request() {
        let requests = RequestSet {
            items: vec![request("host", "example.com", None)],
        };
        let mut review = WrapperReview::new(&requests, &[]).unwrap();
        assert_eq!(review.handle_key(KeyCode::Enter), WrapperAction::Stay);
        assert!(review.feedback.contains("explicit"));
        review.handle_key(KeyCode::Char('r'));
        assert_eq!(review.handle_key(KeyCode::Enter), WrapperAction::Complete);
        assert!(review.approved().is_empty());
    }

    #[test]
    fn prior_approval_is_context_not_a_default_decision() {
        let item = request("host", "example.com", None);
        let requests = RequestSet {
            items: vec![item.clone()],
        };
        let review = WrapperReview::new(&requests, &[item.approval]).unwrap();
        assert!(review.was_approved(review.selected_request()));
        assert_eq!(review.decisions, vec![None]);
    }

    #[test]
    fn approval_dialog_defaults_to_cancel_and_requires_explicit_choice() {
        let requests = RequestSet {
            items: vec![request("host", "example.com", None)],
        };
        let mut review = WrapperReview::new(&requests, &[]).unwrap();
        assert_eq!(
            review.handle_key(KeyCode::Char('a')),
            WrapperAction::PrepareApprove
        );
        assert_eq!(review.decisions, vec![None]);
        review.begin_approval("complete disclosure".into(), false);
        review.handle_key(KeyCode::Enter);
        assert_eq!(review.decisions, vec![None]);
        review.begin_approval("complete disclosure".into(), false);
        review.handle_key(KeyCode::Tab);
        review.handle_key(KeyCode::Enter);
        assert_eq!(review.decisions, vec![Some(Decision::Approve)]);
    }

    #[test]
    fn open_approval_ignores_text_and_keeps_disclosure_scrollable() {
        let requests = RequestSet {
            items: vec![request("private_host", "10.0.0.1", None)],
        };
        let mut review = WrapperReview::new(&requests, &[]).unwrap();
        review.begin_approval("complete disclosure".into(), true);
        review.set_required_detail_scroll(6);
        review.handle_key(KeyCode::PageDown);
        assert_eq!(review.detail_scroll, 3);
        review.handle_key(KeyCode::Char('x'));
        review.handle_key(KeyCode::Enter);
        assert_eq!(review.decisions, vec![None]);
    }

    #[test]
    fn secret_label_contains_only_name_host_and_hidden_notice() {
        let item = request("secret", "GH_TOKEN", Some("api.github.com"));
        let label = resource_label(&item);
        assert_eq!(
            label,
            "Secret variable GH_TOKEN bound to api.github.com (value hidden)"
        );
        assert!(!label.contains("ghp_"));
    }
}
