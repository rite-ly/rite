//! `enter_pin` action: a person unlocks a device for the steps that follow.

use rite_model::params::EnterPinParams;
use rite_model::{ActionType, Format, Prompt, ValidatorSpec};
use rite_runtime::{
    Action, ActionError, HandlerContext, Icon, Reporter, Response, StepInfo, StepResult,
    parse_params,
};
use rite_sdk::{Backend, PivBackend};
use secrecy::ExposeSecret;
use serde_json::json;

/// Ask for a device's PIN and have the device verify it.
///
/// The device stays unlocked for later steps on the same backend until the
/// run ends, the device is reset or removed, or a key whose PIN policy is
/// `always` is used once. The transcript records that the PIN was entered and
/// how many tries the device had left, never the PIN or its length.
pub struct EnterPinAction;

impl Action for EnterPinAction {
    fn action_type(&self) -> ActionType {
        ActionType::EnterPin
    }

    fn execute(
        &self,
        _step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: EnterPinParams = parse_params(params)?;
        if let Some(message) = typed.message {
            reporter.log(Icon::Info, message)?;
        }
        let backend =
            backend.ok_or_else(|| ActionError::Failed("enter_pin requires a backend".into()))?;
        let name = backend.name().to_string();
        let piv = backend.as_piv_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "backend '{name}' takes no PIN: it is not a PIV device"
            ))
        })?;

        let retries_before = enter_and_verify_pin(piv, reporter)?;
        reporter.backend_operation(
            "verify_pin",
            json!({ "retries_before": retries_before }),
            json!({}),
            None,
        )?;
        Ok(StepResult::completed(format!("Backend '{name}' unlocked")))
    }
}

/// Ask for the device's PIN and have the device verify it, returning how many tries the device had left before this entry.
///
/// The retry count is read before the PIN is sent, so the warning at one
/// try left comes before that try is spent.
///
/// # Errors
///
/// The backend's errors: `PinFailed` with the tries left for a wrong PIN,
/// `PinBlocked` once none are. A PIN of the wrong length is asked again
/// before anything reaches the device, so it costs no try.
fn enter_and_verify_pin(
    piv: &mut dyn PivBackend,
    reporter: &mut Reporter<'_>,
) -> Result<u32, ActionError> {
    let retries = piv.pin_retries()?;
    // 0 comes only from a card that reads a verified PIN so; a blocked PIN
    // is `PinBlocked` from `pin_retries`.
    if retries == 1 {
        reporter.log(
            Icon::Warning,
            "Only 1 PIN attempt remaining. Card will lock on failure.",
        )?;
    }

    // Six to eight bytes, which is what SP 800-73 gives a PIV PIN and what
    // the card will refuse otherwise. Checked here so a slip costs a retype
    // rather than one of the card's few attempts. The prompt counts
    // characters and the card counts bytes, so a PIN with a character
    // outside ASCII can pass the one and fail the other: it is asked again.
    let pin = loop {
        let response = reporter.prompt(&Prompt::Secret {
            label: "Enter PIV PIN (6 to 8 characters)".to_string(),
            validator: ValidatorSpec::Format {
                format: Format::Text,
                min_length: Some(6),
                max_length: Some(8),
            },
        })?;
        let Response::Secret(pin) = response else {
            return Err(ActionError::Failed(
                "expected a secret response for the PIV PIN".to_string(),
            ));
        };
        let length = pin.expose_secret().len();
        if (6..=8).contains(&length) {
            break pin;
        }
        reporter.log(
            Icon::Warning,
            format!(
                "The PIN is {length} bytes and a PIV PIN is 6 to 8; nothing was sent to \
                 the card. Enter it again."
            ),
        )?;
    };
    piv.verify_pin(pin.expose_secret().as_bytes())?;
    reporter.log(Icon::Checkmark, "PIN verified")?;
    Ok(retries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::{StepFact, StepId};
    use rite_runtime::test_support::ReporterHarness;
    use rite_sdk::{BackendError, PivBackend, PivDeviceInfo, PivSlotInfo};
    use secrecy::SecretString;
    use std::collections::HashMap;

    /// A PIV device that accepts one PIN and counts what reaches it.
    struct Card {
        pin: &'static [u8],
        retries: u32,
        verified: bool,
        sent: u32,
    }

    impl Card {
        fn new() -> Self {
            Self {
                pin: b"123456",
                retries: 3,
                verified: false,
                sent: 0,
            }
        }
    }

    impl Backend for Card {
        fn name(&self) -> &'static str {
            "token"
        }
        fn provider(&self) -> &'static str {
            "stub"
        }
        fn fingerprint(&self) -> String {
            "stub".to_string()
        }
        rite_sdk::backend_capabilities!(as_piv_mut: PivBackend);
    }

    impl PivBackend for Card {
        fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
            Ok(Vec::new())
        }
        fn verify_pin(&mut self, pin: &[u8]) -> Result<(), BackendError> {
            self.sent = self.sent.saturating_add(1);
            if pin == self.pin {
                self.verified = true;
                Ok(())
            } else {
                self.retries = self.retries.saturating_sub(1);
                Err(BackendError::PinFailed(self.retries))
            }
        }
        fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
        fn pin_retries(&mut self) -> Result<u32, BackendError> {
            Ok(self.retries)
        }
        fn unblock_pin(&mut self, _puk: &[u8], _new: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
        fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
            Ok(PivDeviceInfo {
                serial: None,
                firmware_version: None,
                form_factor: None,
            })
        }
    }

    fn run(
        card: &mut dyn Backend,
        pin: &str,
        harness: &mut ReporterHarness,
    ) -> Result<StepResult, ActionError> {
        harness.enqueue_response(Response::Secret(SecretString::from(pin.to_string())));
        let (params, artifacts, roles, materials) = (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        let ctx = HandlerContext {
            params: &params,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
        };
        let step = StepInfo::new(
            StepId::new("unlock"),
            None,
            Some("token".to_string()),
            None,
            None,
        );
        let mut reporter = harness.reporter(StepId::new("unlock"));
        EnterPinAction.execute(&step, &ctx, &json!({}), &mut reporter, Some(card))
    }

    #[test]
    fn the_device_is_left_verified_and_the_entry_recorded_without_the_pin() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        run(&mut card, "123456", &mut harness).expect("the right PIN unlocks");

        assert!(card.verified, "nothing after the VERIFY may clear it");
        let operation = harness
            .facts()
            .iter()
            .find_map(|fact| match fact {
                StepFact::BackendOperation { kind, inputs, .. } if kind == "verify_pin" => {
                    Some(inputs.clone())
                }
                _ => None,
            })
            .expect("a verify_pin operation");
        assert_eq!(operation, json!({ "retries_before": 3 }));
        let recorded = serde_json::to_string(harness.facts()).unwrap();
        assert!(!recorded.contains("123456"), "{recorded}");
    }

    #[test]
    fn a_wrong_pin_fails_the_attempt_with_the_tries_left() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let error = run(&mut card, "654321", &mut harness).unwrap_err();
        assert!(
            matches!(error, ActionError::Backend(BackendError::PinFailed(2))),
            "{error:?}"
        );
        assert!(error.retriability().is_retriable());
        assert!(
            !harness
                .facts()
                .iter()
                .any(|fact| matches!(fact, StepFact::BackendOperation { .. })),
            "a failed entry performs nothing a retry would repeat"
        );
    }

    #[test]
    fn a_pin_of_the_wrong_byte_length_is_asked_again_and_never_reaches_the_card() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        // Six characters, but twelve bytes; then the right PIN.
        harness.enqueue_response(Response::Secret(SecretString::from("éééééé")));
        run(&mut card, "123456", &mut harness).expect("the second entry unlocks");
        assert_eq!(
            card.sent, 1,
            "only the PIN of the right length reached the card"
        );
        assert_eq!(card.retries, 3);
        assert!(card.verified);
    }

    #[test]
    fn a_backend_with_no_pin_is_refused() {
        struct Software;
        impl Backend for Software {
            fn name(&self) -> &'static str {
                "software"
            }
            fn provider(&self) -> &'static str {
                "stub"
            }
            fn fingerprint(&self) -> String {
                "stub".to_string()
            }
            rite_sdk::backend_capabilities!();
        }
        let mut harness = ReporterHarness::new();
        let error = run(&mut Software, "123456", &mut harness).unwrap_err();
        assert!(error.to_string().contains("takes no PIN"), "{error}");
    }
}
