//! `authenticate` action: a credential opens a session on a backend for the
//! steps that follow.

use rite_model::params::AuthenticateParams;
use rite_model::{
    ActionType, ArtifactRef, Credential, Format, Prompt, ValidatorSpec, unsupported_fields,
};
use rite_runtime::{
    Action, ActionError, HandlerContext, Icon, Reporter, Response, StepInfo, StepResult,
    parse_params,
};
use rite_sdk::{Backend, PivBackend};
use secrecy::ExposeSecret;
use serde_json::json;

/// Open a session on a backend with one of its credentials.
///
/// Rite authenticates with a user credential its holder types: a PIV PIN.
/// The device stays unlocked for later steps on the same backend until the
/// run ends, the device is reset or removed, or a key whose PIN policy is
/// `always` is used once. The transcript records the credential, what it
/// grants, where its value came from and how many tries the device had
/// left, never the value or its length.
pub struct AuthenticateAction;

impl Action for AuthenticateAction {
    fn action_type(&self) -> ActionType {
        ActionType::Authenticate
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: AuthenticateParams = parse_params(params)?;
        let reference = step.required_named_input("credential", "authenticate")?;
        let found = match reference {
            ArtifactRef::Credential { id } => ctx.credentials.get(id),
            ArtifactRef::Material { .. } | ArtifactRef::Produced { .. } => None,
        };
        let Some(credential) = found else {
            return Err(ActionError::Failed(format!(
                "authenticate input 'credential' ('{}') must be a credential, as \
                 '${{credential.<id>}}'",
                reference.display_name()
            )));
        };
        let name = credential.id.as_str();
        let shown = credential.display_name();
        let backend =
            backend.ok_or_else(|| ActionError::Failed("authenticate requires a backend".into()))?;
        let backend_name = backend.name().to_string();
        check_credential(credential, &backend_name)?;
        if let Some(message) = typed.message {
            reporter.log(Icon::Info, message)?;
        }
        let piv = backend.as_piv_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "backend '{backend_name}' takes no PIN: it is not a PIV device"
            ))
        })?;

        let retries_before = enter_and_verify_pin(piv, shown, reporter)?;
        reporter.backend_operation(
            "authenticate",
            json!({
                "credential": name,
                "grants": credential.grants,
                "source": credential.source,
                "retries_before": retries_before,
            }),
            json!({}),
            None,
        )?;
        Ok(StepResult::completed(format!(
            "Backend '{backend_name}' unlocked with '{shown}'"
        )))
    }
}

/// Refuses a credential of another backend, or one Rite cannot present
/// yet. `rite check` refuses both first; this holds for a caller that
/// skipped it.
fn check_credential(credential: &Credential, backend: &str) -> Result<(), ActionError> {
    let name = &credential.id;
    if credential.backend != backend {
        return Err(ActionError::Failed(format!(
            "'{name}' is a credential of backend '{}', and this step runs on '{backend}'",
            credential.backend
        )));
    }
    if let (grants, source) = credential.unsupported()
        && (grants.is_some() || source.is_some())
    {
        return Err(ActionError::Failed(format!(
            "'{name}' declares {}: Rite authenticates with a user credential its holder types, \
             and does not support this one yet",
            unsupported_fields(grants, source)
        )));
    }
    Ok(())
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
    name: &str,
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
            label: format!("Enter the PIN of '{name}' (6 to 8 characters)"),
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
    use rite_model::{
        CredentialGrant, CredentialId, CredentialSource, NamedInput, StepFact, StepId, StepInputs,
    };
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

    /// The PIN of backend `token`, typed by its holder.
    fn card_pin() -> Credential {
        Credential {
            id: CredentialId::new("card_pin"),
            title: Some("Signer's PIN".to_string()),
            description: None,
            backend: "token".to_string(),
            grants: CredentialGrant::User,
            source: CredentialSource::Entered,
        }
    }

    fn run(
        card: &mut dyn Backend,
        pin: &str,
        harness: &mut ReporterHarness,
    ) -> Result<StepResult, ActionError> {
        run_with(card, card_pin(), pin, harness)
    }

    fn run_with(
        card: &mut dyn Backend,
        credential: Credential,
        pin: &str,
        harness: &mut ReporterHarness,
    ) -> Result<StepResult, ActionError> {
        harness.enqueue_response(Response::Secret(SecretString::from(pin.to_string())));
        let credentials = HashMap::from([(credential.id.clone(), credential)]);
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
            credentials: &credentials,
        };
        let inputs = StepInputs::Named(HashMap::from([(
            "credential".to_string(),
            NamedInput::One(ArtifactRef::Credential {
                id: CredentialId::new("card_pin"),
            }),
        )]));
        let step = StepInfo::new(
            StepId::new("unlock"),
            None,
            Some("token".to_string()),
            None,
            Some(inputs),
        );
        let mut reporter = harness.reporter(StepId::new("unlock"));
        AuthenticateAction.execute(&step, &ctx, &json!({}), &mut reporter, Some(card))
    }

    #[test]
    fn the_device_is_left_verified_and_the_entry_recorded_without_the_pin() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let result = run(&mut card, "123456", &mut harness).expect("the right PIN unlocks");

        assert!(card.verified, "nothing after the VERIFY may clear it");
        // The operator is shown the credential's title; the transcript keeps
        // its name.
        assert!(
            format!("{:?}", result.outcome).contains("Signer's PIN"),
            "{:?}",
            result.outcome
        );
        let operation = harness
            .facts()
            .iter()
            .find_map(|fact| match fact {
                StepFact::BackendOperation { kind, inputs, .. } if kind == "authenticate" => {
                    Some(inputs.clone())
                }
                _ => None,
            })
            .expect("an authenticate operation");
        assert_eq!(
            operation,
            json!({
                "credential": "card_pin",
                "grants": "user",
                "source": "entered",
                "retries_before": 3,
            })
        );
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
    fn a_credential_of_another_backend_is_refused_before_the_prompt() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let other = Credential {
            backend: "spare".to_string(),
            ..card_pin()
        };
        let error = run_with(&mut card, other, "123456", &mut harness).unwrap_err();
        assert!(error.to_string().contains("backend 'spare'"), "{error}");
        assert_eq!(card.sent, 0);
    }

    #[test]
    fn a_credential_rite_cannot_present_yet_is_refused() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let admin = Credential {
            grants: CredentialGrant::Admin,
            source: CredentialSource::FactoryDefault,
            ..card_pin()
        };
        let error = run_with(&mut card, admin, "123456", &mut harness).unwrap_err();
        assert!(error.to_string().contains("does not support"), "{error}");
        assert_eq!(card.sent, 0);
    }

    #[test]
    fn a_backend_with_no_pin_is_refused() {
        struct Software;
        impl Backend for Software {
            fn name(&self) -> &'static str {
                "token"
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
