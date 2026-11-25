//! `authenticate` action: a credential opens a session on a backend for the
//! steps that follow.

use rite_model::params::AuthenticateParams;
use rite_model::{
    ActionType, ArtifactRef, Credential, CredentialGrant, CredentialSource, Format, Prompt,
    Provider, ValidatorSpec, supports_credential,
};
use rite_runtime::{
    Action, ActionError, HandlerContext, Icon, Reporter, Response, StepInfo, StepResult,
    parse_params, resolve_artifact_bytes,
};
use rite_sdk::{Backend, ManagementKey, PinDefaults, PivBackend, YubikeyBackend};
use secrecy::ExposeSecret;
use serde_json::json;

/// Open a session on a backend with one of its credentials.
///
/// A user credential is a PIV PIN its holder types. The device stays
/// unlocked for later steps on the same backend until the run ends, the
/// device is reset or removed, or a key whose PIN policy is `always` is used
/// once. An admin credential is a `YubiKey`'s management key: the factory
/// default, a value held in an artifact, or one the card releases after the
/// PIN, which then unlocks the device too. The transcript records the
/// credential, what it grants, where its value came from, how many PIN tries
/// the device had left, and for a management key its algorithm and whether
/// it is still the default; never a value or its length.
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
        let credential = credential_input(step, ctx)?;
        let shown = credential.display_name();
        let backend =
            backend.ok_or_else(|| ActionError::Failed("authenticate requires a backend".into()))?;
        let backend_name = backend.name().to_string();
        check_credential(credential, &backend_name)?;
        if let Some(message) = typed.message {
            reporter.log(Icon::Info, message)?;
        }

        let admin = format!("Admin session open on '{backend_name}' with '{shown}'");
        let summary = match &credential.source {
            CredentialSource::Entered => {
                unlock_with_pin(backend, credential, reporter)?;
                format!("Backend '{backend_name}' unlocked with '{shown}'")
            }
            CredentialSource::FactoryDefault => {
                open_admin_session(backend, credential, ManagementKey::FactoryDefault, reporter)?;
                admin
            }
            CredentialSource::Held => {
                let reference = step.required_named_input("value", "authenticate")?;
                let value = resolve_artifact_bytes(
                    ctx.artifacts,
                    &reference.artifact_id(),
                    reference.property(),
                )
                .map_err(|e| {
                    ActionError::Failed(format!(
                        "Cannot read the value of '{shown}' from '{}': {e}",
                        reference.display_name()
                    ))
                })?;
                open_admin_session(backend, credential, ManagementKey::Value(value), reporter)?;
                admin
            }
            CredentialSource::ProtectedBy(by) => {
                let releasing = ctx.credentials.get(by).ok_or_else(|| {
                    ActionError::Failed(format!(
                        "'{}' is protected by '{by}', which the ceremony does not declare",
                        credential.id
                    ))
                })?;
                check_credential(releasing, &backend_name)?;
                if releasing.grants != CredentialGrant::User
                    || releasing.source != CredentialSource::Entered
                {
                    return Err(ActionError::Failed(format!(
                        "'{}' is protected by '{by}', which is not a user credential its holder \
                         types",
                        credential.id
                    )));
                }
                unlock_with_pin(backend, releasing, reporter)?;
                open_admin_session(backend, credential, ManagementKey::Protected, reporter)?;
                admin
            }
            // `check_credential` refused it.
            CredentialSource::OnDevice => {
                return Err(ActionError::Failed(format!(
                    "'{shown}' is presented on the device, which Rite does not support yet"
                )));
            }
        };
        Ok(StepResult::completed(summary))
    }
}

/// The credential a step reads as `credential`.
fn credential_input<'a>(
    step: &StepInfo,
    ctx: &'a HandlerContext,
) -> Result<&'a Credential, ActionError> {
    let reference = step.required_named_input("credential", "authenticate")?;
    let found = match reference {
        ArtifactRef::Credential { id } => ctx.credentials.get(id),
        ArtifactRef::Material { .. } | ArtifactRef::Produced { .. } => None,
    };
    found.ok_or_else(|| {
        ActionError::Failed(format!(
            "authenticate input 'credential' ('{}') must be a credential, as \
             '${{credential.<id>}}'",
            reference.display_name()
        ))
    })
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
    // The backend's own capabilities refuse the rest: a PIN on a device
    // with none, a management key on a device that is not a YubiKey.
    if !Provider::ALL
        .iter()
        .any(|provider| supports_credential(*provider, credential.grants, &credential.source))
    {
        return Err(ActionError::Failed(format!(
            "'{name}' declares 'grants: {}' with 'source: {}', which Rite does not support yet",
            credential.grants,
            credential.source.as_str()
        )));
    }
    Ok(())
}

/// What an `authenticate` record says of the credential, before what the
/// device reported.
fn recorded(credential: &Credential) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("credential".into(), json!(credential.id));
    inputs.insert("grants".into(), json!(credential.grants));
    inputs.insert("source".into(), json!(credential.source));
    inputs
}

/// Have the holder of a user credential type it, and record the
/// authentication.
fn unlock_with_pin(
    backend: &mut dyn Backend,
    credential: &Credential,
    reporter: &mut Reporter<'_>,
) -> Result<(), ActionError> {
    let backend_name = backend.name().to_string();
    let piv = backend.as_piv_mut().ok_or_else(|| {
        ActionError::Failed(format!(
            "backend '{backend_name}' takes no PIN: it is not a PIV device"
        ))
    })?;
    let retries_before = enter_and_verify_pin(piv, credential.display_name(), reporter)?;
    let mut inputs = recorded(credential);
    inputs.insert("retries_before".into(), json!(retries_before));
    // The PIN is verified by now: a card that cannot say whether it is the
    // factory value has not failed the step.
    let defaults = match backend
        .as_yubikey_mut()
        .map(|yubikey| yubikey.pin_defaults())
    {
        None => PinDefaults::default(),
        Some(Ok(defaults)) => defaults,
        Some(Err(error)) => {
            reporter.log(
                Icon::Warning,
                format!("The card did not say whether its PIN is the factory value: {error}"),
            )?;
            PinDefaults::default()
        }
    };
    warn_of_defaults(defaults, credential.display_name(), reporter)?;
    let mut outputs = serde_json::Map::new();
    if let Some(pin) = defaults.pin {
        outputs.insert("pin_is_default".into(), pin.into());
    }
    if let Some(puk) = defaults.puk {
        outputs.insert("puk_is_default".into(), puk.into());
    }
    reporter.backend_operation("authenticate", inputs.into(), outputs.into(), None)?;
    Ok(())
}

/// Warn that the PIN or the PUK is still the factory value, which anyone
/// holding the card can enter.
fn warn_of_defaults(
    defaults: PinDefaults,
    name: &str,
    reporter: &mut Reporter<'_>,
) -> Result<(), ActionError> {
    if defaults.pin == Some(true) {
        reporter.log(
            Icon::Warning,
            format!("'{name}' is still the factory PIN: anyone holding the card can use its keys"),
        )?;
    }
    if defaults.puk == Some(true) {
        reporter.log(
            Icon::Warning,
            "The card's PUK is still the factory value: anyone holding the card can reset its PIN",
        )?;
    }
    Ok(())
}

/// Authenticate with a management key, and record what the card reports
/// of it.
fn open_admin_session(
    backend: &mut dyn Backend,
    credential: &Credential,
    key: ManagementKey<'_>,
    reporter: &mut Reporter<'_>,
) -> Result<(), ActionError> {
    let backend_name = backend.name().to_string();
    let yubikey: &mut dyn YubikeyBackend = backend.as_yubikey_mut().ok_or_else(|| {
        ActionError::Failed(format!(
            "backend '{backend_name}' has no management key Rite can authenticate with: it \
             is not a YubiKey"
        ))
    })?;
    let session = yubikey.authenticate_management(key)?;
    reporter.log(
        Icon::Checkmark,
        format!("Management key of '{backend_name}' accepted"),
    )?;
    reporter.backend_operation(
        "authenticate",
        recorded(credential).into(),
        json!({
            "algorithm": session.algorithm,
            "is_default": session.is_default,
        }),
        None,
    )?;
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
    use rite_runtime::ArtifactValue;
    use rite_runtime::test_support::ReporterHarness;
    use rite_sdk::{
        BackendError, ManagementKeyAlgorithm, ManagementSession, PivBackend, PivDeviceInfo,
        PivSlotInfo,
    };
    use secrecy::SecretBox;
    use secrecy::SecretString;
    use std::collections::HashMap;

    /// The management key [`Card`] accepts when a step holds it.
    const HELD_KEY: &[u8; 24] = b"held-management-key-24b!";

    /// A `YubiKey` that accepts one PIN and one management key, and counts
    /// what reaches it.
    struct Card {
        pin: &'static [u8],
        retries: u32,
        verified: bool,
        sent: u32,
        /// How the management key was presented, once the card accepted it.
        admin: Option<&'static str>,
    }

    impl Card {
        fn new() -> Self {
            Self {
                pin: b"123456",
                retries: 3,
                verified: false,
                sent: 0,
                admin: None,
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
        rite_sdk::backend_capabilities!(as_piv_mut: PivBackend, as_yubikey_mut: YubikeyBackend);
    }

    impl YubikeyBackend for Card {
        fn attest_slot(&self, _slot: rite_sdk::PivSlot) -> Result<Vec<u8>, BackendError> {
            Ok(Vec::new())
        }
        fn authenticate_management(
            &mut self,
            key: ManagementKey<'_>,
        ) -> Result<ManagementSession, BackendError> {
            let presented = match key {
                ManagementKey::FactoryDefault => "factory_default",
                ManagementKey::Value(value) if value == HELD_KEY => "held",
                ManagementKey::Protected if self.verified => "protected",
                ManagementKey::Protected => return Err(BackendError::PinRequired),
                ManagementKey::Value(_) => return Err(BackendError::ManagementKeyRequired),
            };
            self.admin = Some(presented);
            Ok(ManagementSession {
                algorithm: ManagementKeyAlgorithm::Aes192,
                is_default: Some(presented == "factory_default"),
            })
        }
        /// A card whose PIN is still the factory one, and its PUK changed.
        fn pin_defaults(&self) -> Result<PinDefaults, BackendError> {
            Ok(PinDefaults {
                pin: Some(true),
                puk: Some(false),
            })
        }
        fn change_management_key(
            &mut self,
            _current: &[u8],
            _new: &[u8],
        ) -> Result<(), BackendError> {
            Ok(())
        }
        fn slot_metadata(
            &self,
            _slot: rite_sdk::PivSlot,
        ) -> Result<rite_sdk::YubikeySlotMetadata, BackendError> {
            Err(BackendError::UnsupportedOperation("stub".to_string()))
        }
        fn block_puk(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
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
        let id = credential.id.clone();
        run_step(card, vec![credential], &id, None, harness)
    }

    /// Run an `authenticate` step on `card` that reads `credential`, among
    /// `credentials`, and `value` when given.
    fn run_step(
        card: &mut dyn Backend,
        credentials: Vec<Credential>,
        credential: &CredentialId,
        value: Option<&[u8]>,
        harness: &mut ReporterHarness,
    ) -> Result<StepResult, ActionError> {
        let credentials: HashMap<_, _> = credentials
            .into_iter()
            .map(|credential| (credential.id.clone(), credential))
            .collect();
        let artifacts = value
            .map(|value| {
                HashMap::from([(
                    rite_model::ArtifactId::new("admin_key"),
                    ArtifactValue::Secret(SecretBox::new(Box::new(value.to_vec()))),
                )])
            })
            .unwrap_or_default();
        let (params, roles, materials) = (HashMap::new(), HashMap::new(), HashMap::new());
        let ctx = HandlerContext {
            params: &params,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
            credentials: &credentials,
        };
        let mut inputs = HashMap::from([(
            "credential".to_string(),
            NamedInput::One(ArtifactRef::Credential {
                id: credential.clone(),
            }),
        )]);
        if value.is_some() {
            inputs.insert(
                "value".to_string(),
                NamedInput::One(ArtifactRef::Produced {
                    id: rite_model::ArtifactId::new("admin_key"),
                    property: None,
                }),
            );
        }
        let step = StepInfo::new(
            StepId::new("unlock"),
            None,
            Some("token".to_string()),
            None,
            Some(StepInputs::Named(inputs)),
        );
        let mut reporter = harness.reporter(StepId::new("unlock"));
        AuthenticateAction.execute(&step, &ctx, &json!({}), &mut reporter, Some(card))
    }

    /// The management key of backend `token`, from `source`.
    fn card_admin(source: CredentialSource) -> Credential {
        Credential {
            id: CredentialId::new("card_admin"),
            title: None,
            description: None,
            backend: "token".to_string(),
            grants: CredentialGrant::Admin,
            source,
        }
    }

    /// The `authenticate` operations a step recorded, inputs and outputs.
    fn operations(harness: &ReporterHarness) -> Vec<(serde_json::Value, serde_json::Value)> {
        harness
            .facts()
            .iter()
            .filter_map(|fact| match fact {
                StepFact::BackendOperation {
                    kind,
                    inputs,
                    outputs,
                    ..
                } if kind == "authenticate" => Some((inputs.clone(), outputs.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_factory_management_key_opens_an_admin_session_and_records_what_the_card_says() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let admin = card_admin(CredentialSource::FactoryDefault);
        let result = run_step(
            &mut card,
            vec![admin],
            &CredentialId::new("card_admin"),
            None,
            &mut harness,
        )
        .expect("the factory key is accepted");
        assert_eq!(card.admin, Some("factory_default"));
        assert!(!card.verified, "no PIN was asked");
        assert!(format!("{:?}", result.outcome).contains("Admin session"));
        assert_eq!(
            operations(&harness),
            [(
                json!({"credential": "card_admin", "grants": "admin", "source": "factory_default"}),
                json!({"algorithm": "aes192", "is_default": true}),
            )]
        );
    }

    #[test]
    fn a_held_management_key_comes_from_its_artifact_and_is_never_recorded() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        let admin = card_admin(CredentialSource::Held);
        run_step(
            &mut card,
            vec![admin.clone()],
            &admin.id,
            Some(HELD_KEY),
            &mut harness,
        )
        .expect("the held key is accepted");
        assert_eq!(card.admin, Some("held"));
        let recorded = serde_json::to_string(harness.facts()).unwrap();
        assert!(!recorded.contains("held-management"), "{recorded}");

        let mut harness = ReporterHarness::new();
        let error = run_step(
            &mut Card::new(),
            vec![admin.clone()],
            &admin.id,
            None,
            &mut harness,
        )
        .unwrap_err();
        assert!(error.to_string().contains("value"), "{error}");
    }

    /// The PIN is asked first and recorded as its own authentication; the
    /// card then releases the management key.
    #[test]
    fn a_protected_management_key_asks_for_the_pin_that_releases_it() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        harness.enqueue_response(Response::Secret(SecretString::from("123456")));
        let admin = card_admin(CredentialSource::ProtectedBy(CredentialId::new("card_pin")));
        run_step(
            &mut card,
            vec![card_pin(), admin.clone()],
            &admin.id,
            None,
            &mut harness,
        )
        .expect("the PIN releases the key");
        assert!(card.verified);
        assert_eq!(card.admin, Some("protected"));
        let [(pin, _), (admin, _)] = operations(&harness).try_into().expect("two operations");
        assert_eq!(pin.get("credential"), Some(&json!("card_pin")));
        assert_eq!(admin.get("credential"), Some(&json!("card_admin")));
        assert_eq!(
            admin.get("source"),
            Some(&json!({"protected_by": "card_pin"}))
        );
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
        let [(operation, _)] = operations(&harness).try_into().expect("one operation");
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

    /// A factory PIN is worth a warning: anyone holding the card knows it.
    /// The transcript records what the card said of both.
    #[test]
    fn a_factory_pin_is_warned_and_recorded() {
        let mut card = Card::new();
        let mut harness = ReporterHarness::new();
        run(&mut card, "123456", &mut harness).expect("the right PIN unlocks");
        let logged = harness.logged().join("\n");
        assert!(logged.contains("still the factory PIN"), "{logged}");
        assert!(!logged.contains("PUK"), "{logged}");
        let [(_, outputs)] = operations(&harness).try_into().expect("one operation");
        assert_eq!(
            outputs,
            json!({"pin_is_default": true, "puk_is_default": false})
        );
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
            ..card_pin()
        };
        let error = run_with(&mut card, admin, "123456", &mut harness).unwrap_err();
        assert!(error.to_string().contains("does not support"), "{error}");
        assert_eq!(card.sent, 0);
        assert_eq!(card.admin, None);
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
