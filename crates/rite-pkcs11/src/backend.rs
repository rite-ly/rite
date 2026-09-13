//! Read-only PKCS#11 backend.
//!
//! A session against a module the operator names, and the questions that can
//! be asked of it without changing anything: what token is this, what can it
//! do, what are the attributes of a key it holds, and what is that key's
//! public half.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use rite_sdk::{
    Backend, BackendError, KeyId, KeySecurityAttributes, KeyUsages, Pkcs11Backend, Pkcs11Mechanism,
    Pkcs11TokenFlags, Pkcs11TokenInfo, backend_capabilities,
};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Where to find the token, and which one to use.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Path to the vendor's PKCS#11 module.
    ///
    /// The point of PKCS#11 is that this is chosen at run time: the module is
    /// the vendor's, and Rite links none of them.
    pub module: String,
    /// Token label to open. The first token is used when this is absent,
    /// which is convenient for a single-token test fixture and ambiguous
    /// anywhere else.
    pub token_label: Option<String>,
}

/// A logged-in or anonymous session against one PKCS#11 token.
///
/// The session sits behind a `Mutex` for the reason `PivCardBackend`'s device
/// does: `Backend` is `Send + Sync`, and a PKCS#11 session is neither. That is
/// not an accident of this crate. A session is a single-threaded conversation
/// with a token, and the specification says as much; the mutex is where that
/// meets a trait built for backends that can be shared.
pub struct Pkcs11TokenBackend {
    name: String,
    context: Pkcs11,
    slot: Slot,
    session: Mutex<Session>,
    token: Pkcs11TokenInfo,
}

impl std::fmt::Debug for Pkcs11TokenBackend {
    /// Names the backend and the token, and nothing about the session: a
    /// PKCS#11 session handle says nothing a reader can act on.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11TokenBackend")
            .field("name", &self.name)
            .field("token", &self.token.label)
            .finish_non_exhaustive()
    }
}

impl Pkcs11TokenBackend {
    /// Open a session against the token named by `config`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Configuration`] if the module cannot be loaded
    /// or the named token is not present, and [`BackendError::HardwareFailure`]
    /// if the module is there but the session cannot be opened.
    pub fn try_new(name: &str, config: &Pkcs11Config) -> Result<Self, BackendError> {
        let context = Pkcs11::new(&config.module)
            .map_err(|e| BackendError::Configuration(format!("load {}: {e}", config.module)))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| BackendError::Configuration(format!("initialize module: {e}")))?;

        let slot = find_slot(&context, config.token_label.as_deref())?;
        let session = context
            .open_rw_session(slot)
            .map_err(|e| BackendError::HardwareFailure(format!("open session: {e}")))?;
        let token = read_token_info(&context, slot)?;

        Ok(Self {
            name: name.to_string(),
            context,
            slot,
            session: Mutex::new(session),
            token,
        })
    }

    /// The session, recovered even if a previous holder panicked. A poisoned
    /// mutex says a thread died, not that the token is unusable.
    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Find a key object by its `CKA_LABEL`.
    ///
    /// A `KeyId` on this backend is the label, which is what an operator sees
    /// in the vendor's own tooling. A handle would be shorter but is only
    /// valid for the life of the session.
    fn find_key(
        &self,
        key_id: &KeyId,
        class: ObjectClassFilter,
    ) -> Result<ObjectHandle, BackendError> {
        let mut template = vec![Attribute::Label(key_id.as_str().as_bytes().to_vec())];
        template.push(match class {
            ObjectClassFilter::Private => {
                Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY)
            }
            ObjectClassFilter::Secret => {
                Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY)
            }
        });
        let found = self
            .session()
            .find_objects(&template)
            .map_err(|e| BackendError::HardwareFailure(format!("find objects: {e}")))?;
        found
            .first()
            .copied()
            .ok_or_else(|| BackendError::KeyNotFound(key_id.as_str().to_string()))
    }
}

/// Which object class a lookup is after.
#[derive(Debug, Clone, Copy)]
enum ObjectClassFilter {
    Private,
    Secret,
}

impl Backend for Pkcs11TokenBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider(&self) -> &'static str {
        "pkcs11"
    }

    fn fingerprint(&self) -> String {
        format!(
            "pkcs11-token={}+serial={}+firmware={}",
            self.token.label, self.token.serial, self.token.firmware_version
        )
    }

    backend_capabilities!(
        /// Reports token identity, mechanisms and key attributes.
        as_pkcs11_mut: Pkcs11Backend,
    );
}

impl Pkcs11Backend for Pkcs11TokenBackend {
    fn token_info(&self) -> Result<Pkcs11TokenInfo, BackendError> {
        Ok(self.token.clone())
    }

    fn key_security_attributes(
        &self,
        key_id: &KeyId,
    ) -> Result<KeySecurityAttributes, BackendError> {
        let handle = self
            .find_key(key_id, ObjectClassFilter::Private)
            .or_else(|_| self.find_key(key_id, ObjectClassFilter::Secret))?;

        let wanted = [
            AttributeType::AlwaysSensitive,
            AttributeType::NeverExtractable,
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::WrapWithTrusted,
            AttributeType::Sign,
            AttributeType::Verify,
            AttributeType::Encrypt,
            AttributeType::Decrypt,
            AttributeType::Wrap,
            AttributeType::Unwrap,
            AttributeType::Derive,
        ];
        let attributes = self
            .session()
            .get_attributes(handle, &wanted)
            .map_err(|e| BackendError::HardwareFailure(format!("read attributes: {e}")))?;

        // A token may return fewer attributes than were asked for: one it does
        // not hold is absent rather than false, and absent reads as false here.
        let mut found = KeySecurityAttributes {
            always_sensitive: false,
            never_extractable: false,
            sensitive: false,
            extractable: false,
            wrap_with_trusted_only: false,
            usages: KeyUsages::empty(),
        };
        for attribute in &attributes {
            let usage = match attribute {
                Attribute::AlwaysSensitive(v) => {
                    found.always_sensitive = *v;
                    continue;
                }
                Attribute::NeverExtractable(v) => {
                    found.never_extractable = *v;
                    continue;
                }
                Attribute::Sensitive(v) => {
                    found.sensitive = *v;
                    continue;
                }
                Attribute::Extractable(v) => {
                    found.extractable = *v;
                    continue;
                }
                Attribute::WrapWithTrusted(v) => {
                    found.wrap_with_trusted_only = *v;
                    continue;
                }
                Attribute::Sign(v) => (*v, KeyUsages::SIGN),
                Attribute::Verify(v) => (*v, KeyUsages::VERIFY),
                Attribute::Encrypt(v) => (*v, KeyUsages::ENCRYPT),
                Attribute::Decrypt(v) => (*v, KeyUsages::DECRYPT),
                Attribute::Wrap(v) => (*v, KeyUsages::WRAP),
                Attribute::Unwrap(v) => (*v, KeyUsages::UNWRAP),
                Attribute::Derive(v) => (*v, KeyUsages::DERIVE),
                _ => continue,
            };
            if usage.0 {
                found.usages |= usage.1;
            }
        }
        Ok(found)
    }

    fn supported_mechanisms(&self) -> Result<Vec<Pkcs11Mechanism>, BackendError> {
        let mechanisms = self
            .context
            .get_mechanism_list(self.slot)
            .map_err(|e| BackendError::HardwareFailure(format!("list mechanisms: {e}")))?;
        Ok(mechanisms
            .into_iter()
            .map(|mechanism| Pkcs11Mechanism::new(format!("{mechanism:?}")))
            .collect())
    }

    fn login(&mut self, pin: &[u8]) -> Result<(), BackendError> {
        let pin = std::str::from_utf8(pin)
            .map_err(|_| BackendError::InvalidData("PIN is not valid UTF-8".to_string()))?;
        self.session()
            .login(UserType::User, Some(&AuthPin::from(pin.to_string())))
            .map_err(|e| BackendError::HardwareFailure(format!("login: {e}")))
    }

    fn logout(&mut self) -> Result<(), BackendError> {
        self.session()
            .logout()
            .map_err(|e| BackendError::HardwareFailure(format!("logout: {e}")))
    }
}

/// Find the slot holding the named token, or the first token present.
fn find_slot(context: &Pkcs11, token_label: Option<&str>) -> Result<Slot, BackendError> {
    let slots = context
        .get_slots_with_token()
        .map_err(|e| BackendError::Configuration(format!("list slots: {e}")))?;

    match token_label {
        None => slots.first().copied().ok_or(BackendError::TokenNotPresent),
        Some(wanted) => {
            for slot in slots {
                let info = context
                    .get_token_info(slot)
                    .map_err(|e| BackendError::HardwareFailure(format!("token info: {e}")))?;
                if info.label().trim() == wanted {
                    return Ok(slot);
                }
            }
            Err(BackendError::Configuration(format!(
                "no token labelled '{wanted}' is present"
            )))
        }
    }
}

/// Read the token's identity and capability flags.
fn read_token_info(context: &Pkcs11, slot: Slot) -> Result<Pkcs11TokenInfo, BackendError> {
    let info = context
        .get_token_info(slot)
        .map_err(|e| BackendError::HardwareFailure(format!("token info: {e}")))?;

    let mut flags = Pkcs11TokenFlags::empty();
    if info.login_required() {
        flags |= Pkcs11TokenFlags::LOGIN_REQUIRED;
    }
    if info.user_pin_initialized() {
        flags |= Pkcs11TokenFlags::USER_PIN_INITIALIZED;
    }
    if info.token_initialized() {
        flags |= Pkcs11TokenFlags::TOKEN_INITIALIZED;
    }
    if info.write_protected() {
        flags |= Pkcs11TokenFlags::WRITE_PROTECTED;
    }

    Ok(Pkcs11TokenInfo {
        label: info.label().trim().to_string(),
        manufacturer: info.manufacturer_id().trim().to_string(),
        model: info.model().trim().to_string(),
        serial: info.serial_number().trim().to_string(),
        firmware_version: info.firmware_version().to_string(),
        flags,
    })
}
