//! PIV smart card backend implementation.
//!
//! Wraps a `yubikey::YubiKey` connection (via a `Mutex` for interior
//! mutability) to provide standard PIV operations per NIST SP 800-73-5.

use std::sync::{Mutex, MutexGuard};

use rite_sdk::{
    Backend, BackendConfig, BackendError, CertRef, CertStoreBackend, KeyId, KeyMetadata, KeySpec,
    KeyStoreBackend, PivBackend, PivDeviceInfo, PivSlotInfo, PublicKeyDer, SignAlgorithm,
    SignBackend,
};

use crate::ops;

/// PIV smart card backend.
///
/// Wraps a `yubikey::YubiKey` connection to provide standard PIV operations
/// per NIST SP 800-73-5. The inner `YubiKey` is held in a `Mutex` because
/// PC/SC transactions require exclusive device access even for read-only
/// commands, yet several backend trait methods take `&self`. The device's
/// identity is read once at connection, so reporting it never takes the lock.
pub struct PivCardBackend {
    name: String,
    yubikey: Mutex<yubikey::YubiKey>,
    info: PivDeviceInfo,
    fingerprint: String,
}

impl PivCardBackend {
    /// Connect to a PIV card.
    ///
    /// If the backend config carries a `serial` key, opens the card with that
    /// serial number. Otherwise opens the first available PIV card.
    ///
    /// # Errors
    ///
    /// Returns `BackendError::HardwareFailure` when no card is present, or
    /// `BackendError::Configuration` when the serial number cannot be parsed.
    pub fn try_new(name: String, config: &BackendConfig) -> Result<Self, BackendError> {
        let serial = config
            .extra
            .get("serial")
            .and_then(serde_json::Value::as_str);
        let yk = if let Some(serial_str) = serial {
            let serial_n: u32 = serial_str.parse().map_err(|_| {
                BackendError::Configuration(format!("Invalid serial number: {serial_str}"))
            })?;
            yubikey::YubiKey::open_by_serial(yubikey::Serial(serial_n)).map_err(ops::map_error)?
        } else {
            yubikey::YubiKey::open().map_err(ops::map_error)?
        };
        let info = ops::device_info(&yk);
        let fingerprint = format!("piv-serial={}+firmware={}", yk.serial(), yk.version());
        Ok(Self {
            name,
            yubikey: Mutex::new(yk),
            info,
            fingerprint,
        })
    }

    /// Lock the device; see [`rite_sdk::lock_device`].
    fn device(&self) -> Result<MutexGuard<'_, yubikey::YubiKey>, BackendError> {
        rite_sdk::lock_device(&self.yubikey)
    }
}

impl Backend for PivCardBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider(&self) -> &'static str {
        "piv"
    }

    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    rite_sdk::backend_capabilities!(
        as_keystore_mut: KeyStoreBackend,
        as_sign_mut: SignBackend,
        as_certstore_mut: CertStoreBackend,
        as_piv_mut: PivBackend,
    );
}

impl KeyStoreBackend for PivCardBackend {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let mut yk = self.device()?;
        ops::generate_key(
            &mut yk,
            spec.algorithm,
            &spec.label,
            spec.location_hint.as_deref(),
        )
    }

    fn import_key(
        &mut self,
        _spec: KeySpec,
        _key_bytes: &[u8],
        _passphrase: Option<&[u8]>,
    ) -> Result<KeyMetadata, BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIV key import requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<PublicKeyDer, BackendError> {
        let mut yk = self.device()?;
        ops::export_public_key(&mut yk, key_id)
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        let mut yk = self.device()?;
        ops::list_keys(&mut yk)
    }

    fn delete_key(&mut self, _key_id: &KeyId) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIV does not support key deletion".to_string(),
        ))
    }
}

impl SignBackend for PivCardBackend {
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        let mut yk = self.device()?;
        ops::sign(&mut yk, key_id, message, algorithm)
    }
}

impl CertStoreBackend for PivCardBackend {
    fn store_cert(&mut self, cert_ref: &CertRef, cert_der: &[u8]) -> Result<(), BackendError> {
        match cert_ref {
            CertRef::PivSlot(slot) => {
                let mut yk = self.device()?;
                ops::write_certificate(&mut yk, *slot, cert_der)
            }
            // `CertRef` is #[non_exhaustive]; PIV addresses certificates by slot only.
            _ => Err(BackendError::UnsupportedOperation(
                "PIV backend only supports PivSlot certificate references".to_string(),
            )),
        }
    }

    fn read_cert(&self, cert_ref: &CertRef) -> Result<Vec<u8>, BackendError> {
        match cert_ref {
            CertRef::PivSlot(slot) => {
                let mut yk = self.device()?;
                ops::read_certificate(&mut yk, *slot)
            }
            // `CertRef` is #[non_exhaustive]; PIV addresses certificates by slot only.
            _ => Err(BackendError::UnsupportedOperation(
                "PIV backend only supports PivSlot certificate references".to_string(),
            )),
        }
    }

    fn delete_cert(&mut self, _cert_ref: &CertRef) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIV does not support certificate deletion".to_string(),
        ))
    }
}

impl PivBackend for PivCardBackend {
    fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
        let mut yk = self.device()?;
        ops::list_slots(&mut yk)
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), BackendError> {
        let mut yk = self.device()?;
        yk.verify_pin(pin).map_err(ops::map_error)
    }

    fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "Changing PIN requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn pin_retries(&mut self) -> Result<u32, BackendError> {
        let mut yk = self.device()?;
        ops::pin_retries(&mut yk)
    }

    fn unblock_pin(&mut self, _puk: &[u8], _new_pin: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIN unblock requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
        Ok(self.info.clone())
    }
}
