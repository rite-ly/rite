//! `YubiKey` backend implementation.
//!
//! Provides PIV operations plus `Yubico` vendor extensions (touch/PIN policy
//! metadata, management key authentication, on-device attestation). The inner
//! `YubiKey` is held in a `Mutex` for the same reason as `PivCardBackend`:
//! PC/SC requires `&mut` even for reads, but some trait methods take `&self`.

use std::sync::{Mutex, MutexGuard, PoisonError};

use rite_piv::{convert, ops};
use rite_sdk::{
    Attestation, AttestationBackend, AttestationKind, Backend, BackendConfig, BackendError,
    CertRef, CertStoreBackend, KeyId, KeyMetadata, KeySpec, KeyStoreBackend, PivBackend,
    PivDeviceInfo, PivSlot, PivSlotInfo, SignAlgorithm, SignBackend, YubikeyBackend,
    YubikeySlotMetadata,
};

/// `YubiKey` backend with PIV + `Yubico` extensions.
///
/// Wraps a `yubikey::YubiKey` connection to provide both standard PIV
/// operations (delegated to `rite_piv::ops`) and `Yubico`-specific operations
/// (attestation, slot metadata, management key authentication).
pub struct YubikeyDevice {
    name: String,
    yubikey: Mutex<yubikey::YubiKey>,
}

impl YubikeyDevice {
    /// Connect to a `YubiKey`.
    ///
    /// If the backend config carries a `serial` key, opens the device with that
    /// serial number. Otherwise opens the first available `YubiKey`.
    ///
    /// # Errors
    ///
    /// Returns `BackendError::HardwareFailure` when no device is present, or
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
        Ok(Self {
            name,
            yubikey: Mutex::new(yk),
        })
    }

    /// Lock the device, recovering the guard if a previous holder panicked.
    ///
    /// See `rite_piv::PivCardBackend` for the rationale: a poisoned PC/SC lock
    /// is recovered so a single failed step does not wedge the backend.
    fn device(&self) -> MutexGuard<'_, yubikey::YubiKey> {
        self.yubikey.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Backend for YubikeyDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider(&self) -> &'static str {
        "yubikey"
    }

    fn fingerprint(&self) -> String {
        let yk = self.device();
        format!("yubikey-serial={}+firmware={}", yk.serial(), yk.version())
    }

    rite_sdk::backend_capabilities!(
        as_keystore_mut: KeyStoreBackend,
        as_sign_mut: SignBackend,
        as_attest_mut: AttestationBackend,
        as_certstore_mut: CertStoreBackend,
        as_piv_mut: PivBackend,
        as_yubikey_mut: YubikeyBackend,
    );
}

impl KeyStoreBackend for YubikeyDevice {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let mut yk = self.device();
        ops::generate_key(
            &mut yk,
            spec.algorithm,
            &spec.label,
            spec.location_hint.as_deref(),
        )
    }

    fn import_private_key(
        &mut self,
        _spec: KeySpec,
        _key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError> {
        Err(BackendError::UnsupportedOperation(
            "YubiKey key import requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, BackendError> {
        let mut yk = self.device();
        ops::export_public_key(&mut yk, key_id)
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        let mut yk = self.device();
        ops::list_keys(&mut yk)
    }

    fn delete_key(&mut self, _key_id: &KeyId) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIV does not support key deletion".to_string(),
        ))
    }
}

impl SignBackend for YubikeyDevice {
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        let mut yk = self.device();
        ops::sign(&mut yk, key_id, message, algorithm)
    }

    fn verify(
        &self,
        _key_id: &KeyId,
        _message: &[u8],
        _signature: &[u8],
        _algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIV cards are signing-only; call verify with the raw public key".to_string(),
        ))
    }
}

impl AttestationBackend for YubikeyDevice {
    fn attest_key(&self, key_id: &KeyId) -> Result<Attestation, BackendError> {
        let slot = ops::slot_from_key_id(key_id)?;
        let cert_der = self.attest_slot(slot)?;
        Ok(Attestation {
            kind: AttestationKind::HardwareCertChain,
            certificates: vec![cert_der],
            signature: None,
            metadata: serde_json::json!({ "slot": key_id.as_str() }),
        })
    }
}

impl CertStoreBackend for YubikeyDevice {
    fn store_cert(&mut self, cert_ref: &CertRef, cert_der: &[u8]) -> Result<(), BackendError> {
        match cert_ref {
            CertRef::PivSlot(slot) => {
                let mut yk = self.device();
                ops::write_certificate(&mut yk, *slot, cert_der)
            }
            // `CertRef` is #[non_exhaustive]; PIV addresses certificates by slot only.
            _ => Err(BackendError::UnsupportedOperation(
                "YubiKey backend only supports PivSlot certificate references".to_string(),
            )),
        }
    }

    fn read_cert(&self, cert_ref: &CertRef) -> Result<Vec<u8>, BackendError> {
        match cert_ref {
            CertRef::PivSlot(slot) => {
                let mut yk = self.device();
                ops::read_certificate(&mut yk, *slot)
            }
            // `CertRef` is #[non_exhaustive]; PIV addresses certificates by slot only.
            _ => Err(BackendError::UnsupportedOperation(
                "YubiKey backend only supports PivSlot certificate references".to_string(),
            )),
        }
    }

    fn delete_cert(&mut self, _cert_ref: &CertRef) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "YubiKey does not support certificate deletion".to_string(),
        ))
    }
}

impl PivBackend for YubikeyDevice {
    fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
        let mut yk = self.device();
        ops::list_slots(&mut yk)
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), BackendError> {
        let mut yk = self.device();
        yk.verify_pin(pin).map_err(ops::map_error)
    }

    fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "Changing PIN requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn pin_retries(&mut self) -> Result<u32, BackendError> {
        let mut yk = self.device();
        ops::pin_retries(&mut yk)
    }

    fn unblock_pin(&mut self, _puk: &[u8], _new_pin: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIN unblock requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
        let yk = self.device();
        Ok(ops::device_info(&yk))
    }
}

impl YubikeyBackend for YubikeyDevice {
    fn attest_slot(&self, slot: PivSlot) -> Result<Vec<u8>, BackendError> {
        let yubikey_slot = convert::to_yubikey_slot(slot)?;
        let mut yk = self.device();
        let cert = yubikey::piv::attest(&mut yk, yubikey_slot).map_err(ops::map_error)?;
        Ok(cert.to_vec())
    }

    fn authenticate_management(&mut self, mgm_key: &[u8]) -> Result<(), BackendError> {
        let mut yk = self.device();
        ops::authenticate_management(&mut yk, mgm_key)
    }

    fn change_management_key(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "Changing the management key requires the 'untested' yubikey feature".to_string(),
        ))
    }

    fn slot_metadata(&self, slot: PivSlot) -> Result<YubikeySlotMetadata, BackendError> {
        let mut yk = self.device();
        ops::yubikey_slot_metadata(&mut yk, slot)
    }

    fn block_puk(&mut self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PUK block requires the 'untested' yubikey feature".to_string(),
        ))
    }
}
