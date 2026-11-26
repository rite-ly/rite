//! `YubiKey` backend implementation.
//!
//! Provides PIV operations plus `Yubico` vendor extensions (touch/PIN policy
//! metadata, management key authentication, on-device attestation). The inner
//! `YubiKey` is held in a `Mutex` for the same reason as `PivCardBackend`:
//! PC/SC requires `&mut` even for reads, but some trait methods take `&self`.

use std::sync::{Mutex, MutexGuard};

use rite_piv::{convert, ops};
use rite_sdk::{
    AccessPolicy, AgreedSecret, Attestation, AttestationBackend, AttestationFormat, Backend,
    BackendConfig, BackendError, CertRef, CertStoreBackend, CertificateDer, KeyAgreementBackend,
    KeyDecryptBackend, KeyId, KeyMetadata, KeyProtection, KeySpec, KeyStoreBackend, ManagementKey,
    ManagementSession, PinDefaults, PivBackend, PivDeviceInfo, PivSlot, PivSlotInfo, PublicKeyDer,
    SignAlgorithm, SignBackend, YubikeyBackend, YubikeySlotMetadata,
};
use zeroize::Zeroizing;

/// `YubiKey` backend with PIV + `Yubico` extensions.
///
/// Wraps a `yubikey::YubiKey` connection to provide both standard PIV
/// operations (delegated to `rite_piv::ops`) and `Yubico`-specific operations
/// (attestation, slot metadata, management key authentication). The device's
/// identity is read once at connection, so reporting it never takes the lock.
pub struct YubikeyDevice {
    name: String,
    yubikey: Mutex<yubikey::YubiKey>,
    info: PivDeviceInfo,
    fingerprint: String,
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
        let info = ops::device_info(&yk);
        let fingerprint = format!("yubikey-serial={}+firmware={}", yk.serial(), yk.version());
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

impl Backend for YubikeyDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider(&self) -> &'static str {
        "yubikey"
    }

    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    rite_sdk::backend_capabilities!(
        as_keystore_mut: KeyStoreBackend,
        as_sign_mut: SignBackend,
        as_attest_mut: AttestationBackend,
        as_agreement_mut: KeyAgreementBackend,
        as_key_decrypt_mut: KeyDecryptBackend,
        as_certstore_mut: CertStoreBackend,
        as_piv_mut: PivBackend,
        as_yubikey_mut: YubikeyBackend,
    );
}

impl KeyStoreBackend for YubikeyDevice {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let mut yk = self.device()?;
        ops::generate_key(
            &mut yk,
            spec.algorithm,
            &spec.label,
            spec.location_hint.as_deref(),
            spec.policy.access,
        )
    }

    fn access_policy(&self, key_id: &KeyId) -> Result<Option<AccessPolicy>, BackendError> {
        let mut yk = self.device()?;
        ops::access_policy(&mut yk, key_id)
    }

    fn import_key(
        &mut self,
        _spec: KeySpec,
        _key_bytes: &[u8],
        _passphrase: Option<&[u8]>,
    ) -> Result<KeyMetadata, BackendError> {
        Err(BackendError::UnsupportedOperation(
            "YubiKey key import is not supported yet".to_string(),
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

impl SignBackend for YubikeyDevice {
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

impl KeyAgreementBackend for YubikeyDevice {
    fn agree(&mut self, key_id: &KeyId, peer: &PublicKeyDer) -> Result<AgreedSecret, BackendError> {
        let mut yk = self.device()?;
        ops::agree(&mut yk, key_id, peer)
    }
}

impl KeyDecryptBackend for YubikeyDevice {
    fn decrypt_key(
        &mut self,
        key_id: &KeyId,
        encrypted: &[u8],
        protection: KeyProtection,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let mut yk = self.device()?;
        ops::decrypt_key(&mut yk, key_id, encrypted, protection)
    }
}

impl AttestationBackend for YubikeyDevice {
    /// The slot's attestation certificate, signed by the key in F9, followed
    /// by F9's own certificate.
    ///
    /// The slot's metadata (firmware 5.3 and later) is read first, so an
    /// imported key or an empty slot is named as such: the card refuses both
    /// with the same status word.
    fn attest_key(&mut self, key_id: &KeyId) -> Result<Attestation, BackendError> {
        let slot = ops::slot_from_key_id(key_id)?;
        let yubikey_slot = convert::to_yubikey_slot(slot)?;
        let mut yk = self.device()?;
        // Whether the card reported the key's origin. Without that, a
        // refusal is put down to its usual causes, said as such.
        let origin_known = match yubikey::piv::metadata(&mut yk, yubikey_slot) {
            Ok(metadata) if metadata.origin == Some(yubikey::piv::Origin::Imported) => {
                return Err(BackendError::OperationNotPermitted(format!(
                    "slot {key_id} holds an imported key, and a YubiKey attests only keys \
                     it generated"
                )));
            }
            Ok(metadata) => metadata.origin.is_some(),
            Err(yubikey::Error::NotFound) => {
                return Err(BackendError::SlotEmpty(key_id.to_string()));
            }
            Err(_) => false,
        };
        let leaf = yubikey::piv::attest(&mut yk, yubikey_slot).map_err(|error| match error {
            yubikey::Error::GenericError if !origin_known => {
                BackendError::OperationNotPermitted(format!(
                    "the YubiKey refused to attest slot {key_id}; it does not report a key's \
                     origin, and the usual causes are an empty slot or an imported key"
                ))
            }
            other => ops::map_error(other),
        })?;
        let device = ops::read_certificate_at(&mut yk, yubikey::piv::SlotId::Attestation)?;
        Attestation::new(
            AttestationFormat::YubicoPiv,
            vec![
                CertificateDer::new(leaf.to_vec())?,
                CertificateDer::new(device)?,
            ],
        )
    }
}

impl CertStoreBackend for YubikeyDevice {
    fn store_cert(&mut self, cert_ref: &CertRef, cert_der: &[u8]) -> Result<(), BackendError> {
        match cert_ref {
            CertRef::PivSlot(slot) => {
                let mut yk = self.device()?;
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
                let mut yk = self.device()?;
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
        let mut yk = self.device()?;
        ops::list_slots(&mut yk)
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), BackendError> {
        let mut yk = self.device()?;
        yk.verify_pin(pin).map_err(ops::map_error)
    }

    fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "Changing PIN is not supported yet".to_string(),
        ))
    }

    fn pin_retries(&mut self) -> Result<u32, BackendError> {
        let mut yk = self.device()?;
        ops::pin_retries(&mut yk)
    }

    fn unblock_pin(&mut self, _puk: &[u8], _new_pin: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PIN unblock is not supported yet".to_string(),
        ))
    }

    fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
        Ok(self.info.clone())
    }
}

impl YubikeyBackend for YubikeyDevice {
    fn authenticate_management(
        &mut self,
        key: ManagementKey<'_>,
    ) -> Result<ManagementSession, BackendError> {
        let mut yk = self.device()?;
        ops::authenticate_management(&mut yk, key)
    }

    fn pin_defaults(&self) -> Result<PinDefaults, BackendError> {
        let mut yk = self.device()?;
        ops::pin_defaults(&mut yk)
    }

    fn change_management_key(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "Changing the management key is not supported yet".to_string(),
        ))
    }

    fn slot_metadata(&self, slot: PivSlot) -> Result<YubikeySlotMetadata, BackendError> {
        let mut yk = self.device()?;
        ops::yubikey_slot_metadata(&mut yk, slot)
    }

    fn block_puk(&mut self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOperation(
            "PUK block is not supported yet".to_string(),
        ))
    }
}
