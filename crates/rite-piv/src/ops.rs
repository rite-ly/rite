//! PIV operations as free functions.
//!
//! All operations take `&mut YubiKey` because PC/SC transactions require
//! exclusive device access even for nominally read-only commands (e.g.
//! `Certificate::read` or `piv::metadata`). Backends call these through a
//! `Mutex<YubiKey>` to satisfy the `Backend: Sync` requirement while still
//! implementing `&self` trait methods.

use der::Encode;
use sha2::{Digest, Sha256, Sha384};
use yubikey::certificate::CertInfo;
use yubikey::piv::{self, SlotId};
use yubikey::{Certificate, YubiKey};

use rite_sdk::{
    AgreedSecret, BackendError, EcCurve, EcPoint, KeyAlgorithm, KeyId, KeyMetadata, PivDeviceInfo,
    PivKeyOrigin, PivPinPolicy, PivSlot, PivSlotInfo, PivTouchPolicy, PublicKeyDer, SignAlgorithm,
    YubikeySlotMetadata,
};

use crate::convert;

// ============================================================================
// Error mapping
// ============================================================================

/// Map a `yubikey::Error` to a `BackendError`.
pub fn map_error(e: yubikey::Error) -> BackendError {
    use yubikey::Error;
    match e {
        Error::NotFound => BackendError::HardwareFailure("No PIV device found".to_string()),
        Error::AuthenticationError => BackendError::PinRequired,
        Error::WrongPin { tries } => BackendError::PinFailed(u32::from(tries)),
        Error::PinLocked => BackendError::PinBlocked,
        Error::NotSupported => {
            BackendError::UnsupportedOperation("operation not supported by device".to_string())
        }
        Error::AlgorithmError => {
            BackendError::UnsupportedAlgorithm("algorithm not supported by device".to_string())
        }
        other => BackendError::HardwareFailure(other.to_string()),
    }
}

// ============================================================================
// Slot / KeyId helpers
// ============================================================================

/// Parse a PIV slot from a string hint.
///
/// Accepts the standard slot identifiers (`"9a"`, `"9c"`, `"9d"`, `"9e"`), the
/// retired key-management slots by their hex key reference (`"82"`..`"95"`), or
/// any of these with a `"piv:"` prefix (`"piv:9a"`, `"piv:82"`).
///
/// Returns a Rite [`PivSlot`]; callers that need the vendor `SlotId` should
/// chain [`convert::to_yubikey_slot`].
///
/// # Errors
///
/// Returns `BackendError::Configuration` for an unrecognized slot string.
pub fn slot_from_hint(hint: &str) -> Result<PivSlot, BackendError> {
    let s = hint.strip_prefix("piv:").unwrap_or(hint);
    match s {
        "9a" => Ok(PivSlot::Authentication),
        "9c" => Ok(PivSlot::Signature),
        "9d" => Ok(PivSlot::KeyManagement),
        "9e" => Ok(PivSlot::CardAuthentication),
        other => {
            // Retired key-management slots are addressed by their NIST key
            // reference (0x82..=0x95). Rite stores them as a 0-based index.
            // Two hex digits, as the reference is written: `from_str_radix`
            // alone also reads `082` and `+82`.
            let unknown = || BackendError::Configuration(format!("Unknown PIV slot: {hint}"));
            if other.len() != 2 || !other.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(unknown());
            }
            let key_ref = u8::from_str_radix(other, 16).map_err(|_| unknown())?;
            if (convert::RETIRED_KEY_REF_MIN..=convert::RETIRED_KEY_REF_MAX).contains(&key_ref) {
                Ok(PivSlot::Retired(
                    key_ref.saturating_sub(convert::RETIRED_KEY_REF_MIN),
                ))
            } else {
                Err(unknown())
            }
        }
    }
}

/// Parse a PIV slot from a `KeyId`.
///
/// # Errors
///
/// Returns `BackendError::Configuration` for an unrecognized slot string.
pub fn slot_from_key_id(key_id: &KeyId) -> Result<PivSlot, BackendError> {
    slot_from_hint(key_id.as_str())
}

/// Convert a `yubikey::piv::SlotId` to a Rite `KeyId`.
// `SlotId` is a vendor #[non_exhaustive] enum; everything outside the four
// standard PIV slots, the retired range, and F9 is deliberately bucketed as
// unknown, so a single wildcard arm is intentional here.
#[allow(clippy::match_wildcard_for_single_variants)]
pub fn key_id_for_slot(slot: SlotId) -> KeyId {
    match slot {
        SlotId::Authentication => KeyId::new("piv:9a"),
        SlotId::Signature => KeyId::new("piv:9c"),
        SlotId::KeyManagement => KeyId::new("piv:9d"),
        SlotId::CardAuthentication => KeyId::new("piv:9e"),
        SlotId::Retired(r) => KeyId::new(format!("piv:{:02x}", u8::from(r))),
        SlotId::Attestation => KeyId::new("piv:f9"),
        _ => KeyId::new("piv:unknown"),
    }
}

/// Build the canonical `KeyId` for a Rite [`PivSlot`] (e.g. `piv:9c`).
///
/// This is the inverse of [`slot_from_key_id`] and the single way to turn a
/// slot into a key reference; callers must not assemble the `piv:` prefix by
/// hand, or a slot hint that already carries the prefix gets doubled.
///
/// # Errors
///
/// Returns `BackendError::Configuration` when a `Retired` slot index is
/// outside the valid `0..=19` range.
pub fn key_id_for_piv_slot(slot: PivSlot) -> Result<KeyId, BackendError> {
    Ok(key_id_for_slot(convert::to_yubikey_slot(slot)?))
}

// ============================================================================
// Device operations
// ============================================================================

/// Get device identity information from a connected card.
///
/// Only accesses cached values (serial, version); no device I/O required.
pub fn device_info(yk: &YubiKey) -> PivDeviceInfo {
    PivDeviceInfo {
        serial: Some(yk.serial().to_string()),
        firmware_version: Some(yk.version().to_string()),
        form_factor: None,
    }
}

/// Get the number of remaining PIN retries.
///
/// # Errors
///
/// Returns a `BackendError` if the device query fails.
pub fn pin_retries(yk: &mut YubiKey) -> Result<u32, BackendError> {
    yk.get_pin_retries().map(u32::from).map_err(map_error)
}

/// Authenticate with the management key.
///
/// # Errors
///
/// Returns a `BackendError` if the key is malformed or authentication fails.
pub fn authenticate_management(yk: &mut YubiKey, mgm_key: &[u8]) -> Result<(), BackendError> {
    let key = yubikey::MgmKey::from_bytes(mgm_key).map_err(map_error)?;
    yk.authenticate(key).map_err(map_error)
}

// ============================================================================
// Slot and certificate operations
// ============================================================================

/// List all populated PIV slots with metadata.
///
/// # Errors
///
/// Returns a `BackendError` if slot enumeration fails.
pub fn list_slots(yk: &mut YubiKey) -> Result<Vec<PivSlotInfo>, BackendError> {
    let keys = piv::Key::list(yk).map_err(map_error)?;
    let mut result = Vec::new();
    for key in keys {
        let slot_id = key.slot();
        let rite_slot = convert::from_yubikey_slot(slot_id);
        let (algorithm, origin) = match piv::metadata(yk, slot_id) {
            Ok(meta) => {
                let algo = match meta.algorithm {
                    piv::ManagementAlgorithmId::Asymmetric(a) => convert::from_yubikey_algorithm(a),
                    _ => None,
                };
                let origin = meta
                    .origin
                    .map_or(PivKeyOrigin::Unknown, convert::from_yubikey_origin);
                (algo, origin)
            }
            Err(_) => (None, PivKeyOrigin::Unknown),
        };
        result.push(PivSlotInfo {
            slot: rite_slot,
            algorithm,
            has_certificate: true,
            origin,
        });
    }
    Ok(result)
}

/// Read the DER-encoded X.509 certificate from a PIV slot.
///
/// # Errors
///
/// Returns a `BackendError` if the slot is invalid or the read fails.
pub fn read_certificate(yk: &mut YubiKey, slot: PivSlot) -> Result<Vec<u8>, BackendError> {
    let slot_id = convert::to_yubikey_slot(slot)?;
    let cert = Certificate::read(yk, slot_id).map_err(map_error)?;
    cert.cert
        .to_der()
        .map_err(|e| BackendError::Other(e.to_string()))
}

/// Write a DER-encoded X.509 certificate to a PIV slot.
///
/// # Errors
///
/// Returns a `BackendError` if the slot is invalid, the certificate is
/// malformed, or the write fails.
pub fn write_certificate(
    yk: &mut YubiKey,
    slot: PivSlot,
    cert_der: &[u8],
) -> Result<(), BackendError> {
    let slot_id = convert::to_yubikey_slot(slot)?;
    let cert = Certificate::from_bytes(cert_der.to_vec()).map_err(map_error)?;
    cert.write(yk, slot_id, CertInfo::Uncompressed)
        .map_err(map_error)
}

// ============================================================================
// Key management operations
// ============================================================================

/// Generate a new asymmetric key pair on the device.
///
/// Stores the key in the PIV slot indicated by `slot_hint` (e.g. `"9c"` or
/// `"piv:9c"`). Defaults to the Authentication slot (9A) when no hint is given.
///
/// # Errors
///
/// Returns a `BackendError` if the algorithm or slot is unsupported, or if
/// generation fails on the device.
pub fn generate_key(
    yk: &mut YubiKey,
    algorithm: KeyAlgorithm,
    label: &str,
    slot_hint: Option<&str>,
) -> Result<KeyMetadata, BackendError> {
    let yk_algo = convert::to_yubikey_algorithm(algorithm).ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!("{algorithm} is not supported by PIV"))
    })?;
    let piv_slot = slot_hint
        .map(slot_from_hint)
        .transpose()?
        .unwrap_or(PivSlot::Authentication);
    let slot = convert::to_yubikey_slot(piv_slot)?;
    let spki = piv::generate(
        yk,
        slot,
        yk_algo,
        yubikey::PinPolicy::Default,
        yubikey::TouchPolicy::Default,
    )
    .map_err(map_error)?;
    let key_id = key_id_for_slot(slot);
    Ok(KeyMetadata {
        key_id,
        algorithm,
        label: label.to_string(),
        public_key: Some(encode_public_key(&spki)?),
        check_value: None,
        attestation: None,
    })
}

/// Export the public key from a slot.
///
/// # Errors
///
/// Returns a `BackendError` if the slot is invalid or empty.
pub fn export_public_key(yk: &mut YubiKey, key_id: &KeyId) -> Result<PublicKeyDer, BackendError> {
    let slot = convert::to_yubikey_slot(slot_from_key_id(key_id)?)?;
    let meta = piv::metadata(yk, slot).map_err(map_error)?;
    let spki = meta
        .public
        .ok_or_else(|| BackendError::SlotEmpty(key_id.to_string()))?;
    encode_public_key(&spki)
}

/// Encode a card-reported `SubjectPublicKeyInfo` as a typed public key.
///
/// Every caller passes `x509_cert::spki::SubjectPublicKeyInfoOwned`, but from
/// the `yubikey` crate's `der` 0.7 rather than the `der` 0.8 that `rite-sdk`
/// parses with. Naming the type would mean depending on both majors at once,
/// so the bound is on `der::Encode` (0.7, per this crate's `Cargo.toml`) and
/// only the DER bytes cross the boundary.
fn encode_public_key<T: Encode>(spki: &T) -> Result<PublicKeyDer, BackendError> {
    let der = spki
        .to_der()
        .map_err(|e| BackendError::Other(e.to_string()))?;
    PublicKeyDer::new(der)
}

/// List all keys (slots with certificates) on the device.
///
/// # Errors
///
/// Returns a `BackendError` if slot enumeration fails.
pub fn list_keys(yk: &mut YubiKey) -> Result<Vec<KeyMetadata>, BackendError> {
    let keys = piv::Key::list(yk).map_err(map_error)?;
    let mut result = Vec::new();
    for key in keys {
        let slot_id = key.slot();
        let key_id = key_id_for_slot(slot_id);
        let (algorithm, public_key) = match piv::metadata(yk, slot_id) {
            Ok(meta) => {
                let algo = match meta.algorithm {
                    piv::ManagementAlgorithmId::Asymmetric(a) => convert::from_yubikey_algorithm(a),
                    _ => None,
                };
                // Enumeration reports every slot it can reach, so a slot whose
                // key will not encode is listed without one rather than failing
                // the whole listing.
                let pk = meta.public.and_then(|spki| encode_public_key(&spki).ok());
                (algo, pk)
            }
            Err(_) => (None, None),
        };
        if let Some(algorithm) = algorithm {
            result.push(KeyMetadata {
                key_id,
                algorithm,
                label: String::new(),
                public_key,
                check_value: None,
                attestation: None,
            });
        }
    }
    Ok(result)
}

// ============================================================================
// Signing
// ============================================================================

/// RSA-2048 modulus length in bytes.
///
/// RSA-2048 is the only RSA size Rite supports on PIV cards (see
/// [`convert::to_yubikey_algorithm`]), so the PKCS#1 encoding below can fix
/// the block length instead of querying the slot.
const RSA_2048_LEN: usize = 256;

/// DER encoding of the PKCS#1 `DigestInfo` header for SHA-256
/// (RFC 8017, §9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Offset one past the `0xff` padding string PS: the leading `0x00 0x01` plus
/// PS itself. PS fills whatever the fixed-size trailer (`0x00` separator,
/// `DigestInfo` header, 32-byte digest) leaves of the modulus length.
const EMSA_PS_END: usize = RSA_2048_LEN - SHA256_DIGEST_INFO_PREFIX.len() - 32 - 1;

/// EMSA-PKCS1-v1_5 encoding of a SHA-256 digest for an RSA-2048 key
/// (RFC 8017, §9.2): `0x00 0x01 PS 0x00 DigestInfo`, padded to the modulus
/// length.
///
/// The card performs a raw RSA private-key operation on its input, so the
/// caller must supply the full padded block; sending the bare digest produces
/// a card error or an invalid signature.
fn emsa_pkcs1_v1_5_sha256(digest: [u8; 32]) -> Vec<u8> {
    let mut em = Vec::with_capacity(RSA_2048_LEN);
    em.push(0x00);
    em.push(0x01);
    em.resize(EMSA_PS_END, 0xff);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    em.extend_from_slice(&digest);
    em
}

/// Sign data using an on-device private key.
///
/// Encodes the message per algorithm before it reaches the card: ECDSA takes
/// the bare digest, while RSA takes the full EMSA-PKCS1-v1_5 block, because
/// the card applies a raw RSA private-key operation to whatever it receives.
///
/// # Errors
///
/// Returns a `BackendError` if the algorithm is unsupported or signing fails.
pub fn sign(
    yk: &mut YubiKey,
    key_id: &KeyId,
    message: &[u8],
    algorithm: SignAlgorithm,
) -> Result<Vec<u8>, BackendError> {
    let slot = convert::to_yubikey_slot(slot_from_key_id(key_id)?)?;

    let input = match algorithm {
        SignAlgorithm::EcdsaSha256 => Sha256::digest(message).to_vec(),
        SignAlgorithm::EcdsaSha384 => Sha384::digest(message).to_vec(),
        SignAlgorithm::RsaPkcs1Sha256 => emsa_pkcs1_v1_5_sha256(Sha256::digest(message).into()),
        SignAlgorithm::RsaPssSha256 => {
            return Err(BackendError::UnsupportedAlgorithm(
                "RSA-PSS requires client-side encoding that is not implemented; \
                 use RSA-PKCS1-SHA256"
                    .to_string(),
            ));
        }
        SignAlgorithm::Ed25519 => {
            return Err(BackendError::UnsupportedAlgorithm(
                "Ed25519 is not supported by PIV cards".to_string(),
            ));
        }
        // `SignAlgorithm` is #[non_exhaustive]; reject anything PIV cannot do.
        _ => {
            return Err(BackendError::UnsupportedAlgorithm(format!(
                "{algorithm} is not supported by PIV cards"
            )));
        }
    };
    // The card algorithm comes from the shared SignAlgorithm -> KeyAlgorithm
    // pairing so this table cannot drift from the SDK or the mock backend.
    let yk_algo = convert::to_yubikey_algorithm(algorithm.key_algorithm()).ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!("{algorithm} is not supported by PIV cards"))
    })?;
    let sig = piv::sign_data(yk, &input, yk_algo, slot).map_err(map_error)?;
    Ok(sig.to_vec())
}

// ============================================================================
// Key agreement
// ============================================================================

/// Run ECDH between the private key in a slot and `peer`, and return the
/// agreed secret Z.
///
/// The card computes Z through GENERAL AUTHENTICATE with the peer's point
/// under tag `0x85` (SP 800-73-5 Part 2, §3.2.4). The PIN must have been
/// verified in this session if the slot's policy asks for it, and the card
/// waits for a touch if its touch policy does.
///
/// Only the key-management slots agree: 9D and the retired slots `82`..`95`,
/// which hold its earlier keys. A PIV key carries no usage attribute, so the
/// slot is its usage, and this refuses the others rather than have the card
/// run an ECDH it would also run on a signing key. 9E is the case that
/// matters most: it has no PIN.
///
/// Performs ECDH with the key in a PIV slot and returns the shared secret.
///
/// The peer's curve selects the algorithm sent to the card. Reading the slot's
/// curve first would require GET METADATA, a Yubico extension; the card
/// refuses an algorithm that does not match its key, so a mismatch computes
/// nothing. The peer point is checked before it reaches the card. The card
/// applies the slot's PIN and touch policies.
///
/// # Errors
///
/// - [`BackendError::OperationNotPermitted`] if the slot is not a
///   key-management slot;
/// - [`BackendError::InvalidData`] if the peer point is invalid or uses a
///   different curve from the slot key;
/// - [`BackendError::UnsupportedAlgorithm`] if the slot key is not EC;
/// - [`BackendError::SlotEmpty`] if the slot is empty;
/// - [`BackendError::PinRequired`] if the PIN has not been verified;
/// - [`BackendError::HardwareFailure`] if the card refuses and the reason
///   cannot be determined;
/// - [`BackendError::Other`] if the returned secret has an unexpected length.
pub fn agree(
    yk: &mut YubiKey,
    key_id: &KeyId,
    peer: &PublicKeyDer,
) -> Result<AgreedSecret, BackendError> {
    let piv_slot = slot_from_key_id(key_id)?;
    permits_agreement(piv_slot, key_id)?;
    let slot = convert::to_yubikey_slot(piv_slot)?;
    let point = peer_point(peer)?;
    let curve = point.curve();
    let card_algorithm = convert::to_yubikey_algorithm(curve.key_algorithm()).ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!("PIV defines no key agreement on {curve}"))
    })?;

    match piv::decrypt_data(yk, point.sec1_uncompressed(), card_algorithm, slot) {
        Ok(z) => agreed_secret(z, curve),
        Err(yubikey::Error::GenericError) => {
            let held = match piv::metadata(yk, slot) {
                Ok(meta) => match meta.algorithm {
                    piv::ManagementAlgorithmId::Asymmetric(a) => {
                        SlotKey::Held(convert::from_yubikey_algorithm(a))
                    }
                    _ => SlotKey::Held(None),
                },
                Err(yubikey::Error::GenericError) => SlotKey::Empty,
                Err(_) => SlotKey::Unknown,
            };
            Err(refusal(held, key_id, curve))
        }
        Err(other) => Err(map_error(other)),
    }
}

/// Returns an error unless `slot` is a key-management slot.
fn permits_agreement(slot: PivSlot, key_id: &KeyId) -> Result<(), BackendError> {
    let purpose = match slot {
        PivSlot::KeyManagement | PivSlot::Retired(_) => return Ok(()),
        PivSlot::Authentication => "the authentication slot",
        PivSlot::Signature => "the signature slot",
        PivSlot::CardAuthentication => "the card authentication slot, which needs no PIN",
    };
    Err(BackendError::OperationNotPermitted(format!(
        "{key_id} is {purpose}; key agreement is permitted only in slot 9d or retired \
         key-management slots 82 to 95"
    )))
}

/// Parses the peer's EC point and checks that it lies on its curve.
///
/// P-256 and P-384 have cofactor 1, so an on-curve point belongs to the
/// intended group.
fn peer_point(peer: &PublicKeyDer) -> Result<EcPoint, BackendError> {
    let point = peer.ec_point().map_err(|e| {
        BackendError::InvalidData(format!(
            "the peer key cannot be used for key agreement: {e}"
        ))
    })?;
    let bytes = point.sec1_uncompressed();
    let on_curve = match point.curve() {
        EcCurve::P256 => p256::PublicKey::from_sec1_bytes(bytes).is_ok(),
        EcCurve::P384 => p384::PublicKey::from_sec1_bytes(bytes).is_ok(),
        // `EcCurve` is #[non_exhaustive]; a curve PIV does not define has no
        // check here, and no slot holds a key on it.
        other => {
            return Err(BackendError::InvalidData(format!(
                "the peer key uses {other}; PIV key agreement supports only P-256 and P-384"
            )));
        }
    };
    if !on_curve {
        return Err(BackendError::InvalidData(format!(
            "the peer key's point is not on {}",
            point.curve()
        )));
    }
    Ok(point)
}

/// Result of asking the card for the key in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotKey {
    /// The card reports a key, with its algorithm when known.
    Held(Option<KeyAlgorithm>),
    /// The card reports that the slot is empty.
    Empty,
    /// The card cannot report the slot contents.
    Unknown,
}

/// Maps a card refusal to an error using the slot contents, when known.
fn refusal(held: SlotKey, key_id: &KeyId, peer_curve: EcCurve) -> BackendError {
    match held {
        SlotKey::Held(Some(algorithm)) => match EcCurve::of(algorithm) {
            Some(slot_curve) if slot_curve == peer_curve => BackendError::HardwareFailure(format!(
                "the card refused key agreement in slot {key_id}, which holds a {slot_curve} key"
            )),
            Some(slot_curve) => BackendError::InvalidData(format!(
                "the peer key uses {peer_curve}, but slot {key_id} holds a {slot_curve} key"
            )),
            None => BackendError::UnsupportedAlgorithm(format!(
                "slot {key_id} holds {algorithm}; key agreement requires an EC key"
            )),
        },
        SlotKey::Held(None) => BackendError::UnsupportedAlgorithm(format!(
            "slot {key_id} holds a key with an unsupported algorithm"
        )),
        SlotKey::Empty => BackendError::SlotEmpty(key_id.to_string()),
        SlotKey::Unknown => BackendError::HardwareFailure(format!(
            "the card refused key agreement in slot {key_id}; it cannot report whether the \
             slot is empty or holds a key on another curve"
        )),
    }
}

/// Returns the shared secret if its length matches the curve's field length.
fn agreed_secret(z: yubikey::Buffer, curve: EcCurve) -> Result<AgreedSecret, BackendError> {
    if z.len() != curve.field_len() {
        return Err(BackendError::Other(format!(
            "the card returned a {}-byte shared secret; {curve} requires {} bytes",
            z.len(),
            curve.field_len()
        )));
    }
    Ok(AgreedSecret::new(z))
}

// ============================================================================
// YubiKey-specific operations
// ============================================================================

/// Read YubiKey-specific slot metadata (touch policy, PIN policy, key origin).
///
/// Requires firmware 5.2.3 or later.
///
/// # Errors
///
/// Returns a `BackendError` on older firmware or if the metadata read fails.
pub fn yubikey_slot_metadata(
    yk: &mut YubiKey,
    slot: PivSlot,
) -> Result<YubikeySlotMetadata, BackendError> {
    let slot_id = convert::to_yubikey_slot(slot)?;
    let meta = piv::metadata(yk, slot_id).map_err(map_error)?;
    let (pin_policy, touch_policy) = meta.policy.map_or(
        (PivPinPolicy::Default, PivTouchPolicy::Default),
        |(pin, touch)| {
            (
                convert::from_yubikey_pin_policy(pin),
                convert::from_yubikey_touch_policy(touch),
            )
        },
    );
    let origin = meta
        .origin
        .map_or(PivKeyOrigin::Unknown, convert::from_yubikey_origin);
    let public_key = meta.public.and_then(|spki| encode_public_key(&spki).ok());
    Ok(YubikeySlotMetadata {
        pin_policy,
        touch_policy,
        origin,
        public_key,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::BackendError;

    // --- slot_from_hint ---

    #[test]
    fn slot_from_hint_bare_identifiers() {
        assert_eq!(slot_from_hint("9a").unwrap(), PivSlot::Authentication);
        assert_eq!(slot_from_hint("9c").unwrap(), PivSlot::Signature);
        assert_eq!(slot_from_hint("9d").unwrap(), PivSlot::KeyManagement);
        assert_eq!(slot_from_hint("9e").unwrap(), PivSlot::CardAuthentication);
    }

    #[test]
    fn slot_from_hint_piv_prefixed() {
        assert_eq!(slot_from_hint("piv:9a").unwrap(), PivSlot::Authentication);
        assert_eq!(slot_from_hint("piv:9c").unwrap(), PivSlot::Signature);
        assert_eq!(slot_from_hint("piv:9d").unwrap(), PivSlot::KeyManagement);
        assert_eq!(
            slot_from_hint("piv:9e").unwrap(),
            PivSlot::CardAuthentication
        );
    }

    #[test]
    fn slot_from_hint_retired_slots() {
        // 0x82 is retired index 0, 0x95 is retired index 19.
        assert_eq!(slot_from_hint("82").unwrap(), PivSlot::Retired(0));
        assert_eq!(slot_from_hint("95").unwrap(), PivSlot::Retired(19));
        assert_eq!(slot_from_hint("piv:82").unwrap(), PivSlot::Retired(0));
        assert_eq!(slot_from_hint("piv:8a").unwrap(), PivSlot::Retired(8));
    }

    #[test]
    fn slot_from_hint_unknown_returns_configuration_error() {
        // 0x9b is outside both the standard and retired ranges.
        assert!(matches!(
            slot_from_hint("9b").unwrap_err(),
            BackendError::Configuration(_)
        ));
        assert!(matches!(
            slot_from_hint("piv:ff").unwrap_err(),
            BackendError::Configuration(_)
        ));
        assert!(matches!(
            slot_from_hint("invalid").unwrap_err(),
            BackendError::Configuration(_)
        ));
    }

    // --- slot_from_key_id ---

    #[test]
    fn slot_from_key_id_parses_prefixed_and_bare() {
        assert_eq!(
            slot_from_key_id(&KeyId::new("piv:9a")).unwrap(),
            PivSlot::Authentication
        );
        assert_eq!(
            slot_from_key_id(&KeyId::new("9c")).unwrap(),
            PivSlot::Signature
        );
    }

    #[test]
    fn slot_from_key_id_unknown_returns_error() {
        assert!(matches!(
            slot_from_key_id(&KeyId::new("piv:xx")).unwrap_err(),
            BackendError::Configuration(_)
        ));
    }

    // --- key_id_for_slot ---

    #[test]
    fn key_id_for_slot_standard_slots() {
        assert_eq!(
            key_id_for_slot(SlotId::Authentication),
            KeyId::new("piv:9a")
        );
        assert_eq!(key_id_for_slot(SlotId::Signature), KeyId::new("piv:9c"));
        assert_eq!(key_id_for_slot(SlotId::KeyManagement), KeyId::new("piv:9d"));
        assert_eq!(
            key_id_for_slot(SlotId::CardAuthentication),
            KeyId::new("piv:9e")
        );
        assert_eq!(key_id_for_slot(SlotId::Attestation), KeyId::new("piv:f9"));
    }

    // --- key_id_for_piv_slot ---

    #[test]
    fn key_id_for_piv_slot_is_canonical_and_never_double_prefixed() {
        assert_eq!(
            key_id_for_piv_slot(PivSlot::Signature).unwrap(),
            KeyId::new("piv:9c")
        );
        assert_eq!(
            key_id_for_piv_slot(PivSlot::Retired(0)).unwrap(),
            KeyId::new("piv:82")
        );
        // A hint that already carries the prefix parses to the same slot and
        // therefore the same canonical key id.
        let slot = slot_from_hint("piv:9c").unwrap();
        assert_eq!(key_id_for_piv_slot(slot).unwrap(), KeyId::new("piv:9c"));
    }

    #[test]
    fn key_id_for_piv_slot_rejects_out_of_range_retired_index() {
        assert!(matches!(
            key_id_for_piv_slot(PivSlot::Retired(20)).unwrap_err(),
            BackendError::Configuration(_)
        ));
    }

    // --- emsa_pkcs1_v1_5_sha256 ---

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Static test vector for the digest-then-pad pipeline exactly as
    /// [`sign`] runs it. The expected block is a hardcoded literal, so the
    /// assertion fails if any part of the encoding drifts; its tail is the
    /// SHA-256("abc") digest published in FIPS 180-2, Appendix B.1, which
    /// also pins the digest computation.
    ///
    /// Expected block: RFC 8017, §9.2 (SHA-256 `DigestInfo` from Note 1),
    /// cross-checked byte-for-byte against OpenSSL 3.x by recovering the
    /// encoded message from a PKCS#1 v1.5 signature with
    /// `openssl pkeyutl -verifyrecover -pkeyopt rsa_padding_mode:none`.
    #[test]
    fn emsa_pkcs1_v1_5_sha256_matches_the_published_vector() {
        const EXPECTED_EM: &str = concat!(
            "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffff003031300d060960864801650304020105000420",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );

        let em = emsa_pkcs1_v1_5_sha256(Sha256::digest(b"abc").into());
        assert_eq!(to_hex(&em), EXPECTED_EM);
    }

    #[test]
    fn emsa_pkcs1_v1_5_sha256_produces_the_rfc8017_block() {
        let digest: [u8; 32] = sha2::Sha256::digest(b"release manifest").into();
        let em = emsa_pkcs1_v1_5_sha256(digest);

        // Modulus-length block: 0x00 0x01 PS(0xff..) 0x00 DigestInfo digest.
        let mut expected = vec![0x00, 0x01];
        expected.resize(EMSA_PS_END, 0xff);
        expected.push(0x00);
        expected.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
        expected.extend_from_slice(&digest);
        assert_eq!(expected.len(), RSA_2048_LEN);
        assert_eq!(em, expected);
    }

    #[test]
    fn key_id_for_slot_roundtrips_through_slot_from_hint() {
        for slot in [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
        ] {
            let key_id = key_id_for_slot(slot);
            let piv_slot = slot_from_key_id(&key_id).unwrap();
            assert_eq!(convert::to_yubikey_slot(piv_slot).unwrap(), slot);
        }
    }

    // --- key agreement ---

    /// The SPKI vectors `rite-sdk` tests with, copied so this crate packages
    /// on its own.
    mod vectors {
        pub const P256: &[u8] = include_bytes!("../tests/vectors/p256.spki.der");
        pub const P384: &[u8] = include_bytes!("../tests/vectors/p384.spki.der");
        pub const RSA_2048: &[u8] = include_bytes!("../tests/vectors/rsa2048.spki.der");
    }

    fn key(der: &[u8]) -> PublicKeyDer {
        PublicKeyDer::new(der.to_vec()).unwrap()
    }

    #[test]
    fn agreement_runs_in_the_key_management_slots() {
        for slot in [
            PivSlot::KeyManagement,
            PivSlot::Retired(0),
            PivSlot::Retired(19),
        ] {
            let key_id = key_id_for_piv_slot(slot).unwrap();
            assert!(permits_agreement(slot, &key_id).is_ok(), "{key_id}");
        }
    }

    #[test]
    fn agreement_is_refused_in_the_other_slots_by_name() {
        for (slot, named) in [
            (PivSlot::Authentication, "authentication slot"),
            (PivSlot::Signature, "signature slot"),
            (PivSlot::CardAuthentication, "needs no PIN"),
        ] {
            let key_id = key_id_for_piv_slot(slot).unwrap();
            let error = permits_agreement(slot, &key_id).unwrap_err();
            assert!(
                matches!(&error, BackendError::OperationNotPermitted(m)
                    if m.contains(named) && m.contains(key_id.as_str())),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_peer_on_its_curve_is_passed_to_the_card_as_its_point() {
        for (der, curve) in [
            (vectors::P256, EcCurve::P256),
            (vectors::P384, EcCurve::P384),
        ] {
            let point = peer_point(&key(der)).unwrap();
            assert_eq!(point.curve(), curve);
            assert_eq!(point.sec1_uncompressed().len(), curve.point_len());
        }
    }

    /// The vector with the last byte of y flipped: still a well-formed SPKI
    /// with an uncompressed point of the right length, so only the curve
    /// equation refuses it. The SPKI ends with the point, so the last byte of
    /// the DER is the last byte of y.
    fn off_curve(der: &[u8]) -> PublicKeyDer {
        let mut bytes = der.to_vec();
        if let Some(last) = bytes.last_mut() {
            *last ^= 0x01;
        }
        PublicKeyDer::new(bytes).unwrap()
    }

    #[test]
    fn a_peer_off_its_curve_is_refused_before_the_card() {
        for (der, curve) in [
            (vectors::P256, EcCurve::P256),
            (vectors::P384, EcCurve::P384),
        ] {
            let peer = off_curve(der);
            assert_eq!(peer.ec_point().unwrap().curve(), curve);
            let error = peer_point(&peer).unwrap_err();
            assert!(
                matches!(&error, BackendError::InvalidData(m) if m.contains("not on")),
                "{curve}: {error:?}"
            );
        }
    }

    #[test]
    fn a_peer_that_is_not_ec_is_refused_with_the_cause() {
        let error = peer_point(&key(vectors::RSA_2048)).unwrap_err();
        assert!(
            matches!(&error, BackendError::InvalidData(m) if m.contains("not an EC key")),
            "{error:?}"
        );
    }

    #[test]
    fn a_refusal_names_the_curve_mismatch() {
        let key_id = KeyId::new("piv:9d");
        let held = SlotKey::Held(Some(KeyAlgorithm::EcdsaP384));
        let error = refusal(held, &key_id, EcCurve::P256);
        assert!(
            matches!(&error, BackendError::InvalidData(m)
                if m.contains("P-256") && m.contains("P-384") && m.contains("but slot")),
            "{error:?}"
        );
    }

    #[test]
    fn a_refusal_names_a_slot_that_is_not_ec() {
        let key_id = KeyId::new("piv:9d");
        for held in [
            SlotKey::Held(Some(KeyAlgorithm::Rsa2048)),
            SlotKey::Held(None),
        ] {
            let error = refusal(held, &key_id, EcCurve::P256);
            assert!(
                matches!(error, BackendError::UnsupportedAlgorithm(_)),
                "{held:?}: {error:?}"
            );
        }
    }

    #[test]
    fn a_refusal_names_an_empty_slot() {
        let key_id = KeyId::new("piv:9d");
        let error = refusal(SlotKey::Empty, &key_id, EcCurve::P256);
        assert!(
            matches!(&error, BackendError::SlotEmpty(slot) if slot == "piv:9d"),
            "{error:?}"
        );
    }

    #[test]
    fn a_refusal_the_card_cannot_explain_says_so() {
        let key_id = KeyId::new("piv:9d");
        for held in [
            SlotKey::Unknown,
            SlotKey::Held(Some(KeyAlgorithm::EcdsaP256)),
        ] {
            let error = refusal(held, &key_id, EcCurve::P256);
            assert!(
                matches!(&error, BackendError::HardwareFailure(m) if m.contains("refused")),
                "{held:?}: {error:?}"
            );
        }
    }

    #[test]
    fn the_secret_is_a_whole_field_element() {
        // A leading zero is part of Z and is kept.
        let mut z = vec![0u8; 31];
        z.push(0x01);
        let secret = agreed_secret(yubikey::Buffer::new(z.clone()), EcCurve::P256).unwrap();
        assert_eq!(secret.kdf_input(), z.as_slice());

        for wrong in [31, 33, 48] {
            let error =
                agreed_secret(yubikey::Buffer::new(vec![0x01; wrong]), EcCurve::P256).unwrap_err();
            assert!(
                matches!(error, BackendError::Other(_)),
                "{wrong}: {error:?}"
            );
        }
    }

    // --- map_error ---

    #[test]
    fn map_error_not_found_is_hardware_failure() {
        assert!(matches!(
            map_error(yubikey::Error::NotFound),
            BackendError::HardwareFailure(_)
        ));
    }

    #[test]
    fn map_error_authentication_error_is_pin_required() {
        assert!(matches!(
            map_error(yubikey::Error::AuthenticationError),
            BackendError::PinRequired
        ));
    }

    #[test]
    fn map_error_wrong_pin_carries_retry_count() {
        assert!(matches!(
            map_error(yubikey::Error::WrongPin { tries: 3 }),
            BackendError::PinFailed(3)
        ));
        assert!(matches!(
            map_error(yubikey::Error::WrongPin { tries: 0 }),
            BackendError::PinFailed(0)
        ));
    }

    #[test]
    fn map_error_pin_locked_is_pin_blocked() {
        assert!(matches!(
            map_error(yubikey::Error::PinLocked),
            BackendError::PinBlocked
        ));
    }

    #[test]
    fn map_error_not_supported_is_unsupported_operation() {
        assert!(matches!(
            map_error(yubikey::Error::NotSupported),
            BackendError::UnsupportedOperation(_)
        ));
    }

    #[test]
    fn map_error_algorithm_error_is_unsupported_algorithm() {
        assert!(matches!(
            map_error(yubikey::Error::AlgorithmError),
            BackendError::UnsupportedAlgorithm(_)
        ));
    }
}
