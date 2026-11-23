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
use zeroize::Zeroizing;

use rite_sdk::{
    AgreedSecret, BackendError, EcCurve, EcPoint, KeyAlgorithm, KeyId, KeyMetadata, KeyProtection,
    PivDeviceInfo, PivKeyOrigin, PivPinPolicy, PivSlot, PivSlotInfo, PivTouchPolicy, PublicKeyDer,
    SignAlgorithm, YubikeySlotMetadata,
};

use crate::{convert, oaep};

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
    PivSlot::from_hint(hint)
        .ok_or_else(|| BackendError::Configuration(format!("Unknown PIV slot: {hint}")))
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
/// Read from the PIN's metadata (firmware 5.3 and later), which leaves a
/// verified PIN as it is. A card that cannot answer that, whatever status
/// it gives, falls back to the `yubikey` crate's empty VERIFY. That call
/// re-selects the applet first: on firmware 5.7 the PIN stays verified and
/// is reported as 0 retries, and other cards may clear it. Call it before
/// the PIN is entered, not after.
///
/// # Errors
///
/// Returns `PinBlocked` when the metadata reports no tries left, and a
/// `BackendError` if the fallback query fails.
pub fn pin_retries(yk: &mut YubiKey) -> Result<u32, BackendError> {
    match piv::metadata(yk, SlotId::Management(piv::ManagementSlotId::Pin)) {
        Ok(piv::SlotMetadata {
            retries: Some(retries),
            ..
        }) if retries.remaining_count == 0 => return Err(BackendError::PinBlocked),
        Ok(piv::SlotMetadata {
            retries: Some(retries),
            ..
        }) => return Ok(u32::from(retries.remaining_count)),
        Ok(_) | Err(_) => {}
    }
    yk.get_pin_retries().map(u32::from).map_err(map_error)
}

/// Authenticate with the management key.
///
/// # Errors
///
/// Returns a `BackendError` if the key is malformed, and
/// `ManagementKeyRequired` if the card refuses it: [`map_error`] reads an
/// authentication failure as a missing PIN, which here it is not.
pub fn authenticate_management(yk: &mut YubiKey, mgm_key: &[u8]) -> Result<(), BackendError> {
    // `None` reads 24 bytes as a 3DES key. An AES-192 key, the default from
    // firmware 5.7, has the same length; telling them apart needs the card's
    // management-key algorithm, which this function does not read yet.
    let key = yubikey::MgmKey::from_bytes(mgm_key, None).map_err(map_error)?;
    yk.authenticate(&key).map_err(|error| match error {
        yubikey::Error::AuthenticationError => BackendError::ManagementKeyRequired,
        other => map_error(other),
    })
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
                    piv::SlotAlgorithmId::Asymmetric(a) => convert::from_yubikey_algorithm(a),
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
    runs_on_firmware(algorithm, yk.version())?;
    let piv_slot = slot_hint
        .map(slot_from_hint)
        .transpose()?
        .unwrap_or(PivSlot::GENERATE_DEFAULT);
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

/// Refuses an algorithm the card's firmware does not implement, so that the
/// error names the firmware rather than a card refusal.
///
/// RSA-4096 needs firmware 5.7 or later, as the card reports it through GET
/// VERSION. The others Rite uses are standard PIV, which every YubiKey with
/// PIV supports. Signing needs no check: it uses RSA-4096 only when the card
/// reported an RSA-4096 key in the slot.
fn runs_on_firmware(
    algorithm: KeyAlgorithm,
    firmware: yubikey::Version,
) -> Result<(), BackendError> {
    if algorithm == KeyAlgorithm::Rsa4096 && (firmware.major, firmware.minor) < (5, 7) {
        return Err(BackendError::UnsupportedAlgorithm(format!(
            "RSA-4096 on a YubiKey needs firmware 5.7 or later, and this card runs {firmware}"
        )));
    }
    Ok(())
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
                    piv::SlotAlgorithmId::Asymmetric(a) => convert::from_yubikey_algorithm(a),
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

/// An RSA key size Rite uses on a PIV card.
///
/// RSA-2048 is standard PIV (SP 800-78-5). RSA-4096 is a YubiKey extension,
/// from firmware 5.7. Rite refuses RSA-1024 as too weak, and has no
/// [`KeyAlgorithm`] for RSA-3072.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaSize {
    Rsa2048,
    Rsa4096,
}

impl RsaSize {
    const ALL: [Self; 2] = [Self::Rsa2048, Self::Rsa4096];

    /// The size of an RSA key algorithm, or `None` for any other algorithm.
    fn of(algorithm: KeyAlgorithm) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|size| size.key_algorithm() == algorithm)
    }

    /// The size whose modulus is `len` bytes. An RSA ciphertext is exactly
    /// the modulus length (RFC 8017, §7.1.1).
    fn from_modulus_len(len: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|size| size.modulus_len() == len)
    }

    /// The modulus length `k`, in bytes.
    const fn modulus_len(self) -> usize {
        match self {
            Self::Rsa2048 => 256,
            Self::Rsa4096 => 512,
        }
    }

    const fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::Rsa2048 => KeyAlgorithm::Rsa2048,
            Self::Rsa4096 => KeyAlgorithm::Rsa4096,
        }
    }
}

/// The card's name for `algorithm`, from the one table in [`convert`].
fn card_algorithm(algorithm: KeyAlgorithm) -> Result<piv::AlgorithmId, BackendError> {
    convert::to_yubikey_algorithm(algorithm).ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!("{algorithm} is not supported by PIV cards"))
    })
}

/// DER encoding of the PKCS#1 `DigestInfo` header for SHA-256
/// (RFC 8017, §9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// What follows the `0xff` padding string PS: the `0x00` separator, the
/// `DigestInfo` header and the 32-byte digest. PS fills the rest of the
/// modulus length after the leading `0x00 0x01`.
const EMSA_TRAILER_LEN: usize = 1 + SHA256_DIGEST_INFO_PREFIX.len() + 32;

/// EMSA-PKCS1-v1_5 encoding of a SHA-256 digest for an RSA key of `size`
/// (RFC 8017, §9.2): `0x00 0x01 PS 0x00 DigestInfo`, padded to the modulus
/// length.
///
/// The card performs a raw RSA private-key operation on its input, so the
/// caller must supply the full padded block; sending the bare digest produces
/// a card error or an invalid signature.
fn emsa_pkcs1_v1_5_sha256(digest: [u8; 32], size: RsaSize) -> Vec<u8> {
    let k = size.modulus_len();
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.resize(k.saturating_sub(EMSA_TRAILER_LEN), 0xff);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    em.extend_from_slice(&digest);
    em
}

/// The size of the RSA key a slot holds, as the card reported it through GET
/// METADATA, which the PKCS#1 block must match.
///
/// A card that cannot report is taken to hold RSA-2048: RSA-4096 is a YubiKey
/// extension, and a YubiKey that holds one (firmware 5.7 or later) answers GET
/// METADATA.
fn rsa_size_held(held: SlotKey, key_id: &KeyId) -> Result<RsaSize, BackendError> {
    match held {
        SlotKey::Held(Some(algorithm)) => RsaSize::of(algorithm).ok_or_else(|| {
            BackendError::UnsupportedAlgorithm(format!(
                "slot {key_id} holds {algorithm}; an RSA signature requires an RSA key"
            ))
        }),
        SlotKey::Held(None) => Err(BackendError::UnsupportedAlgorithm(format!(
            "slot {key_id} holds a key with an unsupported algorithm"
        ))),
        SlotKey::Empty => Err(BackendError::SlotEmpty(key_id.to_string())),
        SlotKey::Unknown => Ok(RsaSize::Rsa2048),
    }
}

/// Sign data using an on-device private key.
///
/// Encodes the message per algorithm before it reaches the card: ECDSA takes
/// the bare digest, while RSA takes the full EMSA-PKCS1-v1_5 block, because
/// the card applies a raw RSA private-key operation to whatever it receives.
///
/// An RSA block is the modulus length, so an RSA signature first reads the
/// slot's key size through GET METADATA (see [`rsa_size_held`]).
///
/// # Errors
///
/// - [`BackendError::UnsupportedAlgorithm`] if PIV cannot sign with
///   `algorithm`, or, for an RSA signature, if the slot holds a key that is
///   not RSA-2048 or RSA-4096;
/// - [`BackendError::SlotEmpty`] if the card reports the slot empty before an
///   RSA signature;
/// - the mapped card error if signing fails.
pub fn sign(
    yk: &mut YubiKey,
    key_id: &KeyId,
    message: &[u8],
    algorithm: SignAlgorithm,
) -> Result<Vec<u8>, BackendError> {
    let slot = convert::to_yubikey_slot(slot_from_key_id(key_id)?)?;

    // The key algorithm sent to the card: the slot's size for RSA, which a
    // signature algorithm does not name, and the SDK's pairing for ECDSA.
    let (input, key_algorithm) = match algorithm {
        SignAlgorithm::EcdsaSha256 => (Sha256::digest(message).to_vec(), algorithm.key_algorithm()),
        SignAlgorithm::EcdsaSha384 => (Sha384::digest(message).to_vec(), algorithm.key_algorithm()),
        SignAlgorithm::RsaPkcs1Sha256 => {
            let size = rsa_size_held(slot_key(yk, slot)?, key_id)?;
            let em = emsa_pkcs1_v1_5_sha256(Sha256::digest(message).into(), size);
            (em, size.key_algorithm())
        }
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
    let sig =
        piv::sign_data(yk, &input, card_algorithm(key_algorithm)?, slot).map_err(map_error)?;
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
    permits_key_management(piv_slot, key_id, "key agreement")?;
    let slot = convert::to_yubikey_slot(piv_slot)?;
    let point = peer_point(peer)?;
    let curve = point.curve();
    let card_algorithm = convert::to_yubikey_algorithm(curve.key_algorithm()).ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!("PIV defines no key agreement on {curve}"))
    })?;

    match piv::decrypt_data(yk, point.sec1_uncompressed(), card_algorithm, slot) {
        Ok(z) => agreed_secret(z, curve),
        Err(yubikey::Error::GenericError) => Err(refusal(slot_key(yk, slot)?, key_id, curve)),
        Err(other) => Err(map_error(other)),
    }
}

/// Returns an error unless `slot` is a key-management slot.
///
/// `operation` completes "... is permitted only in slot 9d".
fn permits_key_management(
    slot: PivSlot,
    key_id: &KeyId,
    operation: &str,
) -> Result<(), BackendError> {
    let purpose = match slot {
        PivSlot::KeyManagement | PivSlot::Retired(_) => return Ok(()),
        PivSlot::Authentication => "the authentication slot",
        PivSlot::Signature => "the signature slot",
        PivSlot::CardAuthentication => "the card authentication slot, which needs no PIN",
    };
    Err(BackendError::OperationNotPermitted(format!(
        "{key_id} is {purpose}; {operation} is permitted only in slot 9d or retired \
         key-management slots 82 to 95"
    )))
}

/// What the card reports holding in `slot`, through GET METADATA.
///
/// GET METADATA is a Yubico extension (firmware 5.2.3 and later). A card
/// without it answers [`SlotKey::Unknown`].
///
/// # Errors
///
/// Returns the mapped error if the card cannot be reached, as opposed to a
/// card that answers without the slot contents.
fn slot_key(yk: &mut YubiKey, slot: SlotId) -> Result<SlotKey, BackendError> {
    match piv::metadata(yk, slot) {
        Ok(meta) => Ok(match meta.algorithm {
            piv::SlotAlgorithmId::Asymmetric(a) => {
                SlotKey::Held(convert::from_yubikey_algorithm(a))
            }
            _ => SlotKey::Held(None),
        }),
        Err(error) => slot_key_unread(error),
    }
}

/// [`slot_key`] when the card does not return the metadata.
///
/// The `yubikey` crate maps an empty slot (`6A88`) to `NotFound`. A card
/// that cannot be reached is an error. Anything else leaves the slot
/// contents unknown: firmware before 5.2.3 (`NotSupported`), another status
/// word, which a card without the command may answer (`GenericError`), or a
/// reply the crate cannot parse, such as a public key it does not rebuild.
fn slot_key_unread(error: yubikey::Error) -> Result<SlotKey, BackendError> {
    match error {
        yubikey::Error::NotFound => Ok(SlotKey::Empty),
        unreachable @ (yubikey::Error::PcscError { .. }
        | yubikey::Error::AppletError
        | yubikey::Error::AppletNotFound { .. }) => Err(map_error(unreachable)),
        _ => Ok(SlotKey::Unknown),
    }
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
// Key decryption
// ============================================================================

/// Decrypt a key encrypted to the RSA key in a slot with RSAES-OAEP-SHA256,
/// and return it.
///
/// The card runs the raw RSA private-key operation through GENERAL
/// AUTHENTICATE, with the ciphertext under tag `0x81` (SP 800-73-5 Part 2,
/// §3.2.4). The host removes the OAEP encoding from the returned block with
/// `oaep::decode`. The PIN must have been verified in this session if the
/// slot's policy asks for it, and the card waits for a touch if its touch
/// policy does.
///
/// Only the key-management slots decrypt, for the reason [`agree`] gives.
/// The ciphertext length names the key size, RSA-2048 or RSA-4096: a
/// ciphertext is exactly the modulus length, and the card refuses a size
/// that does not match its key.
///
/// # Errors
///
/// - [`BackendError::UnsupportedAlgorithm`] for a protection other than
///   RSA-OAEP-SHA256, or if the slot key is not RSA;
/// - [`BackendError::OperationNotPermitted`] if the slot is not a
///   key-management slot;
/// - [`BackendError::InvalidData`] if the ciphertext is neither 256 nor 512
///   bytes, if it is for an RSA key of another size than the slot's, if the
///   card refuses it under a key of its size, or if the decrypted block is
///   not an OAEP encoding. The latter two have the same message;
/// - [`BackendError::Other`] if the card returns a block longer than the
///   modulus;
/// - [`BackendError::SlotEmpty`], [`BackendError::PinRequired`] and
///   [`BackendError::HardwareFailure`] as for [`agree`].
pub fn decrypt_key(
    yk: &mut YubiKey,
    key_id: &KeyId,
    encrypted: &[u8],
    protection: KeyProtection,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let (slot, size) = decryption_slot(key_id, encrypted, protection)?;
    runs_on_firmware(size.key_algorithm(), yk.version())?;

    let block = match piv::decrypt_data(yk, encrypted, card_algorithm(size.key_algorithm())?, slot)
    {
        Ok(block) => block,
        Err(yubikey::Error::GenericError) => {
            return Err(decryption_refusal(slot_key(yk, slot)?, key_id, size));
        }
        Err(other) => return Err(map_error(other)),
    };
    let block = full_length_block(&block, size)?;
    oaep::decode(&block).map_err(|oaep::DecodingError| does_not_decrypt(key_id))
}

/// The shared error for a card refusal under a key of the ciphertext's size
/// or an OAEP decoding failure.
fn does_not_decrypt(key_id: &KeyId) -> BackendError {
    BackendError::InvalidData(format!(
        "the ciphertext does not decrypt under the key in slot {key_id}"
    ))
}

/// The slot [`decrypt_key`] sends `encrypted` to and the key size its length
/// names, once the checks that need no card pass.
fn decryption_slot(
    key_id: &KeyId,
    encrypted: &[u8],
    protection: KeyProtection,
) -> Result<(SlotId, RsaSize), BackendError> {
    if protection != KeyProtection::RsaOaepSha256 {
        return Err(BackendError::UnsupportedAlgorithm(format!(
            "a PIV card decrypts a key protected with RSA-OAEP-SHA256, not {protection}"
        )));
    }
    let piv_slot = slot_from_key_id(key_id)?;
    permits_key_management(piv_slot, key_id, "key decryption")?;
    // The length is public: refused before the card sees it.
    let size = RsaSize::from_modulus_len(encrypted.len()).ok_or_else(|| {
        BackendError::InvalidData(format!(
            "a ciphertext under an RSA-2048 or RSA-4096 key is 256 or 512 bytes, and this \
             one is {}",
            encrypted.len()
        ))
    })?;
    Ok((convert::to_yubikey_slot(piv_slot)?, size))
}

/// The card's result at the full modulus length, the form OAEP decoding
/// reads (I2OSP, RFC 8017 §4.1).
///
/// A card may drop the block's leading zero byte. The length says only how
/// many leading zeros the block has, which a valid block fixes at one.
fn full_length_block(block: &[u8], size: RsaSize) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let k = size.modulus_len();
    let too_long = || {
        BackendError::Other(format!(
            "the card returned a {}-byte block; {} gives {k}",
            block.len(),
            size.key_algorithm()
        ))
    };
    let pad = k.checked_sub(block.len()).ok_or_else(too_long)?;
    let mut full = Zeroizing::new(vec![0u8; k]);
    full.get_mut(pad..)
        .ok_or_else(too_long)?
        .copy_from_slice(block);
    Ok(full)
}

/// Maps a card refusal to decrypt to an error using the slot contents, when
/// known.
///
/// A missing PIN reaches the caller as `PinRequired` before this (the card's
/// security status error). When a `GenericError` occurs and the slot is
/// reported to hold an RSA key of the ciphertext's `size`, the refusal is
/// typically a ciphertext at or above the modulus, which a retry does not
/// change. It is reported as a decryption failure rather than a transient
/// hardware failure. Whether a ciphertext is below the modulus is public, and
/// so are both key sizes, so this mapping gives away nothing.
fn decryption_refusal(held: SlotKey, key_id: &KeyId, size: RsaSize) -> BackendError {
    match held {
        SlotKey::Held(Some(algorithm)) => match RsaSize::of(algorithm) {
            Some(held) if held == size => does_not_decrypt(key_id),
            Some(_) => BackendError::InvalidData(format!(
                "the ciphertext is for an {} key and slot {key_id} holds {algorithm}",
                size.key_algorithm()
            )),
            None => BackendError::UnsupportedAlgorithm(format!(
                "slot {key_id} holds {algorithm}; decrypting a key requires an RSA key"
            )),
        },
        SlotKey::Held(None) => BackendError::UnsupportedAlgorithm(format!(
            "slot {key_id} holds a key with an unsupported algorithm"
        )),
        SlotKey::Empty => BackendError::SlotEmpty(key_id.to_string()),
        SlotKey::Unknown => BackendError::HardwareFailure(format!(
            "the card refused to decrypt in slot {key_id}; it cannot report whether the slot \
             is empty or holds a key other than {}",
            size.key_algorithm()
        )),
    }
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

        let em = emsa_pkcs1_v1_5_sha256(Sha256::digest(b"abc").into(), RsaSize::Rsa2048);
        assert_eq!(to_hex(&em), EXPECTED_EM);
    }

    /// The block verifies under OpenSSL's PKCS#1 v1.5 once the raw RSA
    /// private-key operation the card applies has run over it.
    #[test]
    fn emsa_pkcs1_v1_5_sha256_signs_as_openssl_verifies() {
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Padding;
        use openssl::sign::Verifier;

        let message = b"release manifest";
        for (size, key) in [
            (RsaSize::Rsa2048, oaep::tests::key()),
            (RsaSize::Rsa4096, oaep::tests::rsa_4096_key().clone()),
        ] {
            let rsa = key.rsa().unwrap();
            let em = emsa_pkcs1_v1_5_sha256(Sha256::digest(message).into(), size);
            assert_eq!(em.len(), size.modulus_len());
            let mut signature = vec![0; size.modulus_len()];
            rsa.private_encrypt(&em, &mut signature, Padding::NONE)
                .unwrap();

            let key = PKey::from_rsa(rsa).unwrap();
            let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
            verifier.update(message).unwrap();
            assert!(verifier.verify(&signature).unwrap(), "{size:?}");
        }
    }

    #[test]
    fn rsa_sizes_name_their_algorithms_and_modulus_lengths() {
        for size in RsaSize::ALL {
            assert_eq!(RsaSize::of(size.key_algorithm()), Some(size));
            assert_eq!(RsaSize::from_modulus_len(size.modulus_len()), Some(size));
        }
        assert_eq!(RsaSize::of(KeyAlgorithm::EcdsaP256), None);
        assert_eq!(RsaSize::from_modulus_len(384), None);
    }

    #[test]
    fn an_rsa_signature_takes_the_size_of_the_slot_key() {
        let key_id = KeyId::new("piv:9c");
        assert_eq!(
            rsa_size_held(SlotKey::Held(Some(KeyAlgorithm::Rsa4096)), &key_id).unwrap(),
            RsaSize::Rsa4096
        );
        assert_eq!(
            rsa_size_held(SlotKey::Held(Some(KeyAlgorithm::Rsa2048)), &key_id).unwrap(),
            RsaSize::Rsa2048
        );
        // A card without GET METADATA holds standard PIV's RSA-2048.
        assert_eq!(
            rsa_size_held(SlotKey::Unknown, &key_id).unwrap(),
            RsaSize::Rsa2048
        );
        assert!(matches!(
            rsa_size_held(SlotKey::Held(Some(KeyAlgorithm::EcdsaP256)), &key_id),
            Err(BackendError::UnsupportedAlgorithm(m)) if m.contains("ECDSA-P256")
        ));
        assert!(matches!(
            rsa_size_held(SlotKey::Held(None), &key_id),
            Err(BackendError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            rsa_size_held(SlotKey::Empty, &key_id),
            Err(BackendError::SlotEmpty(_))
        ));
    }

    #[test]
    fn unread_metadata_maps_to_what_the_card_answered() {
        assert_eq!(
            slot_key_unread(yubikey::Error::NotFound).unwrap(),
            SlotKey::Empty
        );
        for error in [
            yubikey::Error::NotSupported,
            yubikey::Error::GenericError,
            yubikey::Error::ParseError,
            yubikey::Error::InvalidObject,
        ] {
            assert_eq!(slot_key_unread(error).unwrap(), SlotKey::Unknown);
        }
        assert!(slot_key_unread(yubikey::Error::AppletError).is_err());
    }

    #[test]
    fn rsa_4096_is_generated_from_firmware_5_7() {
        let firmware = |major, minor, patch| yubikey::Version {
            major,
            minor,
            patch,
        };
        assert!(runs_on_firmware(KeyAlgorithm::Rsa4096, firmware(5, 7, 0)).is_ok());
        assert!(runs_on_firmware(KeyAlgorithm::Rsa4096, firmware(6, 0, 0)).is_ok());
        let error = runs_on_firmware(KeyAlgorithm::Rsa4096, firmware(5, 4, 3)).unwrap_err();
        assert!(
            matches!(&error, BackendError::UnsupportedAlgorithm(m) if m.contains("5.4.3")),
            "{error:?}"
        );
        assert!(runs_on_firmware(KeyAlgorithm::Rsa2048, firmware(4, 3, 5)).is_ok());
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
    fn key_management_runs_in_the_key_management_slots() {
        for slot in [
            PivSlot::KeyManagement,
            PivSlot::Retired(0),
            PivSlot::Retired(19),
        ] {
            let key_id = key_id_for_slot(convert::to_yubikey_slot(slot).unwrap());
            assert!(
                permits_key_management(slot, &key_id, "key agreement").is_ok(),
                "{key_id}"
            );
        }
    }

    #[test]
    fn key_management_is_refused_in_the_other_slots_by_name() {
        for (slot, named) in [
            (PivSlot::Authentication, "authentication slot"),
            (PivSlot::Signature, "signature slot"),
            (PivSlot::CardAuthentication, "needs no PIN"),
        ] {
            let key_id = key_id_for_slot(convert::to_yubikey_slot(slot).unwrap());
            for operation in ["key agreement", "key decryption"] {
                let error = permits_key_management(slot, &key_id, operation).unwrap_err();
                assert!(
                    matches!(&error, BackendError::OperationNotPermitted(m)
                        if m.contains(named) && m.contains(key_id.as_str())
                            && m.contains(operation)),
                    "{error:?}"
                );
            }
        }
    }

    #[test]
    fn decryption_goes_to_slot_9d_at_the_size_the_ciphertext_names() {
        for size in RsaSize::ALL {
            let (slot, named) = decryption_slot(
                &KeyId::new("piv:9d"),
                &vec![0; size.modulus_len()],
                KeyProtection::RsaOaepSha256,
            )
            .unwrap();
            assert_eq!(slot, SlotId::KeyManagement);
            assert_eq!(named, size);
        }
    }

    /// Everything the host can refuse is refused before the card is asked.
    #[test]
    fn decryption_is_refused_before_the_card_by_name() {
        let block = [0u8; 256];
        let cases: [(&str, &[u8], KeyProtection, &str); 4] = [
            ("piv:9d", &block, KeyProtection::AesKeyWrap, "AES-KW"),
            (
                "piv:9c",
                &block,
                KeyProtection::RsaOaepSha256,
                "signature slot",
            ),
            ("piv:9d", &[0; 384], KeyProtection::RsaOaepSha256, "384"),
            ("piv:9d", &[], KeyProtection::RsaOaepSha256, "RSA-4096"),
        ];
        for (key_id, encrypted, protection, named) in cases {
            let error = decryption_slot(&KeyId::new(key_id), encrypted, protection).unwrap_err();
            assert!(error.to_string().contains(named), "{named}: {error}");
        }
    }

    #[test]
    fn a_block_without_its_leading_zero_still_decodes() {
        let key = oaep::tests::key();
        let message = [0x5a; 32];
        let block = oaep::tests::encoded(&key, &message);
        let (&leading, shortened) = block.split_first().unwrap();
        assert_eq!(leading, 0);

        let full = full_length_block(shortened, RsaSize::Rsa2048).unwrap();
        assert_eq!(&oaep::decode(&full).unwrap()[..], &message[..]);
    }

    #[test]
    fn a_block_the_card_shortened_is_restored_to_full_length() {
        for size in RsaSize::ALL {
            let k = size.modulus_len();
            let full = full_length_block(&vec![0xab; k - 1], size).unwrap();
            assert_eq!(full.len(), k);
            assert_eq!(full.first(), Some(&0));
            assert_eq!(full.last(), Some(&0xab));

            assert_eq!(
                &full_length_block(&vec![7; k], size).unwrap()[..],
                &vec![7; k][..]
            );
            assert!(matches!(
                full_length_block(&vec![0; k + 1], size),
                Err(BackendError::Other(_))
            ));
        }
    }

    #[test]
    fn a_refused_decryption_names_what_the_slot_holds() {
        let key_id = KeyId::new("piv:9d");
        for (held, check) in [
            (
                SlotKey::Held(Some(KeyAlgorithm::Rsa2048)),
                (|e: &BackendError| matches!(e, BackendError::InvalidData(_)))
                    as fn(&BackendError) -> bool,
            ),
            (SlotKey::Held(Some(KeyAlgorithm::Rsa4096)), |e| {
                matches!(e, BackendError::InvalidData(m)
                    if m.contains("RSA-2048") && m.contains("RSA-4096"))
            }),
            (
                SlotKey::Held(Some(KeyAlgorithm::EcdsaP256)),
                |e| matches!(e, BackendError::UnsupportedAlgorithm(m) if m.contains("ECDSA-P256")),
            ),
            (SlotKey::Empty, |e| matches!(e, BackendError::SlotEmpty(_))),
            (SlotKey::Unknown, |e| {
                matches!(e, BackendError::HardwareFailure(_))
            }),
        ] {
            let error = decryption_refusal(held, &key_id, RsaSize::Rsa2048);
            assert!(check(&error), "{held:?}: {error:?}");
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
