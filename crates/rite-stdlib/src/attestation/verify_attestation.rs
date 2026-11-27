//! `verify_attestation` action: check a device's statement about a key
//! against the roots the ceremony trusts.

use std::collections::HashMap;
use std::hash::BuildHasher;

use rite_model::params::{AttestationRequirements, VerifyAttestationParams};
use rite_model::{
    ActionType, ArtifactId, ArtifactRef, AttestationAnchor, AttestedClaimsRecord,
    RequirementRecord, Sha256Digest, StepFact,
};
use rite_openssl::{ChainOutcome, VerifiedChain, chain_verifier, verify_certificate_chain};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    parse_params,
};
use rite_sdk::{
    AccessWhen, Attestation, AttestedClaims, Backend, CertificateDer, CertificateFingerprint,
    PublicKeyDer, StatedAccess,
};

/// Check an attestation against the roots named by the ceremony.
///
/// The action checks the certificate chain, confirms that the attested key
/// matches the supplied key, and evaluates any required claims. Only the
/// named roots are trust anchors. Rite currently reads `yubico-piv/v1`.
///
/// In a dry run, the root the mock attests under is also trusted and recorded
/// as `rehearsal`. A real run refuses that root because its private keys are
/// public.
pub struct VerifyAttestationAction;

impl Action for VerifyAttestationAction {
    fn action_type(&self) -> ActionType {
        ActionType::VerifyAttestation
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: VerifyAttestationParams = parse_params(params)?;
        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.clone())?;
        }

        let inputs = Inputs::resolve(step, ctx)?;
        // The step's instant: the chain is checked at it, and it is recorded.
        let now = reporter.now()?;
        reporter.log(
            Icon::Spinner,
            format!(
                "Checking attestation '{}' against the ceremony's roots...",
                inputs.attestation_name
            ),
        )?;
        let chain = inputs.trusted_chain(now.timestamp().as_second())?;
        let Inputs {
            attestation,
            attestation_value,
            attestation_name,
            key,
            key_name,
            roots,
            roots_name,
            ..
        } = inputs;

        let attested = attestation.leaf().public_key()?;
        if attested != key {
            return Err(ActionError::Failed(format!(
                "attestation '{attestation_name}' attests key {}, not '{key_name}' ({})",
                attested.fingerprint(),
                key.fingerprint()
            )));
        }

        let claims = attestation.claims()?;
        let anchor = if chain.root().is_some_and(is_rehearsal_root) {
            AttestationAnchor::Rehearsal
        } else {
            AttestationAnchor::Trusted
        };
        let (requirements, unmet) = typed
            .require
            .as_ref()
            .map(|require| check(require, &claims))
            .unwrap_or_default();

        let bundle = attestation_value
            .serialize(Some("pem"))
            .map_err(ActionError::Failed)?;
        reporter.fact(StepFact::KeyAttested {
            step: step.id.clone(),
            attestation: attestation_name.clone(),
            format: attestation.format().to_string(),
            digest: Sha256Digest::of(&bundle.bytes),
            key: key.fingerprint(),
            chain: fingerprints(chain.certificates()),
            roots: fingerprints(&roots),
            checked_at: now.to_string(),
            verifier: chain_verifier(),
            anchor,
            claims: Box::new(AttestedClaimsRecord::of(&claims)),
            requirements,
        })?;

        // Its private keys are public: outside a rehearsal, a chain to it is
        // a chain anyone could have made, with any claims.
        if anchor == AttestationAnchor::Rehearsal && !ctx.dry_run {
            return Err(ActionError::Failed(format!(
                "attestation '{attestation_name}' chains to the rehearsal root, whose private \
                 keys are public, and this run is not a rehearsal; '{roots_name}' must hold \
                 only the vendor's roots"
            )));
        }
        // A rehearsal's requirements are not exercised: its stand-in device's
        // claims say nothing of the real one.
        if anchor == AttestationAnchor::Trusted && !unmet.is_empty() {
            return Err(ActionError::Failed(format!(
                "attestation '{attestation_name}' does not meet the step's requirements: {}",
                unmet.join("; ")
            )));
        }
        let summary = match anchor {
            AttestationAnchor::Trusted => format!(
                "Attestation '{attestation_name}' verified: the device generated '{key_name}'"
            ),
            AttestationAnchor::Rehearsal => format!(
                "Attestation '{attestation_name}' chains to the rehearsal root: a rehearsal, \
                 not evidence"
            ),
        };
        Ok(StepResult::completed(summary))
    }
}

/// What a step reads, resolved, with the names the ceremony gives them.
struct Inputs<'a> {
    attestation: &'a Attestation,
    /// The same attestation, as the artifact the step reads.
    attestation_value: &'a ArtifactValue,
    attestation_name: String,
    key: PublicKeyDer,
    key_name: String,
    /// The ceremony's roots, and in a dry run the rehearsal root.
    roots: Vec<CertificateDer>,
    roots_name: String,
    intermediates: Vec<CertificateDer>,
}

impl<'a> Inputs<'a> {
    /// The chain from the attestation to one of the roots at `at`, through
    /// the attestation's own certificates, then `intermediates`.
    fn trusted_chain(&self, at: i64) -> Result<VerifiedChain, ActionError> {
        let (attestation, name, roots) =
            (self.attestation, &self.attestation_name, &self.roots_name);
        let untrusted = [attestation.issuers(), &self.intermediates].concat();
        match verify_certificate_chain(attestation.leaf(), &untrusted, &self.roots, at)? {
            ChainOutcome::Trusted(chain) if attestation.is_start_of(chain.certificates()) => {
                Ok(chain)
            }
            ChainOutcome::Trusted(_) => Err(ActionError::Failed(format!(
                "attestation '{name}' chains to the roots in '{roots}' only through another \
                 device certificate than its own, so its claims are unchecked"
            ))),
            ChainOutcome::Refused(reason) => Err(ActionError::Failed(format!(
                "attestation '{name}' does not chain to the roots in '{roots}': {reason}"
            ))),
        }
    }

    fn resolve(step: &StepInfo, ctx: &HandlerContext<'a>) -> Result<Self, ActionError> {
        let attestation_ref = step.required_named_input("attestation", "verify_attestation")?;
        let key_ref = step.required_named_input("key", "verify_attestation")?;
        let roots_ref = step.required_named_input("roots", "verify_attestation")?;
        let attestation_name = attestation_ref.display_name();
        let Some(attestation_value @ ArtifactValue::Attestation(attestation)) =
            ctx.artifacts.get(&attestation_ref.artifact_id())
        else {
            return Err(ActionError::Failed(format!(
                "verify_attestation input 'attestation' ('{attestation_name}') is not an \
                 attestation"
            )));
        };
        let key_name = key_ref.display_name();
        let key = crate::signatures::resolve_public_key(
            ctx.artifacts,
            &key_ref.artifact_id(),
            key_ref.property(),
        )
        .map_err(|e| {
            ActionError::Failed(format!(
                "verify_attestation input 'key' ('{key_name}') is not a usable public key: {e}"
            ))
        })?;
        let intermediates = match step.named_input("intermediates") {
            Some(reference) => certificates(ctx.artifacts, reference, "intermediates")?,
            None => Vec::new(),
        };
        let mut roots = certificates(ctx.artifacts, roots_ref, "roots")?;
        if ctx.dry_run {
            roots.extend(rehearsal_root()?);
        }
        Ok(Self {
            attestation,
            attestation_value,
            attestation_name,
            key,
            key_name,
            roots,
            roots_name: roots_ref.display_name(),
            intermediates,
        })
    }
}

/// The SHA-256 of each certificate, in order.
fn fingerprints(certificates: &[CertificateDer]) -> Vec<CertificateFingerprint> {
    certificates
        .iter()
        .map(|certificate| CertificateFingerprint::of_der(certificate.as_bytes()))
        .collect()
}

/// The certificates `reference` names under `input`: a certificates file, or
/// one certificate, which a property may select.
fn certificates<S: BuildHasher>(
    artifacts: &HashMap<ArtifactId, ArtifactValue, S>,
    reference: &ArtifactRef,
    input: &str,
) -> Result<Vec<CertificateDer>, ActionError> {
    let artifact_id = reference.artifact_id();
    let name = reference.display_name();
    let failed = |reason: String| {
        ActionError::Failed(format!(
            "verify_attestation input '{input}' ('{name}') is not certificates: {reason}"
        ))
    };
    match (artifacts.get(&artifact_id), reference.property()) {
        (Some(ArtifactValue::Certificates(certificates)), None) => Ok(certificates.clone()),
        (Some(ArtifactValue::Certificates(_)), Some(property)) => Err(failed(format!(
            "a list of certificates has no property '{property}'"
        ))),
        (Some(_), property) => {
            crate::signatures::resolve_certificate(artifacts, &artifact_id, property)
                .map(|certificate| vec![certificate])
                .map_err(|e| failed(e.to_string()))
        }
        (None, _) => Err(ActionError::Failed(format!(
            "verify_attestation input '{input}' ('{name}') does not exist"
        ))),
    }
}

/// Each requirement of `require` against `claims`, and why each unmet one is
/// not met, for the step's error. The serial is compared and not recorded: it
/// identifies the device.
fn check(
    require: &AttestationRequirements,
    claims: &AttestedClaims,
) -> (Vec<RequirementRecord>, Vec<String>) {
    let mut records = Vec::new();
    let mut unmet = Vec::new();
    let mut policy = |claim: &str, accepted: &[AccessWhen], stated: Option<StatedAccess>| {
        let met = matches!(stated, Some(StatedAccess::Value(value)) if accepted.contains(&value));
        let accepted: Vec<String> = accepted
            .iter()
            .map(|value| value.as_str().to_string())
            .collect();
        let observed = stated.map(|value| value.to_string());
        if !met {
            unmet.push(match &observed {
                Some(observed) => format!(
                    "{claim} is {observed}, and the step accepts {}",
                    accepted.join(" or ")
                ),
                None => format!("the attestation states no {claim}"),
            });
        }
        records.push(RequirementRecord::new(claim, accepted, observed, met));
    };
    if let Some(accepted) = &require.authentication {
        policy("authentication", accepted, claims.authentication);
    }
    if let Some(accepted) = &require.presence {
        policy("presence", accepted, claims.presence);
    }
    if let Some(serial) = require.serial {
        let met = claims.serial == Some(serial);
        if !met {
            unmet.push("the device's serial is not the one required".to_string());
        }
        records.push(RequirementRecord::new("serial", Vec::new(), None, met));
    }
    (records, unmet)
}

/// The root a dry run's mock attests under, to which anyone can make a chain.
fn rehearsal_root() -> Result<Option<CertificateDer>, ActionError> {
    #[cfg(feature = "pki")]
    {
        CertificateDer::new(crate::backend::MOCK_ATTESTATION_ROOT.to_vec())
            .map(Some)
            .map_err(|e| ActionError::Failed(format!("the rehearsal root does not parse: {e}")))
    }
    // Without `pki` the mock attests nothing, so there is no root to trust.
    #[cfg(not(feature = "pki"))]
    {
        Ok(None)
    }
}

/// Whether `root` is the rehearsal root.
fn is_rehearsal_root(root: &CertificateDer) -> bool {
    #[cfg(feature = "pki")]
    {
        root.as_bytes() == crate::backend::MOCK_ATTESTATION_ROOT
    }
    #[cfg(not(feature = "pki"))]
    {
        let _ = root;
        false
    }
}

#[cfg(all(test, feature = "pki"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::MockBackend;
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509, X509Extension, X509NameBuilder};
    use rite_model::{ArtifactRef, MaterialId, NamedInput, StepId, StepInputs};
    use rite_runtime::test_support::ReporterHarness;
    use rite_sdk::{
        AttestationBackend, AttestationFormat, KeyAlgorithm, KeyId, KeyPolicy, KeySpec,
        KeyStoreBackend,
    };
    use std::ops::Range;

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A day either side of now, in days from now.
    const CURRENT: Range<i64> = -1..1;

    /// A certificate for `subject`, issued by `issuer` (itself when `None`),
    /// valid over `days` from now, with `extensions`.
    fn certificate(
        name: &str,
        subject: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        days: Range<i64>,
        extensions: Vec<X509Extension>,
    ) -> X509 {
        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("CN", name).unwrap();
        let x509_name = x509_name.build();
        let at = |days: i64| {
            Asn1Time::from_unix(jiff::Timestamp::now().as_second() + days * 86_400).unwrap()
        };
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&x509_name).unwrap();
        builder.set_pubkey(subject).unwrap();
        builder.set_not_before(&at(days.start)).unwrap();
        builder.set_not_after(&at(days.end)).unwrap();
        for extension in extensions {
            builder.append_extension(extension).unwrap();
        }
        let (issuer_name, signer) = match issuer {
            Some((certificate, key)) => (certificate.subject_name().to_owned().unwrap(), key),
            None => (x509_name, subject),
        };
        builder.set_issuer_name(&issuer_name).unwrap();
        builder.sign(signer, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn yubico(arc: u8, value: &[u8]) -> X509Extension {
        let oid = Asn1Object::from_str(&format!("1.3.6.1.4.1.41482.3.{arc}")).unwrap();
        X509Extension::new_from_der(
            &oid,
            false,
            &Asn1OctetString::new_from_bytes(value).unwrap(),
        )
        .unwrap()
    }

    fn der(certificate: &X509) -> CertificateDer {
        CertificateDer::new(certificate.to_der().unwrap()).unwrap()
    }

    fn ca() -> Vec<X509Extension> {
        vec![BasicConstraints::new().critical().ca().build().unwrap()]
    }

    /// A device under a root of these tests, and a key it generated, as a
    /// YubiKey under Yubico's root.
    struct Device {
        root: X509,
        root_key: PKey<Private>,
        certificate: X509,
        key: PKey<Private>,
        attested_key: PKey<Private>,
    }

    impl Device {
        fn new() -> Self {
            let (root_key, key, attested_key) = (key(), key(), key());
            let root = certificate("Root", &root_key, None, CURRENT, ca());
            let certificate = certificate("Device", &key, Some((&root, &root_key)), CURRENT, ca());
            Self {
                root,
                root_key,
                certificate,
                key,
                attested_key,
            }
        }

        /// The device's attestation of its key, issued through `device`:
        /// PIN always, touch cached, serial 32456360.
        fn attestation(&self, device: &X509) -> Attestation {
            let leaf = certificate(
                "Leaf",
                &self.attested_key,
                Some((&self.certificate, &self.key)),
                CURRENT,
                vec![
                    yubico(3, &[5, 7, 1]),
                    yubico(7, &[0x02, 0x04, 0x01, 0xef, 0x3e, 0xa8]),
                    yubico(8, &[3, 3]),
                    yubico(9, &[3]),
                ],
            );
            Attestation::new(AttestationFormat::YubicoPiv, vec![der(&leaf), der(device)]).unwrap()
        }

        fn attested_key(&self) -> PublicKeyDer {
            PublicKeyDer::new(self.attested_key.public_key_to_der().unwrap()).unwrap()
        }
    }

    /// A YubiKey-style attestation under a root of these tests: its key, the
    /// attestation, and the root.
    fn attested() -> (PublicKeyDer, Attestation, CertificateDer) {
        let device = Device::new();
        let attestation = device.attestation(&device.certificate);
        (device.attested_key(), attestation, der(&device.root))
    }

    /// The step in a rehearsal when `dry_run`, otherwise in a real run, with
    /// `intermediates` when there are any.
    fn run(
        dry_run: bool,
        attestation: Attestation,
        key: PublicKeyDer,
        roots: Vec<CertificateDer>,
        intermediates: Vec<CertificateDer>,
        with: &serde_json::Value,
    ) -> (Result<StepResult, ActionError>, ReporterHarness) {
        let mut harness = ReporterHarness::new();
        let mut step = StepInfo::new(StepId::new("check"), None, None, None, None);
        let input = |id: &str| {
            NamedInput::One(ArtifactRef::Material {
                id: MaterialId::new(id),
                property: None,
            })
        };
        let mut inputs = HashMap::from([
            ("attestation".to_string(), input("evidence")),
            ("key".to_string(), input("signing_key")),
            ("roots".to_string(), input("roots")),
        ]);
        let mut artifacts = HashMap::from([
            (
                ArtifactId::new("evidence"),
                ArtifactValue::Attestation(attestation),
            ),
            (
                ArtifactId::new("signing_key"),
                ArtifactValue::PublicKey(key),
            ),
            (ArtifactId::new("roots"), ArtifactValue::Certificates(roots)),
        ]);
        if !intermediates.is_empty() {
            inputs.insert("intermediates".to_string(), input("intermediates"));
            artifacts.insert(
                ArtifactId::new("intermediates"),
                ArtifactValue::Certificates(intermediates),
            );
        }
        step.typed_inputs = Some(StepInputs::Named(inputs));
        let (params, roles, materials) = (HashMap::new(), HashMap::new(), HashMap::new());
        let ctx = HandlerContext {
            params: &params,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
            credentials: &HashMap::new(),
            dry_run,
        };
        let result = {
            let mut reporter = harness.reporter(StepId::new("check"));
            VerifyAttestationAction.execute(&step, &ctx, with, &mut reporter, None)
        };
        (result, harness)
    }

    fn recorded(harness: &ReporterHarness) -> (AttestationAnchor, Vec<RequirementRecord>) {
        harness
            .facts()
            .iter()
            .find_map(|fact| match fact {
                StepFact::KeyAttested {
                    anchor,
                    requirements,
                    ..
                } => Some((*anchor, requirements.clone())),
                _ => None,
            })
            .expect("a key_attested fact")
    }

    #[test]
    fn verifies_the_chain_the_key_and_the_requirements() {
        let (key, attestation, root) = attested();
        let with = serde_json::json!({"require": {
            "authentication": ["per_use"],
            "presence": ["per_use", "cached"],
            "serial": 32_456_360,
        }});
        let (result, harness) = run(false, attestation, key, vec![root], Vec::new(), &with);
        result.expect("the attestation verifies");
        let (anchor, requirements) = recorded(&harness);
        assert_eq!(anchor, AttestationAnchor::Trusted);
        assert_eq!(requirements.len(), 3);
        assert!(requirements.iter().all(|requirement| requirement.met));
    }

    #[test]
    fn an_unmet_requirement_fails_the_step_and_is_recorded() {
        let (key, attestation, root) = attested();
        let with = serde_json::json!({"require": {"presence": ["per_use"], "serial": 1}});
        let (result, harness) = run(false, attestation, key, vec![root], Vec::new(), &with);
        let error = result.expect_err("touch is cached, and the serial differs");
        assert!(error.to_string().contains("presence is cached"), "{error}");
        assert!(error.to_string().contains("serial"), "{error}");
        let (_, requirements) = recorded(&harness);
        assert!(requirements.iter().all(|requirement| !requirement.met));
        assert_eq!(
            requirements[1].observed, None,
            "the serial is never recorded"
        );
    }

    #[test]
    fn refuses_another_key_or_another_root() {
        let (key, attestation, root) = attested();
        let (other_key, _, other_root) = attested();
        let none = serde_json::json!({});
        let (result, _) = run(
            false,
            attestation.clone(),
            other_key,
            vec![root],
            Vec::new(),
            &none,
        );
        assert!(result.unwrap_err().to_string().contains("attests key"));
        let (result, _) = run(false, attestation, key, vec![other_root], Vec::new(), &none);
        assert!(result.unwrap_err().to_string().contains("does not chain"));
    }

    /// The claims are read from the attestation's own device certificate, so
    /// a chain the check builds through another one vouches for none of them.
    #[test]
    fn refuses_a_chain_through_another_device_certificate() {
        let device = Device::new();
        // The device's name and key, claiming FIPS, but expired: the check
        // prefers the current certificate it finds among the intermediates.
        let look_alike = certificate(
            "Device",
            &device.key,
            Some((&device.root, &device.root_key)),
            -3..-2,
            ca().into_iter().chain([yubico(10, &[])]).collect(),
        );
        let (result, harness) = run(
            false,
            device.attestation(&look_alike),
            device.attested_key(),
            vec![der(&device.root)],
            vec![der(&device.certificate)],
            &serde_json::json!({}),
        );
        let error = result.expect_err("the chain does not run through the look-alike");
        assert!(
            error.to_string().contains("another device certificate"),
            "{error}"
        );
        assert!(harness.facts().is_empty(), "nothing is recorded");
    }

    /// A dry run adds the rehearsal root beside the ceremony's, so an
    /// attestation from a material still chains to a root the ceremony names.
    #[test]
    fn a_dry_run_still_trusts_the_ceremonys_roots() {
        let (key, attestation, root) = attested();
        let with = serde_json::json!({"require": {"presence": ["per_use"]}});
        let (result, harness) = run(true, attestation, key, vec![root], Vec::new(), &with);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("presence is cached")
        );
        assert_eq!(recorded(&harness).0, AttestationAnchor::Trusted);
    }

    /// The mock's attestation of a key it generated in 9C, the key, and the
    /// rehearsal root.
    fn rehearsed() -> (Attestation, PublicKeyDer, CertificateDer) {
        let mut mock = MockBackend::new("token".to_string(), "seed".to_string());
        let generated = mock
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::EcdsaP256,
                label: "signing".to_string(),
                policy: KeyPolicy::default(),
                location_hint: Some("9c".to_string()),
            })
            .unwrap();
        let attestation = mock.attest_key(&generated.key_id).unwrap();
        let key = mock
            .export_public_key(&KeyId::new(generated.key_id.as_str()))
            .unwrap();
        let root = CertificateDer::new(crate::backend::MOCK_ATTESTATION_ROOT.to_vec()).unwrap();
        (attestation, key, root)
    }

    #[test]
    fn a_rehearsal_chain_is_recorded_as_such_and_its_requirements_not_exercised() {
        let (attestation, key, _) = rehearsed();
        // The ceremony's roots are a vendor's, not the rehearsal root.
        let (_, _, vendor_root) = attested();
        // The mock states 9C's default touch, never: the requirement fails,
        // and a rehearsal does not stop on it.
        let with = serde_json::json!({"require": {"presence": ["per_use"]}});
        let (result, harness) = run(true, attestation, key, vec![vendor_root], Vec::new(), &with);
        result.expect("a rehearsal completes");
        let (anchor, requirements) = recorded(&harness);
        assert_eq!(anchor, AttestationAnchor::Rehearsal);
        assert!(!requirements[0].met);
    }

    /// Anyone can chain to the rehearsal root, so a real run refuses it,
    /// even when its roots material holds it.
    #[test]
    fn a_real_run_refuses_a_chain_to_the_rehearsal_root() {
        let (attestation, key, root) = rehearsed();
        let none = serde_json::json!({});
        let (result, harness) = run(false, attestation, key, vec![root], Vec::new(), &none);
        let error = result.expect_err("a real run does not take the rehearsal root");
        assert!(error.to_string().contains("not a rehearsal"), "{error}");
        assert_eq!(recorded(&harness).0, AttestationAnchor::Rehearsal);
    }
}
