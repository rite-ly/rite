//! What a wrapping row says: which step, under which key, and what must
//! happen.

use rite_sdk::{Oid, RecipientInfoKind, WrapDescription, WrapScheme};

use crate::keys::TestKey;
use crate::outcome::{Expected, Refusal, Why};
use crate::session::Source;
use crate::shape::Shape;

/// A step that writes a wrapped key or an encrypted container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStep {
    WrapKey,
    EncryptData,
}

/// A step that opens one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStep {
    UnwrapKey,
    DecryptData,
}

impl WriteStep {
    pub const ALL: &'static [WriteStep] = &[WriteStep::WrapKey, WriteStep::EncryptData];

    pub fn name(self) -> &'static str {
        match self {
            WriteStep::WrapKey => "wrap_key",
            WriteStep::EncryptData => "encrypt_data",
        }
    }

    /// The step that opens what this one writes.
    pub fn reader(self) -> ReadStep {
        match self {
            WriteStep::WrapKey => ReadStep::UnwrapKey,
            WriteStep::EncryptData => ReadStep::DecryptData,
        }
    }
}

impl ReadStep {
    pub const ALL: &'static [ReadStep] = &[ReadStep::UnwrapKey, ReadStep::DecryptData];

    pub fn name(self) -> &'static str {
        match self {
            ReadStep::UnwrapKey => "unwrap_key",
            ReadStep::DecryptData => "decrypt_data",
        }
    }
}

/// How the step reaches the key it writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// A key the backend holds: `wrapping_key:` on `wrap_key`,
    /// `encryption_key:` on `encrypt_data`, imported or generated first. A
    /// generated key never leaves the backend, so only Rite reads what is
    /// written to it; the form is an imported key's, which the command line
    /// reads.
    Held(Source),
    /// A public key read as `recipient:` on both, in the form it arrives in.
    /// A symmetric key has no public half and never takes this path.
    Recipient(Shape),
}

impl Path {
    /// Every path, a recipient as the algorithm rows give it.
    pub const ALL: &'static [Path] = &[
        Path::Held(Source::Imported),
        Path::Held(Source::Generated),
        Path::Recipient(Shape::SpkiDer),
    ];

    pub fn name(self) -> &'static str {
        match self {
            Path::Held(Source::Imported) => "held",
            Path::Held(Source::Generated) => "generated",
            Path::Recipient(_) => "recipient",
        }
    }

    /// The step input the key is named by.
    pub fn input(self, step: WriteStep) -> &'static str {
        match (step, self) {
            (WriteStep::WrapKey, Path::Held(_)) => "wrapping_key",
            (WriteStep::EncryptData, Path::Held(_)) => "encryption_key",
            (_, Path::Recipient(_)) => "recipient",
        }
    }
}

/// What a write step must do.
#[derive(Debug, Clone, Copy)]
pub enum Write {
    /// The step writes this form, which opens again.
    Writes(Form),
    /// The step is refused.
    Fails(Why, Refusal),
}

/// What a read step must do.
#[derive(Debug, Clone, Copy)]
pub enum Read {
    /// The step recovers the content.
    Opens,
    Fails(Why, Refusal),
}

/// What a write produced, stated independently of the code that produced it.
#[derive(Debug, Clone, Copy)]
pub enum Form {
    /// A CMS `AuthEnvelopedData`, compared field by field against what
    /// `cms::describe` reads out of the bytes and against what the step
    /// recorded.
    Cms {
        recipient: RecipientInfoKind,
        key_encryption: &'static str,
        /// Only a KEM names its KDF in a field of its own. A key agreement
        /// folds it into `key_encryption`.
        kdf: Option<&'static str>,
        kek_wrap: Option<&'static str>,
        content: &'static str,
    },
    /// A raw mechanism, whose output carries nothing to read back, so only the
    /// recorded description can be compared.
    Raw(WrapScheme),
}

impl Form {
    /// The scheme a step that writes this form reports.
    pub fn scheme(&self) -> WrapScheme {
        match self {
            Form::Cms { .. } => WrapScheme::CmsAes256Gcm,
            Form::Raw(scheme) => *scheme,
        }
    }

    /// The description of the form: what `cms::describe` reads out of a CMS
    /// container, or a raw scheme's fixed description.
    pub fn description(&self) -> WrapDescription {
        match self {
            Form::Cms {
                recipient,
                key_encryption,
                kdf,
                kek_wrap,
                content,
            } => {
                let oid = |value: &str| Oid::new(value).expect("the cases name valid OIDs");
                let mut description = WrapDescription::new(*recipient, oid(key_encryption))
                    .with_content_encryption(oid(content));
                if let Some(kdf) = kdf {
                    description = description.with_kdf(oid(kdf));
                }
                if let Some(kek_wrap) = kek_wrap {
                    description = description.with_kek_wrap(oid(kek_wrap));
                }
                description
            }
            Form::Raw(scheme) => scheme
                .fixed_description()
                .expect("a raw scheme has a fixed description"),
        }
    }
}

/// What a write case seals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    /// [`TestKey::PayloadP256`]: its PKCS#8 DER as content, or the key
    /// itself for `wrap_key`.
    P256,
    /// [`TestKey::PayloadAes256`], for AES-KW, which takes whole 64-bit
    /// blocks only.
    Aes256,
    /// [`TestKey::PayloadRsa2048`], whose PKCS#8 is larger than raw RSA-OAEP
    /// under RSA-2048 carries.
    Rsa2048,
}

impl Payload {
    pub fn key(self) -> TestKey {
        match self {
            Payload::P256 => TestKey::PayloadP256,
            Payload::Aes256 => TestKey::PayloadAes256,
            Payload::Rsa2048 => TestKey::PayloadRsa2048,
        }
    }
}

/// One write: a step, the key it writes to, and what must happen.
#[derive(Debug, Clone, Copy)]
pub struct WriteCase {
    pub step: WriteStep,
    pub path: Path,
    pub key: TestKey,
    /// `scheme:` as a ceremony writes it, so a name Rite does not know can be
    /// a case. `None` leaves the step's default.
    pub scheme: Option<&'static str>,
    pub payload: Payload,
    pub expect: Expected<Write>,
}

impl WriteCase {
    pub fn name(&self) -> String {
        let mut name = format!(
            "{}::{}::{}",
            self.step.name(),
            self.path.name(),
            self.key.stem()
        );
        if let Some(scheme) = self.scheme {
            name.push_str("::");
            name.push_str(scheme);
        }
        if self.payload != Payload::P256 {
            name.push_str("::");
            name.push_str(self.payload.key().stem());
        }
        if let Path::Recipient(shape) = self.path
            && shape != Shape::SpkiDer
        {
            name.push_str("::as::");
            name.push_str(shape.name());
        }
        name
    }
}

/// A container written outside Rite by `openssl cms -encrypt`, committed
/// under `fixtures/cms/`.
///
/// The fields are the command, so regenerating a fixture and reading what it
/// is are the same table. The content is always
/// [`TestKey::PayloadP256`]'s PKCS#8 DER, so the one fixture serves both
/// read steps.
#[derive(Debug, Clone, Copy)]
pub struct Fixture {
    /// The file name under `fixtures/cms/`, without `.der`.
    pub name: &'static str,
    /// The content cipher option, `-aes-256-gcm` for instance.
    pub content: &'static [&'static str],
    /// Whether the recipients are named by key identifier (`-keyid`) rather
    /// than by issuer and serial number.
    pub keyid: bool,
    /// Who it is sealed to, in order.
    pub recipients: &'static [Recipient],
    /// The key a case holds to open it.
    pub opened_with: TestKey,
    /// Algorithm identifiers the bytes must carry, and ones they must not,
    /// checked by searching the DER for each encoded OID. That needs no CMS
    /// reader, so it holds for the forms Rite refuses to read, and it is what
    /// stops a file swapped for another form from passing the row.
    pub holds: &'static [&'static str],
    pub lacks: &'static [&'static str],
    pub unwrap_key: Expected<Read>,
    pub decrypt_data: Expected<Read>,
}

impl Fixture {
    pub fn expect(&self, step: ReadStep) -> &Expected<Read> {
        match step {
            ReadStep::UnwrapKey => &self.unwrap_key,
            ReadStep::DecryptData => &self.decrypt_data,
        }
    }
}

/// One recipient of a fixture.
#[derive(Debug, Clone, Copy)]
pub enum Recipient {
    /// A key: `-recip` with a certificate for an asymmetric one, then these
    /// `-keyopt` arguments, which apply to that recipient alone; `-secretkey`
    /// and `-secretkeyid` with its check value for a symmetric one.
    Key {
        key: TestKey,
        keyopts: &'static [&'static str],
    },
    /// `-pwri_password`.
    Password(&'static str),
}
