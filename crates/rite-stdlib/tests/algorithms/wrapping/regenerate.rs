//! Write what `fixtures/cms/` lacks from [`FIXTURES`], one `openssl cms
//! -encrypt` per row. See `regenerate.rs` at the top for how to run it.

use std::path::{Path, PathBuf};

use super::cases::FIXTURES;
use super::fixture_path;
use super::model::Recipient;
use crate::cli::{Cli, arg};
use crate::harness::reference_check_value;
use crate::keys::TestKey;
use crate::regenerate::write;

pub fn containers(cli: &Cli, written: &mut Vec<String>) -> Result<(), String> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let signer = dir.path().join("signer.pem");
    cli.run(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        arg(&signer),
    ])?;
    let payload = TestKey::PayloadP256.private_path();

    for fixture in FIXTURES {
        let out = fixture_path(fixture);
        if out.exists() {
            continue;
        }
        let mut owned: Vec<String> = Vec::new();
        for recipient in fixture.recipients {
            match recipient {
                Recipient::Key { key, keyopts } if key.is_symmetric() => {
                    owned.extend([
                        "-secretkey".to_string(),
                        base16ct::lower::encode_string(&key.private()),
                        "-secretkeyid".to_string(),
                        base16ct::lower::encode_string(&check_value(*key)),
                    ]);
                    owned.extend(keyopts.iter().map(ToString::to_string));
                }
                Recipient::Key { key, keyopts } => {
                    let cert = certificate(cli, dir.path(), &signer, *key)?;
                    owned.extend(["-recip".to_string(), arg(&cert).to_string()]);
                    owned.extend(keyopts.iter().map(ToString::to_string));
                }
                Recipient::Password(password) => {
                    owned.extend(["-pwri_password".to_string(), (*password).to_string()]);
                }
            }
        }
        let mut command = vec![
            "cms",
            "-encrypt",
            "-binary",
            "-outform",
            "DER",
            "-in",
            arg(&payload),
            "-out",
            arg(&out),
        ];
        command.extend_from_slice(fixture.content);
        if fixture.keyid {
            command.push("-keyid");
        }
        command.extend(owned.iter().map(String::as_str));
        write(cli, &out, &command)?;
        written.push(fixture.name.to_string());
    }
    Ok(())
}

/// A certificate for `key`, signed by `signer`, so `-recip` can name a key
/// that cannot sign, such as an ML-KEM one. Its subject key identifier is
/// what `-keyid` puts in the container.
fn certificate(cli: &Cli, dir: &Path, signer: &Path, key: TestKey) -> Result<PathBuf, String> {
    let public = dir.join(format!("{}.pub.pem", key.stem()));
    let cert = dir.join(format!("{}.crt", key.stem()));
    if !cert.exists() {
        cli.run(&[
            "pkey",
            "-pubin",
            "-inform",
            "DER",
            "-in",
            arg(&key.public_path()),
            "-out",
            arg(&public),
        ])?;
        cli.run(&[
            "x509",
            "-new",
            "-subj",
            &format!("/CN={}", key.stem()),
            "-key",
            arg(signer),
            "-force_pubkey",
            arg(&public),
            "-days",
            "36500",
            "-out",
            arg(&cert),
        ])?;
    }
    Ok(cert)
}

/// The identifier Rite gives a symmetric key, which is what a
/// `KEKRecipientInfo` must carry for Rite to open it. For a key Rite cannot
/// import there is none, and any identifier will do: the case is refused at
/// import.
fn check_value(key: TestKey) -> Vec<u8> {
    if key.rite().is_none() {
        return vec![0];
    }
    reference_check_value(key).as_bytes().to_vec()
}
