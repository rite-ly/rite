//! Write what `fixtures/signatures/` lacks from [`FIXTURES`], one `openssl
//! pkeyutl -sign` per row. See `regenerate.rs` at the top for how to run it.

use openssl::ecdsa::EcdsaSig;

use super::cases::FIXTURES;
use super::model::Encoding;
use super::{MESSAGE, fixture_path, pkeyutl_options};
use crate::cli::{Cli, arg};
use crate::regenerate::write;

pub fn signatures(cli: &Cli, written: &mut Vec<String>) -> Result<(), String> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let message = dir.path().join("message");
    std::fs::write(&message, MESSAGE).expect("the message is written");

    for fixture in FIXTURES {
        let out = fixture_path(fixture);
        if out.exists() {
            continue;
        }
        let private = fixture.key.private_path();
        let mut command = vec![
            "pkeyutl",
            "-sign",
            "-inkey",
            arg(&private),
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            arg(&message),
            "-out",
            arg(&out),
        ];
        command.extend(pkeyutl_options(&fixture.scheme));
        write(cli, &out, &command)?;
        if let Encoding::P1363 { scalar } = fixture.scheme.encoding {
            let der = std::fs::read(&out).expect("the signature is read back");
            std::fs::write(&out, der_to_p1363(&der, scalar)).expect("the signature is rewritten");
        }
        written.push(fixture.name.to_string());
    }
    Ok(())
}

/// Convert a DER `Ecdsa-Sig-Value` to fixed-width `r || s`.
fn der_to_p1363(der: &[u8], scalar: usize) -> Vec<u8> {
    let signature = EcdsaSig::from_der(der).expect("the command line writes DER");
    let width = i32::try_from(scalar).expect("a scalar fits an i32");
    let mut out = signature
        .r()
        .to_vec_padded(width)
        .expect("r fits the scalar");
    out.extend(
        signature
            .s()
            .to_vec_padded(width)
            .expect("s fits the scalar"),
    );
    out
}
