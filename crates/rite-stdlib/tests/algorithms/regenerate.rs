//! Write the fixtures the tables name and the disk lacks, with the `openssl`
//! command line.
//!
//! ```sh
//! RITE_REGENERATE_FIXTURES=1 cargo test -p rite-stdlib --test algorithms
//! ```
//!
//! A committed file stays as it is, so adding a row or a key type changes
//! nothing else. To rewrite a file, delete it first.
//!
//! A family's directory records the version of the command line that wrote
//! its fixtures, as `MADE_WITH`, one line per run that wrote any.

use std::path::Path;

use crate::FAMILIES;
use crate::cli::{Cli, arg};
use crate::keys::{Generate, TestKey, keys_dir};
use crate::shape::{CERTIFIED, certificate_path, certificates_dir};

pub fn run() {
    let cli = Cli::get().expect("regenerating the fixtures needs the openssl command line");
    keys(cli);
    certificates(cli);
    let version = String::from_utf8(must(cli.run(&["version"])))
        .expect("the version is text")
        .trim()
        .to_string();
    for family in FAMILIES {
        std::fs::create_dir_all(family.dir()).expect("the fixture directory is created");
        let mut written = Vec::new();
        let outcome = (family.regenerate)(cli, &mut written);
        // Before a failure stops the run: what it wrote stays, and later runs
        // leave it alone.
        if !written.is_empty() {
            let made_with = family.dir().join("MADE_WITH");
            let before = std::fs::read_to_string(&made_with).unwrap_or_default();
            let record = format!("{before}{}: {version}\n", written.join(", "));
            std::fs::write(made_with, record).expect("MADE_WITH is written");
        }
        must(outcome);
    }
}

/// Run `openssl` with `args`, which write `out`. A failed run can leave an
/// empty file, and a file on disk counts as done, so it does not stay.
pub fn write(cli: &Cli, out: &Path, args: &[&str]) -> Result<(), String> {
    cli.run(args).map(|_| ()).map_err(|e| {
        // A run that failed before opening `out` left nothing to remove.
        std::fs::remove_file(out).ok();
        format!("{}: {e}", out.display())
    })
}

/// Make the keys that are missing, in `TestKey::ALL` order, so a key made from
/// another comes after it. Each half is looked at on its own, because making
/// a private half again would replace the key.
fn keys(cli: &Cli) {
    std::fs::create_dir_all(keys_dir()).expect("the keys directory is created");
    for key in TestKey::ALL.iter().copied() {
        if !key.private_path().exists() {
            must(private_half(cli, key));
        }
        if !key.is_symmetric() && !key.public_path().exists() {
            must(public_half(cli, key));
        }
    }
}

fn private_half(cli: &Cli, key: TestKey) -> Result<(), String> {
    let private = key.private_path();
    match key.generate() {
        Generate::Genpkey(args) => {
            let mut command = vec!["genpkey"];
            command.extend_from_slice(args);
            command.extend_from_slice(&["-outform", "DER", "-out", arg(&private)]);
            write(cli, &private, &command)
        }
        Generate::Compressed(base) => {
            let dir = tempfile::tempdir().expect("a temporary directory");
            let sec1 = dir.path().join("sec1.der");
            let base_private = base.private_path();
            // `ec` writes the compressed point; `pkcs8` puts the result back
            // in the form `import_key` takes, point and all.
            cli.run(&[
                "ec",
                "-inform",
                "DER",
                "-in",
                arg(&base_private),
                "-conv_form",
                "compressed",
                "-outform",
                "DER",
                "-out",
                arg(&sec1),
            ])?;
            write(
                cli,
                &private,
                &[
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-inform",
                    "DER",
                    "-in",
                    arg(&sec1),
                    "-outform",
                    "DER",
                    "-out",
                    arg(&private),
                ],
            )
        }
        Generate::Random(bytes) => write(
            cli,
            &private,
            &["rand", "-out", arg(&private), &bytes.to_string()],
        ),
    }
}

/// The SPKI of a keypair, from its private half. Only `ec` writes a compressed
/// point, and it reads the key the compressed one was made from.
fn public_half(cli: &Cli, key: TestKey) -> Result<(), String> {
    let public = key.public_path();
    if let Generate::Compressed(base) = key.generate() {
        return write(
            cli,
            &public,
            &[
                "ec",
                "-inform",
                "DER",
                "-in",
                arg(&base.private_path()),
                "-conv_form",
                "compressed",
                "-pubout",
                "-outform",
                "DER",
                "-out",
                arg(&public),
            ],
        );
    }
    write(
        cli,
        &public,
        &[
            "pkey",
            "-inform",
            "DER",
            "-in",
            arg(&key.private_path()),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            arg(&public),
        ],
    )
}

/// A self-signed certificate for each key the shape tables use, so a key can
/// arrive as a certificate.
fn certificates(cli: &Cli) {
    std::fs::create_dir_all(certificates_dir()).expect("the certificates directory is created");
    for key in CERTIFIED.iter().copied() {
        let out = certificate_path(key);
        if out.exists() {
            continue;
        }
        must(write(
            cli,
            &out,
            &[
                "x509",
                "-new",
                "-subj",
                &format!("/CN={}", key.stem()),
                "-key",
                arg(&key.private_path()),
                "-keyform",
                "DER",
                "-days",
                "36500",
                "-outform",
                "DER",
                "-out",
                arg(&out),
            ],
        ));
    }
}

fn must<T>(result: Result<T, String>) -> T {
    result.unwrap_or_else(|e| panic!("{e}"))
}
