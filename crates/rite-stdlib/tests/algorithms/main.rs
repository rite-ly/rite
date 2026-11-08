//! The algorithm matrix: what Rite's cryptographic steps do with the key
//! types and forms listed in its tables, including ones Rite does not
//! support.
//!
//! The steps come in families, a family being the steps that write one kind
//! of artifact and the steps that read it: `wrapping/` (`wrap_key`,
//! `encrypt_data`, `unwrap_key`, `decrypt_data`) and `signatures/`
//! (`sign_data`, `verify_signature`). Each has its rows in its `cases.rs`. A
//! row states an outcome per policy level: what is written, what is read, or
//! the refusal, where it happens and what it says. A refusal is tested as
//! strictly as a success, so a form Rite starts to support fails its row
//! until the row says so, and the tables stay a true account of what Rite
//! does.
//!
//! Every case is its own test, named after its row:
//!
//! ```sh
//! cargo test -p rite-stdlib --test algorithms                 # all of it
//! cargo test -p rite-stdlib --test algorithms -- kari          # one form
//! cargo test -p rite-stdlib --test algorithms -- sign_data     # one step
//! cargo test -p rite-stdlib --test algorithms -- --ignored     # what this build skips, and why
//! ```
//!
//! A case this build cannot run (a key the linked OpenSSL cannot read, an
//! `openssl` command line too old to check the output) is skipped with the
//! reason as its label, never passed. The fixtures, and how to regenerate
//! them, are described in `fixtures/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod cli;
mod coverage;
mod family;
mod harness;
mod keys;
mod outcome;
mod regenerate;
mod session;
mod shape;
mod signatures;
mod wrapping;

use family::Family;

/// Every family the matrix tests. A new one is a module and a line here.
pub const FAMILIES: &[Family] = &[wrapping::FAMILY, signatures::FAMILY];

fn main() {
    if std::env::var_os("RITE_REGENERATE_FIXTURES").is_some() {
        regenerate::run();
        return;
    }
    let arguments = libtest_mimic::Arguments::from_args();
    let mut all: Vec<_> = FAMILIES
        .iter()
        .flat_map(|family| (family.trials)())
        .collect();
    let shared = coverage::trials(&all);
    all.extend(shared);
    libtest_mimic::run(&arguments, all).exit();
}
