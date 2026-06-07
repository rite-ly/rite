//! Integration tests for the templated renderers.

use rite_render::{Branding, Theme, render_report, render_script, validate_accent};
use std::path::PathBuf;

fn resolve(rel: &str) -> rite_model::Ceremony {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let (ceremony, diags) = rite_resolver::analyze(&path, None);
    ceremony.unwrap_or_else(|| panic!("failed to resolve {rel}: {diags:?}"))
}

#[test]
fn script_renders_expected_structure() {
    let ceremony = resolve("examples/showcase/demo.rite.yaml");
    let html = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"), "missing doctype");
    assert!(html.contains("Root Signing Key Ceremony"));
    assert!(html.contains("Crypto Officer"));
    // Role abbreviation badge.
    assert!(html.contains("role-abbrev"));
    // Hand-recorded fingerprint and signature blocks.
    assert!(html.contains("fingerprint-record"));
    assert!(html.contains("signature-block"));
    // Every step label is present.
    for label in ["1", "2", "3", "4", "5", "6"] {
        assert!(html.contains(&format!(">{label}</td>")));
    }
}

#[test]
fn named_acts_render_act_headers() {
    let ceremony = resolve("examples/pki/root_ca_software.rite.yaml");
    let html = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    assert!(
        html.contains("act-header"),
        "named acts should emit act headers"
    );
}

#[test]
fn branding_injects_accent_and_name() {
    let ceremony = resolve("examples/showcase/demo.rite.yaml");
    let branding =
        Branding::from_inputs(Some("Acme Corp".to_string()), None, Some("#1F3A5F")).unwrap();
    let html = render_script(&ceremony, &branding, Theme::Formal).unwrap();
    // Accent is normalized to lowercase and injected as a CSS variable.
    assert!(html.contains("--accent: #1f3a5f"));
    assert!(html.contains("brand-name"));
    assert!(html.contains("Acme Corp"));
}

#[test]
fn accent_validation_rejects_non_hex() {
    assert!(validate_accent("#1f3a5f").is_ok());
    assert!(validate_accent("#ABC").is_ok());
    assert!(validate_accent("red").is_err());
    assert!(validate_accent("#12345").is_err());
    assert!(validate_accent("#xyzxyz").is_err());
    // No CSS injection through the accent value.
    assert!(validate_accent("#fff; } body { display:none").is_err());
}

#[test]
fn long_instructions_render_as_paragraphs_and_bullets() {
    let ceremony = resolve("examples/showcase/offline_backup.rite.yaml");
    let html = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    // Structured prose, not a run-on cell.
    assert!(html.contains("<ul class=\"prose-list\">"));
    assert!(html.contains("<li>Wi-Fi and Bluetooth radios are disabled in firmware</li>"));
    // A multi-paragraph instruction yields more than one <p> in the action cell.
    assert!(html.contains(
        "<p>Verify each of the following aloud, and have a witness confirm each before continuing:</p>"
    ));
    // The literal bullet markers must not leak through as plain text.
    assert!(!html.contains("- All wired network interfaces"));
}

#[test]
fn report_renders() {
    let data = rite_render::report::build_report_data(
        std::iter::empty::<(chrono::DateTime<chrono::Utc>, &rite_model::StepFact)>(),
        "sha256:deadbeef",
    );
    let html = render_report(&data, &Branding::default(), Theme::Formal).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("Ceremony Report"));
    assert!(html.contains("report-footer"));
    assert!(html.contains("Transcript fingerprint"));
}
