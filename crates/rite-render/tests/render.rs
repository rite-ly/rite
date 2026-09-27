//! Integration tests for the templated renderers.

use rite_render::{
    Branding, Theme, render_report, render_script, render_worksheets, validate_accent,
};
use std::path::PathBuf;

fn resolve(rel: &str) -> rite_model::Ceremony {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let (ceremony, diags) = rite_resolver::analyze(&path, None);
    ceremony.unwrap_or_else(|| panic!("failed to resolve {rel}: {diags:?}"))
}

/// Snapshot a rendered document with the wall-clock timestamp and the release
/// version normalized, so a diff only ever means a real rendering change, not a
/// different run time or release. Only the report's `started_at` fallback
/// (`Utc::now()` when there are no facts) is nondeterministic; fixture-supplied
/// dates render literally so the snapshot still guards how they are formatted.
fn assert_html_snapshot(name: &str, html: &str) {
    insta::with_settings!({filters => vec![
        (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", "[DATETIME]"),
        (r"Rite v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", "Rite v[VERSION]"),
    ]}, {
        insta::assert_snapshot!(name, html);
    });
}

#[test]
fn script_demo_snapshot() {
    // The full script is the contract participants follow by hand: structure,
    // step numbering, role badges, and the fingerprint/signature blocks.
    let ceremony = resolve("examples/showcase/demo.rite.yaml");
    let html = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    assert_html_snapshot("script_demo", &html);
}

#[test]
fn script_named_acts_snapshot() {
    // root_ca uses named acts, which render as act headers; the snapshot guards
    // the whole structure, not just their presence.
    let ceremony = resolve("examples/pki/root_ca_software.rite.yaml");
    let html = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    assert_html_snapshot("script_named_acts", &html);
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

/// A `reveal` step gets a page in the worksheets document: rows of boxes,
/// one per character the person writes, the parity cells at the end of
/// each row, the note. The script itself carries no sheet.
#[test]
fn a_reveal_step_gets_a_worksheet_page_shaped_by_its_format() {
    let ceremony = resolve("examples/showcase/split_and_combine.rite.yaml");
    let html = render_worksheets(&ceremony, &Branding::default(), Theme::Formal)
        .unwrap()
        .expect("the example writes a share by hand");
    assert!(html.contains("Recovery share 3"));
    assert!(html.contains("Write in block capitals."));
    assert!(!html.contains("Step 2"), "the sheet names no step");
    // A 32-byte secret is a 35-byte share, 56 base-32 characters in two
    // rows of 28, each with 4 of parity: 64 boxes, exact since the length
    // was given.
    assert_eq!(html.matches("<span class=\"ws-box\"></span>").count(), 64);
    assert_eq!(html.matches("<div class=\"ws-line\">").count(), 2);
    assert_eq!(html.matches("class=\"ws-group ws-parity\"").count(), 2);
    assert!(!html.contains("Use as many rows"));

    let script = render_script(&ceremony, &Branding::default(), Theme::Formal).unwrap();
    assert!(!script.contains("<span class=\"ws-box\">"));

    let none = resolve("examples/showcase/encrypt_and_decrypt.rite.yaml");
    assert!(
        render_worksheets(&none, &Branding::default(), Theme::Formal)
            .unwrap()
            .is_none()
    );
}

/// A share typed back with `enter_share` is a share as much as one a
/// split made, so a sheet that shows it again has the share's boxes.
#[test]
fn a_typed_back_share_shown_again_gets_the_share_s_boxes() {
    let ceremony = resolve("crates/rite-render/tests/fixtures/reissue_a_sheet.rite.yaml");
    let html = render_worksheets(&ceremony, &Branding::default(), Theme::Formal)
        .unwrap()
        .expect("the fixture writes a share by hand");
    assert_eq!(html.matches("<span class=\"ws-box\"></span>").count(), 64);
}

#[test]
fn report_snapshot() {
    let data = rite_render::report::build_report_data(
        std::iter::empty::<(chrono::DateTime<chrono::Utc>, &rite_model::StepFact)>(),
        "sha256:deadbeef",
    );
    let html = render_report(&data, &Branding::default(), Theme::Formal).unwrap();
    assert_html_snapshot("report_empty", &html);
}
