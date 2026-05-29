//! Test-only fixtures and rendering helpers. Used to snapshot the TUI
//! into plain text via ratatui's [`TestBackend`], so the view module can
//! be inspected without a live terminal.
//!
//! Run a specific scene with:
//! ```text
//! cargo test -p rite-tui preview:: -- --nocapture
//! ```

use chrono::{DateTime, Local, TimeZone};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;

use rite_model::{MaterialId, Prompt, StepId, ValidatorSpec};
use rite_runtime::{
    BackendVersion, BuildInfo, Disk, Environment, HostInfo, Icon, MaterialOverview,
    MaterialOverviewKind, PromptId, SystemInfo,
};

use crate::model::{LogLine, Model, PendingPrompt, Screen, StepTab, StepView};
use crate::view::view;

/// Build a `DateTime<Local>` on the canonical preview date.
fn at(h: u32, m: u32, s: u32) -> DateTime<Local> {
    Local
        .with_ymd_and_hms(2026, 5, 25, h, m, s)
        .single()
        .expect("valid local time")
}

/// Construct an entry with explicit step and timestamp, bypassing
/// `Model::push_entry` so fixtures stay decoupled from the live clock
/// and the `current_step` field on the model.
fn entry(icon: Icon, text: &str, step: &str, at: DateTime<Local>) -> LogLine {
    LogLine::Entry {
        icon,
        text: text.to_string(),
        step: Some(step.to_string()),
        at,
    }
}

/// Pre-ceremony model: the Overview tab is current, metadata has been
/// populated by `CeremonyStarted`, and the ceremony-start `Continue`
/// prompt is pending. No step has begun yet.
fn sample_overview() -> Model {
    let mut m = Model::new();
    m.now = at(14, 32, 10);
    m.ceremony_name = Some("Root CA Key Generation".to_string());
    // Mirror what a YAML `description: |` literal block produces: a
    // multi-line string where authors break lines for source readability
    // (single \n = soft break, folded to a space) and use blank lines
    // (\n\n) for explicit paragraph boundaries. The Markdown convention.
    m.ceremony_description = Some(
        "Generate the offline root CA keypair on an air-gapped machine.\n\
         The private key is wrapped with a transport public key and stored\n\
         as an encrypted backup.\n\
         \n\
         The keyholder of the transport private key is the sole custodian\n\
         of the wrapped backup."
            .to_string(),
    );
    m.ceremony_step_count = Some(12);
    m.ceremony_materials = vec![
        MaterialOverview {
            id: MaterialId::new("yubikey_primary"),
            title: Some("YubiKey 5C - primary".to_string()),
            description: Some(
                "Holds the long-term signing key. Stored in safe deposit\n\
                 box A-12 between ceremonies."
                    .to_string(),
            ),
            kind: MaterialOverviewKind::physical(Some("SN-15832119".to_string()), Some(1)),
        },
        MaterialOverview {
            id: MaterialId::new("yubikey_backup"),
            title: Some("YubiKey 5C - backup".to_string()),
            description: None,
            kind: MaterialOverviewKind::physical(Some("SN-15832120".to_string()), Some(1)),
        },
        MaterialOverview {
            id: MaterialId::new("policy_template"),
            title: None,
            description: Some("X.509 policy template.".to_string()),
            kind: MaterialOverviewKind::Digital,
        },
    ];
    m.pending_prompt = Some(PendingPrompt {
        prompt_id: PromptId::new(0),
        prompt: Prompt::Continue {
            hint: Some("Press Enter to start the ceremony".to_string()),
        },
        input: String::new(),
        rejection: None,
    });
    m
}

/// Build a realistic mid-ceremony model with a few log lines and an
/// active step. No pending prompt.
fn sample_running() -> Model {
    let mut m = Model::new();
    m.screen = Screen::Step {
        tab: StepTab::Ceremony,
    };
    // Pin the clock so previews are deterministic. Even second → colon
    // visible; switch to an odd second in a dedicated test if you want
    // to inspect the blink-off state.
    m.now = at(14, 32, 10);
    m.ceremony_name = Some("Root CA Key Generation".to_string());
    m.current_step = Some(StepView {
        id: StepId::new("verify_time"),
        label: "1.1".to_string(),
        role_name: "Crypto Officer".to_string(),
    });
    m.push_log(LogLine::StepDivider {
        label: "1.1".to_string(),
        role_name: "Crypto Officer".to_string(),
    });
    m.push_log(entry(
        Icon::Info,
        "System clock reads 2026-05-25 14:32:11 UTC",
        "1.1",
        at(14, 32, 4),
    ));
    m.push_log(entry(
        Icon::Checkmark,
        "Operator confirmed wall clock matches",
        "1.1",
        at(14, 32, 6),
    ));
    m.push_log(entry(
        Icon::Info,
        "Loaded backend: openssl",
        "1.1",
        at(14, 32, 8),
    ));
    m
}

/// Same as [`sample_running`] but with a pending text prompt.
fn sample_with_prompt() -> Model {
    let mut m = sample_running();
    m.pending_prompt = Some(PendingPrompt {
        prompt_id: PromptId::new(1),
        prompt: Prompt::Text {
            label: "Enter the witness full name".to_string(),
            validator: ValidatorSpec::NonEmpty,
        },
        input: "Bob Jo".to_string(),
        rejection: None,
    });
    m
}

/// System tab: build/host identity header plus a small disk inventory,
/// as populated by the `SystemInfo` and `Environment` signals.
fn sample_system() -> Model {
    let mut m = sample_running();
    m.system_info = Some(SystemInfo {
        build: BuildInfo {
            version: "0.2.0".to_string(),
            commit: "a1b2c3d".to_string(),
            commit_date: "2026-05-20".to_string(),
            build_date: "2026-05-25".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            profile: "release".to_string(),
            features: "attestation,crypto,openssl,pki,render,verification".to_string(),
            rustc: "1.95.0".to_string(),
        },
        host: HostInfo {
            arch: "aarch64".to_string(),
            os: Some("Darwin".to_string()),
            os_version: Some("macOS 15.4".to_string()),
            kernel_version: None,
            hostname: Some("ceremony-air-gap".to_string()),
            machine_id: None,
            cpu_model: None,
            hardening: None,
        },
        backends: vec![BackendVersion {
            provider: "openssl".to_string(),
            version: "OpenSSL 3.6.2 7 Apr 2026".to_string(),
            source: Some("system".to_string()),
        }],
    });
    m.environment = Some(Environment {
        disks: vec![
            Disk {
                name: "disk0s1".to_string(),
                mount_point: "/".to_string(),
                file_system: Some("apfs".to_string()),
                total_bytes: 994_662_584_320,
                available_bytes: 612_339_499_008,
                removable: false,
                kind: Some("SSD".to_string()),
            },
            Disk {
                name: "disk4s1".to_string(),
                mount_point: "/Volumes/CEREMONY".to_string(),
                file_system: Some("exfat".to_string()),
                total_bytes: 31_914_983_424,
                available_bytes: 31_900_000_000,
                removable: true,
                kind: None,
            },
        ],
    });
    m.screen = Screen::Step {
        tab: StepTab::System,
    };
    m
}

/// Render `model` into a width×height buffer and return its plain-text
/// dump, one row per line.
fn render(model: &Model, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend constructs");
    terminal
        .draw(|frame| {
            view(model, frame);
        })
        .expect("test backend draws");
    buffer_to_string(terminal.backend().buffer())
}

/// Concatenate the buffer's cell symbols row by row. Styling is dropped:
/// this is for layout / content inspection, not color.
fn buffer_to_string(buf: &Buffer) -> String {
    let area = buf.area();
    let row_width = usize::from(area.width).saturating_add(1);
    let mut out = String::with_capacity(row_width.saturating_mul(usize::from(area.height)));
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
fn preview_overview_tab() {
    let m = sample_overview();
    let out = render(&m, 100, 24);
    eprintln!("--- overview tab / ceremony-start prompt (100x24) ---\n{out}");
}

#[test]
fn preview_step_no_prompt() {
    let m = sample_running();
    let out = render(&m, 100, 24);
    eprintln!("--- step / no prompt (100x24) ---\n{out}");
}

#[test]
fn preview_step_with_prompt() {
    let m = sample_with_prompt();
    let out = render(&m, 100, 24);
    eprintln!("--- step / pending prompt (100x24) ---\n{out}");
}

#[test]
fn preview_confirm_prompt() {
    let mut m = sample_running();
    m.pending_prompt = Some(PendingPrompt {
        prompt_id: PromptId::new(2),
        prompt: Prompt::Confirm {
            question: "Did the device beep twice?".to_string(),
            default: Some(true),
        },
        input: String::new(),
        rejection: None,
    });
    let out = render(&m, 100, 24);
    eprintln!("--- step / confirm prompt (100x24) ---\n{out}");
}

#[test]
fn preview_deviations_tab() {
    let mut m = sample_running();
    m.deviations.push(crate::model::DeviationView {
        step: Some(StepId::new("verify_time")),
        text: "Operator paused to verify external clock against atomic source".to_string(),
        at: at(14, 32, 6),
    });
    m.screen = Screen::Step {
        tab: StepTab::Deviations,
    };
    let out = render(&m, 100, 24);
    eprintln!("--- deviations tab (100x24) ---\n{out}");
}

#[test]
fn preview_deviations_empty() {
    let mut m = sample_running();
    m.screen = Screen::Step {
        tab: StepTab::Deviations,
    };
    let out = render(&m, 100, 24);
    eprintln!("--- deviations tab / empty (100x24) ---\n{out}");
}

#[test]
fn preview_deviation_modal() {
    let mut m = sample_running();
    m.screen = Screen::DeviationModal {
        input: "Clock drift of 3s observed against atomic reference".to_string(),
    };
    let out = render(&m, 100, 24);
    eprintln!("--- deviation modal (100x24) ---\n{out}");
}

#[test]
fn preview_system_tab() {
    let m = sample_system();
    let out = render(&m, 100, 24);
    eprintln!("--- system tab (100x24) ---\n{out}");
}

#[test]
fn preview_ceremony_scrolled() {
    let mut m = sample_running();
    for n in 0..30 {
        m.push_log(entry(
            Icon::Info,
            &format!("Filler line {n}"),
            "1.1",
            at(14, 32, 10),
        ));
    }
    m.log_scroll = 3;
    let out = render(&m, 100, 24);
    eprintln!("--- ceremony tab / scrolled (100x24) ---\n{out}");
}

#[test]
fn preview_step_with_history() {
    // Multi-step history within an act. Past entries appear muted and
    // past dividers stay visible but in footer gray; the current step's
    // divider and content render in full color.
    let mut m = sample_running();
    m.push_log(entry(
        Icon::Checkmark,
        "Initial clock sync recorded",
        "1.1",
        at(14, 32, 9),
    ));
    m.push_log(LogLine::StepDivider {
        label: "1.2".to_string(),
        role_name: "Crypto Officer".to_string(),
    });
    m.push_log(entry(
        Icon::Info,
        "Inserted YubiKey in slot 0",
        "1.2",
        at(14, 32, 13),
    ));
    m.push_log(entry(
        Icon::Checkmark,
        "Witness confirmed device serial",
        "1.2",
        at(14, 32, 18),
    ));
    m.push_log(LogLine::ActDivider {
        label: "Attestation".to_string(),
    });
    m.push_log(LogLine::StepDivider {
        label: "2.1".to_string(),
        role_name: "Witness".to_string(),
    });
    m.push_log(entry(
        Icon::Info,
        "Awaiting attestation",
        "2.1",
        at(14, 32, 22),
    ));
    m.current_step = Some(StepView {
        id: StepId::new("attest"),
        label: "2.1".to_string(),
        role_name: "Witness".to_string(),
    });
    let out = render(&m, 100, 24);
    eprintln!("--- ceremony tab / multi-step history (100x24) ---\n{out}");
}

#[test]
fn preview_completed() {
    let mut m = sample_running();
    m.screen = Screen::Completed {
        fingerprint: Some(
            "sha256:9f3a2b1c4d5e6f70 8192a3b4c5d6e7f8 0123456789abcdef fedcba9876543210"
                .to_string(),
        ),
    };
    let out = render(&m, 100, 24);
    eprintln!("--- completed (100x24) ---\n{out}");
}
