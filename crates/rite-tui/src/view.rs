//! Pure `view(model, frame)`. Renders the current model into a ratatui
//! frame. Never mutates the model, never touches I/O.

use chrono::{DateTime, Local, Timelike};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use rite_model::Prompt;
use rite_runtime::{Icon, MaterialOverview, MaterialOverviewKind};

use crate::model::{LogLine, Model, Screen, StepTab};

/// Shared color palette. Three muted tones plus the terminal-default
/// text color: titles, borders, and the footer all step back so the
/// content of each step is what the operator's eye lands on first.
mod theme {
    use ratatui::style::{Color, Style};

    /// Body text — terminal default foreground.
    pub const TEXT: Color = Color::Reset;
    /// Headings: ceremony name, tabs, box titles, log step dividers, clock.
    /// Muted blue-grey, deliberately less prominent than body text.
    pub const TITLE: Color = Color::Rgb(110, 138, 190);
    /// Box borders. `Color::DarkGray` is ANSI 8, the designated muted /
    /// secondary companion to the default foreground. It auto-adapts to
    /// the terminal theme: lighter on dark backgrounds, darker on light
    /// backgrounds, always distinct from default text (unlike
    /// `Color::Gray` which is ANSI 7 and aliases the default fg).
    pub const BORDER: Color = Color::DarkGray;
    /// Footer hint line. Same grey as borders.
    pub const FOOTER: Color = Color::DarkGray;

    pub fn text() -> Style {
        Style::default().fg(TEXT)
    }
    pub fn title() -> Style {
        Style::default().fg(TITLE)
    }
    pub fn border() -> Style {
        Style::default().fg(BORDER)
    }
    pub fn footer() -> Style {
        Style::default().fg(FOOTER)
    }
}

/// Spinner animation frames cycled by [`spinner_glyph`] for `Icon::Spinner`.
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Tab labels, rendered as a left-aligned pill row.
const TAB_LABELS: [&str; 4] = [" Overview ", " Ceremony ", " Deviations ", " System "];
const TAB_DIVIDER: &str = "│";

/// Static glyph for a non-spinner [`Icon`]. The TUI owns its glyph mapping;
/// the runtime does not provide one so frontends can choose their own.
fn icon_glyph(icon: Icon) -> &'static str {
    match icon {
        Icon::Spinner => SPINNER_FRAMES[0],
        Icon::Checkmark => "✓",
        Icon::Cross => "✗",
        // Info/Warning use ASCII so they align with ✓/✗ and never render as
        // emoji. The symbol forms (ℹ U+2139, ⚠ U+26A0) draw as double-width
        // colour emoji in some renderers (e.g. agg), and the circled/triangle
        // alternatives sit at a different cell width and misalign the column.
        Icon::Info => "i",
        Icon::Warning => "!",
    }
}

/// Render the current model into the given frame. Returns the clamped
/// `log_scroll` value the render actually used so the runtime loop can
/// cap `model.log_scroll` to the real max (the user's Up key keeps
/// growing the counter past the visible top otherwise, then takes that
/// many Down presses before the view moves again).
pub fn view(model: &Model, frame: &mut Frame<'_>) -> usize {
    let area = frame.area();
    let [header_area, body_area, footer_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header (no divider underneath)
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .areas(area);

    render_header(model, frame, header_area);
    let applied_scroll = render_body(model, frame, body_area);
    render_footer(model, frame, footer_area);
    applied_scroll
}

/// The brand marker that opens both the header and the tabs row, giving them
/// a shared left gutter. A full block, not content, in the muted TITLE color
/// so it reads as part of the heading line.
fn brand_marker() -> Span<'static> {
    Span::styled("█ ", theme::title())
}

fn render_header(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let title = model
        .ceremony_name
        .as_deref()
        .unwrap_or("starting ceremony");
    let version = concat!("Rite v", env!("CARGO_PKG_VERSION"));
    let version_width = u16::try_from(version.chars().count()).unwrap_or(0);

    let [left_area, right_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(version_width)]).areas(area);

    let left = Line::from(vec![
        brand_marker(),
        Span::styled(title, theme::title().add_modifier(Modifier::BOLD)),
    ]);
    frame.render_widget(Paragraph::new(left), left_area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(version, theme::title()))),
        right_area,
    );
}

fn render_body(model: &Model, frame: &mut Frame<'_>, area: Rect) -> usize {
    match &model.screen {
        Screen::Step { tab } => render_step_screen(model, *tab, frame, area),
        Screen::DeviationModal { input } => {
            render_deviation_modal(input, frame, area);
            model.log_scroll
        }
        Screen::AbortConfirm => {
            render_abort_confirm(frame, area);
            model.log_scroll
        }
        Screen::Completed { fingerprint, .. } => {
            render_completed(fingerprint.as_deref(), frame, area);
            model.log_scroll
        }
        Screen::Failed { reason } => {
            render_failed(reason, frame, area);
            model.log_scroll
        }
        Screen::Aborted => {
            render_aborted(frame, area);
            model.log_scroll
        }
    }
}

fn render_step_screen(model: &Model, tab: StepTab, frame: &mut Frame<'_>, area: Rect) -> usize {
    let [tabs_area, content_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .areas(area);

    render_tabs_row(model, tab, frame, tabs_area);

    match tab {
        StepTab::Overview => {
            render_overview(model, frame, content_area);
            model.log_scroll
        }
        StepTab::Ceremony => render_ceremony(model, frame, content_area),
        StepTab::Deviations => {
            render_deviations(model, frame, content_area);
            model.log_scroll
        }
        StepTab::System => {
            render_system(model, frame, content_area);
            model.log_scroll
        }
    }
}

/// One-line tabs row with the wall clock right-aligned. The clock has a
/// blinking colon (off on odd seconds) so the operator sees a heartbeat
/// even when the executor is idle.
fn render_tabs_row(model: &Model, tab: StepTab, frame: &mut Frame<'_>, area: Rect) {
    let clock = clock_text(&model.now);
    let clock_width = u16::try_from(clock.chars().count()).unwrap_or(0);

    // Tabs left-aligned under the ceremony title; the clock sits on the
    // right, mirroring the header's title/version split. Nothing centered.
    let [tabs_area, clock_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(clock_width)]).areas(area);

    let selected = match tab {
        StepTab::Overview => 0,
        StepTab::Ceremony => 1,
        StepTab::Deviations => 2,
        StepTab::System => 3,
    };
    // Lead with the same brand marker as the header so the tabs sit under
    // the ceremony title with a left gutter, rather than flush at column 0.
    let mut spans: Vec<Span<'_>> = vec![brand_marker()];
    for (i, label) in TAB_LABELS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(TAB_DIVIDER, theme::border()));
        }
        let style = if i == selected {
            theme::title().add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            theme::title()
        };
        spans.push(Span::styled(*label, style));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), tabs_area);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(clock, theme::title()))).alignment(Alignment::Right),
        clock_area,
    );
}

/// We use ISO 8601 and a numeric offset rather than a locale-formatted
/// date and time-zone name to stay deterministic and portable;
/// `chrono`'s `unstable-locales` feature (or `sys-locale`) is the route
/// if locale-aware formatting becomes a real requirement.
fn clock_text(now: &DateTime<Local>) -> String {
    let sep = if now.second().is_multiple_of(2) {
        ':'
    } else {
        ' '
    };
    let date = now.format("%Y-%m-%d");
    let offset = now.format("%:z");
    format!("{date} {:02}{sep}{:02} {offset}", now.hour(), now.minute())
}

fn render_deviation_modal(input: &str, frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Log a deviation",
            theme::text().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Describe what happened, then press Enter."),
        Line::from(""),
        Line::from(format!("> {input}")),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

fn render_abort_confirm(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Abort the ceremony?",
            theme::text().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "The current step will be interrupted at the next safe point \
             and recorded as aborted in the transcript.",
        ),
        Line::from(""),
        Line::from(Span::styled(
            "y: abort  ·  n / Esc: cancel",
            theme::footer(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

/// Ceremony tab: timestamped table of log entries with past-step
/// dimming, scrollable, plus the pending prompt pinned at the bottom.
/// This is the operator's working surface during execution.
fn render_ceremony(model: &Model, frame: &mut Frame<'_>, area: Rect) -> usize {
    // Always reserve the prompt panel, even with no pending prompt, so the
    // log area keeps a constant size: otherwise the box resizes and flickers
    // each time a prompt appears or clears while an action runs.
    let prompt_height = model
        .pending_prompt
        .as_ref()
        .map_or(EMPTY_PROMPT_HEIGHT, prompt_block_height);
    let [logs_area, prompt_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(prompt_height)])
        .areas(area);
    let applied = render_ceremony_table(model, frame, logs_area);
    match &model.pending_prompt {
        Some(pending) => render_prompt(pending, frame, prompt_area),
        None => render_empty_prompt(frame, prompt_area),
    }
    applied
}

/// Height of the placeholder prompt box: one content line plus borders,
/// matching a single-line prompt so the log area doesn't jump when most
/// prompts appear.
const EMPTY_PROMPT_HEIGHT: u16 = 3;

/// Render the empty placeholder where the prompt box sits, holding the
/// layout steady while no prompt is pending.
fn render_empty_prompt(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Paragraph::new("").block(plain_block()), area);
}

/// Conservative fixed height for the prompt panel, including its border.
fn prompt_block_height(pending: &crate::model::PendingPrompt) -> u16 {
    let content_lines: u16 = match &pending.prompt {
        Prompt::Text { .. } | Prompt::Literal { .. } | Prompt::Secret { .. } => 2,
        _ => 1,
    };
    let rejection_lines: u16 = u16::from(pending.rejection.is_some());
    // +2 for top and bottom borders.
    content_lines
        .saturating_add(rejection_lines)
        .saturating_add(2)
}

fn render_prompt(pending: &crate::model::PendingPrompt, frame: &mut Frame<'_>, area: Rect) {
    let body: Vec<Line<'_>> = match &pending.prompt {
        Prompt::Confirm { question, .. } => vec![Line::from(question.clone())],
        Prompt::Continue { hint } => vec![Line::from(
            hint.clone()
                .unwrap_or_else(|| "Press Enter to continue".to_string()),
        )],
        Prompt::Text { label, .. } | Prompt::Literal { label, .. } => vec![
            Line::from(label.clone()),
            Line::from(format!("> {}", pending.input)),
        ],
        Prompt::Secret { label } => vec![
            Line::from(label.clone()),
            Line::from(format!("> {}", "•".repeat(pending.input.len()))),
        ],
        _ => vec![Line::from("(unknown prompt type)")],
    };
    let mut lines = body;
    if let Some(reason) = &pending.rejection {
        lines.push(Line::from(Span::styled(
            format!("• {reason}"),
            Style::default().add_modifier(Modifier::ITALIC),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block().title(prompt_title(pending))),
        area,
    );
}

/// Compose the prompt box title. `Prompt` proper is shown in the muted
/// title color; the `[y/n]` hint (Confirm prompts) and the "(last
/// attempt rejected)" suffix step further back into footer gray so the
/// word `Prompt` reads as the heading and the rest as annotation.
fn prompt_title(pending: &crate::model::PendingPrompt) -> Line<'_> {
    let mut spans = vec![Span::styled("Prompt", theme::title())];
    // The submit-key hint lives here (not the footer) so the footer stays a
    // constant width while prompts come and go. Confirm shows the y/n keys;
    // typed prompts show the Enter hint; Continue carries "Press Enter…" in
    // its own body, so no title hint is needed.
    match &pending.prompt {
        Prompt::Confirm { default, .. } => {
            // The capitalized letter is the one Enter submits. With no explicit
            // default the handler submits yes (`default.unwrap_or(true)`), so
            // the hint capitalizes Y to match.
            let hint = match default {
                Some(true) | None => "Y/n",
                Some(false) => "y/N",
            };
            spans.push(Span::styled(format!(" [{hint}]"), theme::footer()));
        }
        Prompt::Text { .. } | Prompt::Literal { .. } | Prompt::Secret { .. } => {
            spans.push(Span::styled(" [Enter: submit]", theme::footer()));
        }
        _ => {}
    }
    if pending.rejection.is_some() {
        spans.push(Span::styled(" (last attempt rejected)", theme::footer()));
    }
    Line::from(spans)
}

/// Render a [`LogLine`] as a single styled line in the Ceremony table.
///
/// `Entry` becomes a `time | message` row. The owning step is carried by
/// the `StepDivider` above it (and the header's Step section), so it is not
/// repeated per line.
/// `StepDivider` and `ActDivider` become full-width section markers —
/// the dividers carry section structure (role for steps, name for acts),
/// and act dividers use a double rule to convey the act-contains-steps
/// hierarchy.
///
/// `current` selects active vs. muted styling: current-section content
/// keeps its full color; past content drops to footer gray.
fn log_table_row(line: &LogLine, tick: u64, current: bool, inner_width: u16) -> Line<'_> {
    match line {
        LogLine::Entry { icon, text, at, .. } => {
            let prefix = match icon {
                Icon::Spinner => spinner_glyph(tick),
                other => icon_glyph(*other),
            };
            let time_col = at.format("%H:%M:%S").to_string();
            let message_style = if current {
                theme::text()
            } else {
                theme::footer()
            };
            Line::from(vec![
                Span::styled(time_col, theme::footer()),
                Span::raw("  "),
                Span::styled(format!("{prefix} {text}"), message_style),
            ])
        }
        LogLine::StepDivider { label, role_name } => divider_line(
            &format!("Step {label} · {role_name}"),
            '─',
            current,
            inner_width,
        ),
        LogLine::ActDivider { label } => {
            divider_line(&format!("Act: {label}"), '═', current, inner_width)
        }
    }
}

/// Build a section divider line: `<rule> <label> <rule…>` filling
/// `inner_width` cells. `rule` controls the rule glyph (`─` for steps,
/// `═` for acts). Style is TITLE blue + bold when `current`, footer
/// gray + bold for past sections.
fn divider_line(label: &str, rule: char, current: bool, inner_width: u16) -> Line<'static> {
    let style = if current {
        theme::title().add_modifier(Modifier::BOLD)
    } else {
        theme::footer().add_modifier(Modifier::BOLD)
    };
    let middle = format!(" {label} ");
    let left = format!("{rule}{rule} ");
    let used = left.chars().count().saturating_add(middle.chars().count());
    let right_len = usize::from(inner_width).saturating_sub(used);
    let right: String = std::iter::repeat_n(rule, right_len).collect();
    Line::from(Span::styled(format!("{left}{middle}{right}"), style))
}

/// Wrap `lines` into a paragraph scrolled by `lines_from_tail` (counted
/// from the tail of the feed). Returns the paragraph plus the *clamped*
/// scroll value so callers can show a scroll indicator. The paragraph
/// is returned without a block; callers wrap it themselves.
fn scrolled_paragraph(
    lines: Vec<Line<'_>>,
    inner_width: u16,
    visible_height: u16,
    lines_from_tail: usize,
) -> (Paragraph<'_>, usize) {
    let paragraph = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
    let total = paragraph.line_count(inner_width);
    let max_scroll = total.saturating_sub(usize::from(visible_height));
    let scroll = lines_from_tail.min(max_scroll);
    let scroll_y = u16::try_from(max_scroll.saturating_sub(scroll)).unwrap_or(u16::MAX);
    (paragraph.scroll((scroll_y, 0)), scroll)
}

fn render_ceremony_table(model: &Model, frame: &mut Frame<'_>, area: Rect) -> usize {
    let inner_width = area.width.saturating_sub(2);
    let visible_height = area.height.saturating_sub(2);
    // Per-line currency:
    //  - an act/step divider is "current" iff it is the most recent of
    //    its kind — acts span multiple steps so the current act stays
    //    bright even when newer step dividers land beneath it
    //  - entries are current iff at or after the most recent boundary
    //    (a step divider if any, else the most recent act divider)
    let last_act = model
        .log
        .iter()
        .rposition(|l| matches!(l, LogLine::ActDivider { .. }));
    let last_step = model
        .log
        .iter()
        .rposition(|l| matches!(l, LogLine::StepDivider { .. }));
    let entry_boundary = last_step.or(last_act).unwrap_or(0);

    let lines: Vec<Line<'_>> = model
        .log
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let current = match line {
                LogLine::ActDivider { .. } => Some(i) == last_act,
                LogLine::StepDivider { .. } => Some(i) == last_step,
                LogLine::Entry { .. } => i >= entry_boundary,
            };
            log_table_row(line, model.tick, current, inner_width)
        })
        .collect();
    let (paragraph, applied_scroll) =
        scrolled_paragraph(lines, inner_width, visible_height, model.log_scroll);
    frame.render_widget(paragraph.block(scrollable_box(applied_scroll)), area);
    applied_scroll
}

/// `plain_block` with the standard scroll-position indicator on the
/// bottom border when the operator has scrolled back into history.
/// Tailing logs stay quiet.
fn scrollable_box(applied_scroll: usize) -> Block<'static> {
    let block = plain_block();
    if applied_scroll == 0 {
        return block;
    }
    let noun = if applied_scroll == 1 { "line" } else { "lines" };
    let label = format!(" scrolled {applied_scroll} {noun} ");
    block.title_bottom(Line::from(Span::styled(label, theme::title())).centered())
}

/// Overview tab: description, step count, declared materials. Does
/// **not** render the pending prompt; the ceremony-start `Continue` is
/// answered from the Ceremony tab, so the operator's path is "review
/// here, switch tab, confirm".
fn render_overview(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let mut lines: Vec<Line<'_>> = Vec::new();
    if let Some(desc) = &model.ceremony_description {
        lines.push(Line::from(Span::styled(
            "Description",
            theme::title().add_modifier(Modifier::BOLD),
        )));
        append_prose_paragraphs(&mut lines, desc, 0, theme::text());
        lines.push(Line::from(""));
    }
    if let Some(count) = model.ceremony_step_count {
        let noun = if count == 1 { "step" } else { "steps" };
        lines.push(Line::from(Span::styled(
            format!("{count} {noun} in this ceremony"),
            theme::footer(),
        )));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "Materials",
        theme::title().add_modifier(Modifier::BOLD),
    )));
    if model.ceremony_materials.is_empty() {
        lines.push(Line::from(Span::styled("(none declared)", theme::footer())));
    } else {
        for material in &model.ceremony_materials {
            lines.extend(material_lines(material));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

/// System tab: a static build/host identity header, then the live device
/// environment. Situational awareness for the operator during the run; none
/// of this is recorded to the transcript (the `machine_info` action covers
/// machine identity as evidence).
fn render_system(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let mut lines: Vec<Line<'_>> = Vec::new();

    if let Some(info) = &model.system_info {
        lines.push(section_heading("Build"));
        lines.push(kv_line("rite", &info.build.version));
        lines.push(kv_line("commit", &info.build.commit));
        lines.push(kv_line("built", &info.build.build_date));
        lines.push(kv_line("target", &info.build.target));
        lines.push(kv_line("profile", &info.build.profile));
        if !info.build.features.is_empty() {
            lines.push(kv_line("features", &info.build.features));
        }
        lines.push(Line::from(""));

        lines.push(section_heading("Host"));
        let os = match (&info.host.os, &info.host.os_version) {
            (Some(os), Some(v)) => format!("{os} ({v})"),
            (Some(os), None) => os.clone(),
            (None, _) => "unknown".to_string(),
        };
        lines.push(kv_line("os", &os));
        lines.push(kv_line("arch", &info.host.arch));
        if let Some(hostname) = &info.host.hostname {
            lines.push(kv_line("hostname", hostname));
        }
        lines.push(Line::from(""));

        lines.push(section_heading("Backends"));
        if info.backends.is_empty() {
            lines.push(dim_line("(none linked)"));
        } else {
            for backend in &info.backends {
                let value = match &backend.source {
                    Some(source) => format!("{} ({source})", backend.version),
                    None => backend.version.clone(),
                };
                lines.push(kv_line(&backend.provider, &value));
            }
        }
        lines.push(Line::from(""));
    } else {
        lines.push(dim_line("(system information unavailable)"));
        lines.push(Line::from(""));
    }

    lines.push(section_heading("Disks"));
    match model.environment.as_ref().map(|e| &e.disks) {
        Some(disks) if !disks.is_empty() => {
            for disk in disks {
                lines.extend(disk_lines(disk));
            }
        }
        Some(_) => lines.push(dim_line("(none detected)")),
        None => lines.push(dim_line("(not yet collected)")),
    }
    lines.push(Line::from(""));

    lines.push(section_heading("Peripherals"));
    lines.push(dim_line("(not yet collected)"));
    lines.push(Line::from(""));
    lines.push(section_heading("Network"));
    lines.push(dim_line("(not yet collected)"));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

/// A bold section heading line, styled like the Overview tab's headings.
fn section_heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        theme::title().add_modifier(Modifier::BOLD),
    ))
}

/// A dimmed standalone line (placeholders, "none" markers).
fn dim_line(text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), theme::footer()))
}

/// A `label   value` line: dimmed label in a fixed-width column, value in
/// body text.
fn kv_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<11}"), theme::footer()),
        Span::styled(value.to_string(), theme::text()),
    ])
}

/// Render one disk as a bullet heading plus a dimmed detail line.
fn disk_lines(disk: &rite_runtime::Disk) -> Vec<Line<'static>> {
    let mut head = vec![
        Span::raw("• "),
        Span::styled(
            disk.mount_point.clone(),
            theme::text().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(disk.name.clone(), theme::footer()),
    ];
    if disk.removable {
        head.push(Span::styled("  · removable", theme::footer()));
    }
    let mut detail = format!(
        "{} free of {}",
        format_bytes(disk.available_bytes),
        format_bytes(disk.total_bytes),
    );
    if let Some(fs) = &disk.file_system {
        detail.push_str(" · ");
        detail.push_str(fs);
    }
    if let Some(kind) = &disk.kind {
        detail.push_str(" · ");
        detail.push_str(kind);
    }
    vec![
        Line::from(head),
        Line::from(Span::styled(format!("  {detail}"), theme::footer())),
    ]
}

/// Human-readable byte size with binary (1024) units. Explicit thresholds
/// rather than a divide-and-count loop, to stay clear of the integer
/// arithmetic and indexing lints.
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;
    let scaled = |unit: u64| bytes as f64 / unit as f64;
    if bytes >= TIB {
        format!("{:.1} TiB", scaled(TIB))
    } else if bytes >= GIB {
        format!("{:.1} GiB", scaled(GIB))
    } else if bytes >= MIB {
        format!("{:.1} MiB", scaled(MIB))
    } else if bytes >= KIB {
        format!("{:.1} KiB", scaled(KIB))
    } else {
        format!("{bytes} B")
    }
}

/// Render one material as a heading line plus an optional dimmed
/// description, so the overview reads as a scannable bulleted list.
fn material_lines(material: &MaterialOverview) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::raw("• "),
        Span::styled(
            material.display_title().to_string(),
            theme::text().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(kind_summary(&material.kind), theme::footer()),
    ])];
    if let Some(desc) = &material.description {
        append_prose_paragraphs(&mut lines, desc, 2, theme::footer());
    }
    lines
}

/// One-line summary of a material kind, joined with `" · "`.
fn kind_summary(kind: &MaterialOverviewKind) -> String {
    match kind {
        MaterialOverviewKind::Digital => "digital".to_string(),
        MaterialOverviewKind::Physical {
            identifier,
            quantity,
        } => {
            let mut s = String::from("physical");
            if let Some(q) = quantity {
                use std::fmt::Write as _;
                let _ = write!(s, " · ×{q}");
            }
            if let Some(id) = identifier {
                s.push_str(" · ");
                s.push_str(id);
            }
            s
        }
        _ => "unknown".to_string(),
    }
}

/// Render an author-written prose blob (e.g. a YAML `description: |` block)
/// as a sequence of Markdown-style paragraphs:
///
/// * a single newline is treated as a soft break and folded to a space, so
///   line breaks added for source readability don't surface in the UI
/// * a blank line is a paragraph boundary and produces an empty `Line` in
///   the output
///
/// Each paragraph is wrapped independently by ratatui at render time.
/// `indent` is the number of leading spaces prepended to every output
/// line (used to nest material descriptions under their bullet).
fn append_prose_paragraphs(out: &mut Vec<Line<'static>>, text: &str, indent: usize, style: Style) {
    let prefix: String = " ".repeat(indent);
    let mut first = true;
    for paragraph in text.split("\n\n") {
        let mut folded = String::with_capacity(paragraph.len());
        for line in paragraph.lines().map(str::trim_end) {
            if !folded.is_empty() {
                folded.push(' ');
            }
            folded.push_str(line);
        }
        let trimmed = folded.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !first {
            out.push(Line::from(""));
        }
        first = false;
        let spans = if indent == 0 {
            vec![Span::styled(trimmed.to_string(), style)]
        } else {
            vec![
                Span::raw(prefix.clone()),
                Span::styled(trimmed.to_string(), style),
            ]
        };
        out.push(Line::from(spans));
    }
}

/// Deviations tab. Currently just the deviations list; reserved for
/// future side content (operator notes, attestation summary).
fn render_deviations(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let dev_lines: Vec<Line<'_>> = if model.deviations.is_empty() {
        vec![Line::from(Span::styled(
            "Press d to log a deviation",
            theme::footer(),
        ))]
    } else {
        model
            .deviations
            .iter()
            .map(|d| {
                let time = d.at.format("%H:%M:%S").to_string();
                let warn = icon_glyph(Icon::Warning);
                let body = match &d.step {
                    Some(step) => format!("{warn} ({step}) {}", d.text),
                    None => format!("{warn} {}", d.text),
                };
                Line::from(vec![
                    Span::styled(time, theme::footer()),
                    Span::raw("  "),
                    Span::raw(body),
                ])
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(Text::from(dev_lines))
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

fn render_completed(fingerprint: Option<&str>, frame: &mut Frame<'_>, area: Rect) {
    let bold = theme::text().add_modifier(Modifier::BOLD);
    let dim = theme::footer();

    let mut lines = vec![
        Line::from(Span::styled("Ceremony complete", bold)),
        Line::from(""),
        Line::from(Span::styled("Transcript fingerprint", bold)),
        Line::from(""),
    ];

    match fingerprint {
        Some(fp) => lines.extend(fingerprint_lines(fp, bold)),
        None => lines.push(Line::from(Span::styled("computing…", dim))),
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Record this fingerprint on paper"));
    lines.push(Line::from(""));
    lines.push(Line::from("Press Enter after recording the fingerprint..."));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

/// First 16 bytes (32 hex chars) of the fingerprint are emphasized ,
/// matches the pre-rewire console rendering so an operator copying the
/// value to paper sees the same shape they see in the script.
const EMPHASIZED_HEX: usize = 32;

/// Render the fingerprint as space-separated hex pairs, split across two
/// aligned lines: the emphasized first [`EMPHASIZED_HEX`] characters on top,
/// the rest indented underneath. Two lines avoid the mid-value wrap that a
/// single line hits at 32 spaced byte pairs plus the `sha256:` label.
fn fingerprint_lines(fp: &str, bold: Style) -> Vec<Line<'_>> {
    let (prefix, hex) = fp.split_once(':').unwrap_or(("", fp));
    let (emph, rest) = if hex.len() >= EMPHASIZED_HEX {
        hex.split_at(EMPHASIZED_HEX)
    } else {
        (hex, "")
    };
    let label = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}: ")
    };
    let indent = " ".repeat(label.chars().count());
    let mut lines = vec![Line::from(vec![
        Span::raw(label),
        Span::styled(space_hex_pairs(emph), bold),
    ])];
    if !rest.is_empty() {
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::raw(space_hex_pairs(rest)),
        ]));
    }
    lines
}

fn space_hex_pairs(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_failed(reason: &str, frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Ceremony failed",
            theme::text().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(reason.to_string()),
        Line::from(""),
        Line::from("Press Enter to exit."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

fn render_aborted(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Ceremony aborted",
            theme::text().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Stopped by the operator. The abort is recorded in the transcript."),
        Line::from(""),
        Line::from("Press Enter to exit."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(plain_block()),
        area,
    );
}

fn render_footer(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let hint = match &model.screen {
        Screen::DeviationModal { .. } => "Enter: submit  ·  Backspace: edit  ·  Esc: cancel",
        Screen::AbortConfirm => "y: abort  ·  n / Esc: cancel",
        Screen::Completed { .. } | Screen::Failed { .. } | Screen::Aborted => "Enter / Esc: exit",
        // The submit hint moved into the prompt box title, so the Ceremony
        // footer no longer changes width as prompts come and go.
        Screen::Step { tab } => match tab {
            StepTab::Overview | StepTab::System => "Tab: next tab  ·  Esc: abort",
            StepTab::Ceremony => "↑/↓ · PgUp/PgDn: scroll  ·  Tab: next tab  ·  Esc: abort",
            StepTab::Deviations => "d: log deviation  ·  Tab: next tab  ·  Esc: abort",
        },
    };
    frame.render_widget(
        Paragraph::new(hint)
            .style(theme::footer())
            .alignment(Alignment::Center),
        area,
    );
}

fn spinner_glyph(tick: u64) -> &'static str {
    // SPINNER_FRAMES has 10 entries, so the modulo always fits in usize.
    let idx = usize::try_from(tick.rem_euclid(SPINNER_FRAMES.len() as u64)).unwrap_or(0);
    SPINNER_FRAMES.get(idx).copied().unwrap_or("·")
}

/// Bordered block with no title. The single place where the border
/// color decision lives, so every box in the TUI stays consistent.
fn plain_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
}
