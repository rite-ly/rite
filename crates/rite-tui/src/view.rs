//! Pure `view(model, frame)`. Renders the current model into a ratatui
//! frame. Never mutates the model, never touches I/O.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};

use rite_model::Prompt;
use rite_runtime::Icon;

use crate::model::{LogLine, Model, Screen, StepTab};

/// Spinner animation frames cycled by [`spinner_glyph`] for `Icon::Spinner`.
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Static glyph for a non-spinner [`Icon`]. The TUI owns its glyph mapping;
/// the runtime does not provide one so frontends can choose their own.
fn icon_glyph(icon: Icon) -> &'static str {
    match icon {
        Icon::Spinner => SPINNER_FRAMES[0],
        Icon::Checkmark => "✓",
        Icon::Cross => "✗",
        Icon::Info => "ℹ",
        Icon::Warning => "⚠",
    }
}

/// Render the current model into the given frame.
pub fn view(model: &Model, frame: &mut Frame<'_>) {
    let area = frame.area();
    let [header_area, body_area, footer_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .areas(area);

    render_header(model, frame, header_area);
    render_body(model, frame, body_area);
    render_footer(model, frame, footer_area);
}

fn render_header(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let title = model
        .ceremony_name
        .as_deref()
        .unwrap_or("rite: starting ceremony");
    let spinner = spinner_glyph(model.tick);
    let spans = vec![
        Span::styled(spinner, Style::default().add_modifier(Modifier::DIM)),
        Span::raw(" "),
        Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
    ];
    let header = Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(header, area);
}

fn render_body(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    match &model.screen {
        Screen::Step { tab } => render_step_screen(model, *tab, frame, area),
        Screen::DeviationModal { input } => render_deviation_modal(input, frame, area),
        Screen::AbortConfirm => render_abort_confirm(frame, area),
        Screen::Completed { fingerprint, .. } => {
            render_completed(fingerprint.as_deref(), frame, area);
        }
        Screen::Failed { reason } => render_failed(reason, frame, area),
    }
}

fn render_step_screen(model: &Model, tab: StepTab, frame: &mut Frame<'_>, area: Rect) {
    let [tabs_area, content_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .areas(area);

    let selected = match tab {
        StepTab::Step => 0,
        StepTab::Log => 1,
    };
    let tabs = Tabs::new(vec![Line::from(" Step "), Line::from(" Log ")])
        .select(selected)
        .divider(Span::raw("│"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED));
    frame.render_widget(tabs, tabs_area);

    match tab {
        StepTab::Step => render_step(model, frame, content_area),
        StepTab::Log => render_log(model, frame, content_area),
    }
}

fn render_deviation_modal(input: &str, frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Log a deviation",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Describe what happened, then press Enter."),
        Line::from(""),
        Line::from(format!("> {input}")),
        Line::from(""),
        Line::from(Span::styled(
            "Enter: submit  ·  Esc: cancel",
            Style::default().add_modifier(Modifier::DIM),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Deviation")),
        area,
    );
}

fn render_abort_confirm(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Abort the ceremony?",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "The current step will be interrupted at the next safe point \
             and recorded as aborted in the transcript.",
        ),
        Line::from(""),
        Line::from(Span::styled(
            "y: abort  ·  n / Esc: cancel",
            Style::default().add_modifier(Modifier::DIM),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm abort"),
        ),
        area,
    );
}

fn render_step(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let [step_header_area, body_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // step header (plain inline)
            Constraint::Min(0),    // prompt + log area
        ])
        .areas(area);

    let step_text = if let Some(step) = &model.current_step {
        format!(
            "Step {label} ({id}), role: {role}",
            label = step.label,
            id = step.id,
            role = step.role_name,
        )
    } else {
        "Waiting for first step…".to_string()
    };
    frame.render_widget(
        Paragraph::new(step_text).style(Style::default().add_modifier(Modifier::BOLD)),
        step_header_area,
    );

    if let Some(pending) = &model.pending_prompt {
        let prompt_height = prompt_block_height(pending);
        let [logs_area, prompt_area] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(prompt_height)])
            .areas(body_area);
        render_recent_logs(model, frame, logs_area);
        render_prompt(pending, frame, prompt_area);
    } else {
        render_recent_logs(model, frame, body_area);
    }
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
        Prompt::Confirm { question, default } => {
            let hint = match default {
                Some(true) => " [Y/n]",
                Some(false) => " [y/N]",
                None => " [y/n]",
            };
            vec![Line::from(format!("{question}{hint}"))]
        }
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
    let title = if pending.rejection.is_some() {
        "Prompt (last attempt rejected)"
    } else {
        "Prompt"
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
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// Format a [`LogLine`] as a styled ratatui line.
///
/// `tick` advances the spinner glyph for `Icon::Spinner` entries.
/// `inner_width` is the available width *inside* the surrounding block,
/// used to size step-divider rule strokes.
fn log_line(line: &LogLine, tick: u64, inner_width: u16) -> Line<'_> {
    match line {
        LogLine::Entry { icon, text } => {
            let prefix = match icon {
                Icon::Spinner => spinner_glyph(tick),
                other => icon_glyph(*other),
            };
            Line::from(format!("{prefix} {text}"))
        }
        LogLine::StepDivider { label, role_name } => {
            let title = format!(" {label} · {role_name} ");
            let pad =
                usize::from(inner_width).saturating_sub(title.chars().count().saturating_add(2));
            let left = "── ";
            let right_len = pad.saturating_sub(left.chars().count());
            let right: String = std::iter::repeat_n('─', right_len).collect();
            Line::from(Span::styled(
                format!("{left}{title}{right}"),
                Style::default().add_modifier(Modifier::BOLD),
            ))
        }
    }
}

/// Build a wrapping [`Paragraph`] from the bounded log feed, sized to
/// the visible area and scrolled by `lines_from_tail` wrapped lines.
///
/// Returns `(paragraph, max_scroll)` so the caller can render the title
/// with the actual (clamped) scroll value.
fn log_paragraph<'a>(
    model: &'a Model,
    area: Rect,
    title: impl Into<Line<'a>>,
    lines_from_tail: usize,
) -> (Paragraph<'a>, usize) {
    let inner_width = area.width.saturating_sub(2);
    let visible_height = usize::from(area.height).saturating_sub(2);
    let lines: Vec<Line<'a>> = model
        .log
        .iter()
        .map(|line| log_line(line, model.tick, inner_width))
        .collect();
    let paragraph = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(title));
    let total = paragraph.line_count(inner_width);
    let max_scroll = total.saturating_sub(visible_height);
    let scroll = lines_from_tail.min(max_scroll);
    let scroll_y = u16::try_from(max_scroll.saturating_sub(scroll)).unwrap_or(u16::MAX);
    (paragraph.scroll((scroll_y, 0)), scroll)
}

fn render_recent_logs(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let (paragraph, _) = log_paragraph(model, area, "Recent", 0);
    frame.render_widget(paragraph, area);
}

fn render_log(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let [log_area, dev_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .areas(area);

    let (paragraph, applied_scroll) = log_paragraph(model, log_area, "Log", model.log_scroll);
    let title = if applied_scroll == 0 {
        Line::from("Log")
    } else {
        Line::from(format!(
            "Log  (scrolled {applied_scroll} lines · End: tail)"
        ))
    };
    frame.render_widget(
        paragraph.block(Block::default().borders(Borders::ALL).title(title)),
        log_area,
    );

    let dev_lines: Vec<Line<'_>> = model
        .deviations
        .iter()
        .map(|d| {
            let line = match &d.step {
                Some(step) => format!("⚠ ({step}) {}", d.text),
                None => format!("⚠ {}", d.text),
            };
            Line::from(line)
        })
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(dev_lines))
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Deviations")),
        dev_area,
    );
}

fn render_completed(fingerprint: Option<&str>, frame: &mut Frame<'_>, area: Rect) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().add_modifier(Modifier::DIM);

    let mut lines = vec![
        Line::from(Span::styled("Transcript fingerprint", bold)),
        Line::from(""),
    ];

    match fingerprint {
        Some(fp) => lines.push(fingerprint_line(fp, bold)),
        None => lines.push(Line::from(Span::styled("computing…", dim))),
    }

    lines.push(Line::from("Record this fingerprint on paper"));
    lines.push(Line::from(""));
    lines.push(Line::from("Press Enter after recording the fingerprint..."));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Completed")),
        area,
    );
}

/// First 16 bytes (32 hex chars) of the fingerprint are emphasized ,
/// matches the pre-rewire console rendering so an operator copying the
/// value to paper sees the same shape they see in the script.
const EMPHASIZED_HEX: usize = 32;

/// Render the fingerprint as space-separated hex pairs with the first
/// [`EMPHASIZED_HEX`] characters bolded.
fn fingerprint_line(fp: &str, bold: Style) -> Line<'_> {
    let (prefix, hex) = fp.split_once(':').unwrap_or(("", fp));
    let (emph, rest) = if hex.len() >= EMPHASIZED_HEX {
        hex.split_at(EMPHASIZED_HEX)
    } else {
        (hex, "")
    };
    let mut spans = Vec::new();
    if !prefix.is_empty() {
        spans.push(Span::raw(format!("{prefix}:")));
    }
    spans.push(Span::styled(space_hex_pairs(emph), bold));
    if !rest.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::raw(space_hex_pairs(rest)));
    }
    Line::from(spans)
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
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(reason.to_string()),
        Line::from(""),
        Line::from("Press Enter to exit."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Failed")),
        area,
    );
}

fn render_footer(model: &Model, frame: &mut Frame<'_>, area: Rect) {
    let hint = match &model.screen {
        Screen::DeviationModal { .. } => "Enter: submit  ·  Backspace: edit  ·  Esc: cancel",
        Screen::AbortConfirm => "y: abort  ·  n / Esc: cancel",
        Screen::Completed { .. } | Screen::Failed { .. } => "q / Enter / Esc: exit",
        Screen::Step { tab } => match (tab, model.pending_prompt.is_some()) {
            (StepTab::Step, true) => "Enter: submit  ·  Tab: log  ·  Esc: abort  ·  Ctrl+C: quit",
            (StepTab::Step, false) => "Tab: log  ·  d: deviation  ·  Esc / a: abort  ·  q: quit",
            (StepTab::Log, true) => {
                "↑/↓ · PgUp/PgDn: scroll  ·  Home/End: top/tail  ·  Tab: step  ·  Esc: abort"
            }
            (StepTab::Log, false) => {
                "↑/↓ · PgUp/PgDn: scroll  ·  Home/End: top/tail  ·  \
                 Tab: step  ·  d: deviation  ·  Esc / a: abort  ·  q: quit"
            }
        },
    };
    frame.render_widget(
        Paragraph::new(hint).style(Style::default().add_modifier(Modifier::DIM)),
        area,
    );
}

fn spinner_glyph(tick: u64) -> &'static str {
    // SPINNER_FRAMES has 10 entries, so the modulo always fits in usize.
    let idx = usize::try_from(tick.rem_euclid(SPINNER_FRAMES.len() as u64)).unwrap_or(0);
    SPINNER_FRAMES.get(idx).copied().unwrap_or("·")
}
