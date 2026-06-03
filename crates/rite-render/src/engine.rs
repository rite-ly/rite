//! Theme selection and the minijinja rendering environment.
//!
//! Templates and stylesheets are embedded at build time via `include_str!`.
//! Both document types share one stylesheet per theme, so a script and its
//! report cannot drift apart visually.

use crate::report::ReportData;
use crate::view::{Branding, ReportView, ScriptView, render_prose_html};
use minijinja::value::Value;
use minijinja::{Environment, context};
use rite_model::Ceremony;

const SCRIPT_TEMPLATE: &str = include_str!("../templates/script.html.jinja");
const REPORT_TEMPLATE: &str = include_str!("../templates/report.html.jinja");
const FORMAL_CSS: &str = include_str!("../templates/themes/formal.css");

/// A built-in document theme.
///
/// Only one theme ships today; the type and the `--theme` flag exist so further
/// themes can be added later without an API change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Theme {
    /// Formal serif "ceremony protocol" look.
    #[default]
    Formal,
}

impl Theme {
    /// The stylesheet for this theme, shared by scripts and reports.
    fn css(self) -> &'static str {
        match self {
            Theme::Formal => FORMAL_CSS,
        }
    }

    /// Stable lowercase slug, also used as a `<body>` class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Formal => "formal",
        }
    }
}

impl std::fmt::Display for Theme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Theme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "formal" => Ok(Theme::Formal),
            other => Err(format!("unknown theme '{other}' (expected: formal)")),
        }
    }
}

fn environment() -> Result<Environment<'static>, minijinja::Error> {
    let mut env = Environment::new();
    // `prose` turns a multi-line instruction into paragraphs and bullet lists.
    // It returns pre-escaped, safe HTML, so autoescape leaves it untouched.
    env.add_filter("prose", |text: String| {
        Value::from_safe_string(render_prose_html(&text))
    });
    env.add_template("script.html", SCRIPT_TEMPLATE)?;
    env.add_template("report.html", REPORT_TEMPLATE)?;
    Ok(env)
}

/// Render a ceremony script to a self-contained HTML document.
///
/// # Errors
///
/// Returns a [`minijinja::Error`] if a template fails to compile or render.
pub fn render_script(
    ceremony: &Ceremony,
    branding: &Branding,
    theme: Theme,
) -> Result<String, minijinja::Error> {
    let view = ScriptView::from_ceremony(ceremony);
    let env = environment()?;
    let template = env.get_template("script.html")?;
    template.render(context! {
        script => view,
        branding => branding,
        css => theme.css(),
        theme => theme.as_str(),
    })
}

/// Render a post-ceremony report to a self-contained HTML document.
///
/// # Errors
///
/// Returns a [`minijinja::Error`] if a template fails to compile or render.
pub fn render_report(
    data: &ReportData,
    branding: &Branding,
    theme: Theme,
) -> Result<String, minijinja::Error> {
    let view = ReportView::from_data(data);
    let env = environment()?;
    let template = env.get_template("report.html")?;
    template.render(context! {
        report => view,
        branding => branding,
        css => theme.css(),
        theme => theme.as_str(),
    })
}
