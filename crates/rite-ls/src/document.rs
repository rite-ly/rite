//! Per-document state: text content and analysis results.

use crate::convert::LineIndex;
use rite_model::Ceremony;
use rite_resolver::SpanMap;

/// Cached analysis result for an open document.
pub struct DocumentAnalysis {
    /// The full text of the document as last seen.
    pub text: String,
    /// Span map from the last successful parse, used for go-to-definition and hover.
    pub span_map: SpanMap,
    /// Resolved ceremony from the last successful analysis, used for hover content.
    /// `None` if the ceremony has parse or resolution errors.
    pub resolved: Option<Ceremony>,
}

impl DocumentAnalysis {
    /// The text's lines, to convert positions to and from the client's.
    pub fn lines(&self) -> LineIndex<'_> {
        LineIndex::new(&self.text)
    }
}
