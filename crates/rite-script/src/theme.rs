//! Shared CSS theme for all Rite HTML documents.
//!
//! Both ceremony scripts and reports embed this same stylesheet,
//! ensuring visual consistency across document types.

/// Shared CSS theme embedded in all generated HTML documents.
///
/// Covers styles for: ceremony scripts, post-ceremony reports.
/// Unused classes in a given document have no cost.
pub(crate) const THEME_CSS: &str = r#"
    /* === Base typography === */
    body {
      font-family: Arial, Helvetica, sans-serif;
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
      line-height: 1.4;
    }
    h1 {
      text-align: center;
      border-bottom: 2px solid #333;
      padding-bottom: 10px;
    }
    h2 {
      margin-top: 30px;
      border-bottom: 1px solid #999;
      padding-bottom: 5px;
    }
    h3 {
      margin-top: 20px;
      margin-bottom: 10px;
    }

    /* === Shared components === */
    .metadata {
      background-color: #f5f5f5;
      padding: 15px;
      margin: 20px 0;
      border-radius: 4px;
    }
    .metadata p {
      margin: 5px 0;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 10px 0 20px 0;
    }
    th, td {
      border: 1px solid #333;
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background-color: #f0f0f0;
      font-weight: bold;
    }
    ul.roles, ul.materials, ul.outputs {
      list-style-type: none;
      padding-left: 0;
    }
    ul.roles li, ul.materials li, ul.outputs li {
      padding: 5px 0;
      border-bottom: 1px dotted #ccc;
    }

    /* === Duty blocks (script + report) === */
    .duties-intro {
      color: #555;
      margin-bottom: 15px;
    }
    .duty {
      border: 1px solid #ccc;
      border-left: 4px solid #666;
      padding: 12px 15px;
      margin: 15px 0;
      page-break-inside: avoid;
    }
    .duty-heading {
      margin: 0 0 8px 0;
      border-bottom: none;
      font-size: 1em;
    }
    .duty-prose {
      margin: 5px 0 10px 0;
      color: #333;
    }
    ul.duty-items {
      margin: 5px 0 0 0;
      padding-left: 20px;
    }
    ul.duty-items li {
      padding: 3px 0;
    }

    /* === Checklist & preconditions === */
    ul.checklist {
      list-style-type: none;
      padding-left: 0;
    }
    ul.checklist li {
      padding: 5px 0;
      border-bottom: 1px dotted #ccc;
    }
    ul.checklist li::before {
      content: "\2610\00a0";
    }
    .preconditions {
      background-color: #fffbe6;
      border-left: 4px solid #e6c300;
      padding: 10px 15px;
      margin: 10px 0;
    }
    .preconditions p {
      margin: 0 0 5px 0;
    }

    /* === Script-specific === */
    .overview {
      background-color: #f8f8f8;
      padding: 15px;
      border-left: 4px solid #666;
      margin: 15px 0;
    }
    .act-header {
      background-color: #333;
      color: white;
      padding: 12px 15px;
      margin-top: 40px;
      font-size: 1.2em;
      font-weight: bold;
      page-break-after: avoid;
    }
    .act-preamble {
      background-color: #f0f0f0;
      padding: 15px;
      border-left: 4px solid #333;
      margin: 10px 0 20px 0;
      font-style: italic;
    }
    .section-header {
      border-bottom: 2px solid #666;
      padding-bottom: 5px;
      margin-top: 25px;
      page-break-after: avoid;
    }
    .section-description {
      color: #555;
      font-style: italic;
      margin: 5px 0 15px 0;
    }
    .step-num {
      width: 50px;
      text-align: center;
    }
    .role {
      width: 120px;
    }
    .signatures {
      margin-top: 20px;
    }
    .signature-block {
      margin: 30px 0;
      padding: 15px;
      border: 1px solid #ccc;
      page-break-inside: avoid;
    }
    .signature-block p {
      margin: 10px 0;
    }

    /* === Report-specific === */
    .dry-run-banner {
      background-color: #fee;
      border: 2px solid #c00;
      color: #900;
      padding: 12px 15px;
      margin: 15px 0;
      font-weight: bold;
      text-align: center;
      font-size: 1.1em;
    }
    .summary-box {
      background-color: #f5f5f5;
      padding: 15px;
      margin: 20px 0;
      border-radius: 4px;
      border-left: 4px solid #333;
    }
    .summary-box p {
      margin: 5px 0;
    }
    .deviations {
      border: 2px solid #c00;
      border-left: 4px solid #c00;
      background-color: #fff5f5;
      padding: 12px 15px;
      margin: 15px 0;
    }
    .deviations h3 {
      color: #900;
      margin-top: 0;
    }
    .hash {
      font-family: monospace;
      font-size: 0.85em;
      word-break: break-all;
    }
    .status-completed {
      color: #060;
      font-weight: bold;
    }
    .status-interrupted {
      color: #c00;
      font-weight: bold;
    }
    .status-skipped {
      color: #666;
      font-style: italic;
    }
    .report-footer {
      margin-top: 40px;
      padding-top: 15px;
      border-top: 1px solid #ccc;
      color: #999;
      font-size: 0.85em;
      text-align: center;
    }

    /* === Print === */
    @media print {
      body {
        padding: 0;
      }
      .act-header {
        background-color: #333 !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .signature-block {
        border: 1px solid #000;
      }
      .dry-run-banner {
        background-color: #fee !important;
        border-color: #c00 !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      .deviations {
        border-color: #c00 !important;
        background-color: #fff5f5 !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
    }
"#;
