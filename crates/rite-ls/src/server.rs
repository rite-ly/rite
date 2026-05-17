//! LSP server implementation for the Rite ceremony DSL.

use crate::{
    complete, convert, document::DocumentAnalysis, goto, hover, inlay_hints, references,
    semantic_tokens, symbols,
};
use dashmap::DashMap;
use tower_lsp_server::{
    Client, LanguageServer,
    jsonrpc::Result,
    ls_types::{
        CompletionOptions, CompletionParams, CompletionResponse, DidChangeTextDocumentParams,
        DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentSymbolParams,
        DocumentSymbolResponse, GotoDefinitionParams, GotoDefinitionResponse, Hover, HoverParams,
        HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams, InlayHint,
        InlayHintParams, Location, MessageType, OneOf, ReferenceParams, SemanticTokens,
        SemanticTokensFullOptions, SemanticTokensLegend, SemanticTokensOptions,
        SemanticTokensParams, SemanticTokensResult, SemanticTokensServerCapabilities,
        ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
    },
};

/// The Rite language server.
pub struct RiteLanguageServer {
    client: Client,
    /// Cached analysis results keyed by document URI.
    analyses: DashMap<Uri, DocumentAnalysis>,
}

impl RiteLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            analyses: DashMap::new(),
        }
    }

    /// Analyze the given document text and publish diagnostics to the client.
    async fn analyze_and_publish(&self, uri: Uri, text: String) {
        // Only analyze file:// URIs; non-file URIs (e.g. untitled://) have no filesystem path.
        if uri.scheme().as_str() != "file" {
            return;
        }
        let Some(path) = uri.to_file_path() else {
            return;
        };
        let path = path.into_owned();

        let (resolved, span_map, diags) = rite_resolver::analyze_str(Some(&path), &text);

        // Cache the analysis for hover/completion/goto. `text` can be moved: the borrow above
        // ends after `analyze_str` returns, and `path` borrows from `uri`, not from `text`.
        self.analyses.insert(
            uri.clone(),
            DocumentAnalysis {
                text,
                span_map,
                resolved,
            },
        );

        // Publish diagnostics (tower-lsp-server 0.23 takes separate args, not a params struct)
        let lsp_diags: Vec<_> = diags.iter().map(convert::to_lsp_diagnostic).collect();
        self.client.publish_diagnostics(uri, lsp_diags, None).await;
    }
}

impl LanguageServer for RiteLanguageServer {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: None,
            offset_encoding: None,
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![" ".into(), ":".into(), "{".into()]),
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            legend: SemanticTokensLegend {
                                token_types: semantic_tokens::LEGEND.to_vec(),
                                token_modifiers: vec![],
                            },
                            range: Some(false),
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                            ..Default::default()
                        },
                    ),
                ),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "rite-ls initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.analyze_and_publish(uri, text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        // We use FULL sync, so there's exactly one content change with the full text.
        let Some(change) = params.content_changes.into_iter().next() else {
            return;
        };
        let uri = params.text_document.uri;
        self.analyze_and_publish(uri, change.text).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.analyses.remove(&uri);
        // Clear diagnostics so stale squiggles don't linger.
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        let line = analysis.text.lines().nth(pos.line as usize).unwrap_or("");
        let col = pos.character as usize;

        let items = complete::detect_context(line, col, pos.line)
            .map(|ctx| {
                complete::completions_for(ctx, &analysis.span_map, analysis.resolved.as_ref())
            })
            .unwrap_or_default();

        if items.is_empty() {
            Ok(None)
        } else {
            Ok(Some(CompletionResponse::Array(items)))
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        Ok(hover::hover_at(
            &analysis.text,
            &analysis.span_map,
            analysis.resolved.as_ref(),
            pos,
        ))
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        Ok(goto::goto_definition_at(&analysis.span_map, pos, uri))
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let include_declaration = params.context.include_declaration;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        let locs = references::find_references_at(
            &analysis.span_map,
            &analysis.text,
            pos,
            uri,
            include_declaration,
        );
        if locs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(locs))
        }
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = &params.text_document.uri;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        let hints = inlay_hints::hints_for(&analysis.span_map, analysis.resolved.as_ref());
        if hints.is_empty() {
            Ok(None)
        } else {
            Ok(Some(hints))
        }
    }

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = &params.text_document.uri;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        let data = semantic_tokens::tokens_for(&analysis.span_map);
        if data.is_empty() {
            return Ok(None);
        }

        Ok(Some(SemanticTokensResult::Tokens(SemanticTokens {
            result_id: None,
            data,
        })))
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        let Some(analysis) = self.analyses.get(uri) else {
            return Ok(None);
        };

        let Some(resolved) = analysis.resolved.as_ref() else {
            return Ok(None);
        };

        let syms = symbols::document_symbols(&analysis.span_map, resolved);
        if syms.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Nested(syms)))
        }
    }
}

impl std::fmt::Display for RiteLanguageServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rite-ls")
    }
}
