//! Language server binary for the Rite ceremony DSL.
//!
//! Runs as a standalone LSP server over stdio. Provides diagnostics (parse errors,
//! semantic validation), hover documentation, and completion for ceremony YAML files.

mod actions;
mod complete;
mod convert;
mod document;
mod goto;
mod hover;
mod references;
mod semantic_tokens;
mod server;
mod symbols;

use server::RiteLanguageServer;
use tower_lsp_server::{LspService, Server};

#[tokio::main]
async fn main() {
    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let (service, socket) = LspService::new(RiteLanguageServer::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
