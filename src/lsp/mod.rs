use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::detector::DetectorEngine;
use crate::error::SentrisError;
use crate::model::Severity;
use crate::remediator::code_replacer::CodeReplacer;
use crate::remediator::Remediator;

const MAX_BODY_BYTES: usize = 8 << 20;
const MAX_HEADER_BYTES: u64 = 8 << 10;

/// Converts a byte offset within `line` to UTF-16 code units (what LSP positions count).
fn utf16_col(line: &str, byte_idx: usize) -> usize {
    let mut i = byte_idx.min(line.len());
    while !line.is_char_boundary(i) {
        i -= 1;
    }
    line[..i].encode_utf16().count()
}

#[derive(Debug, Clone, Deserialize)]
pub struct LspMessage {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LspOutbound {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub struct LspServer {
    detector: DetectorEngine,
    documents: HashMap<String, String>,
}

impl LspServer {
    pub fn new() -> Result<Self, SentrisError> {
        Ok(Self {
            detector: DetectorEngine::new()?,
            documents: HashMap::new(),
        })
    }

    /// Runs the Language Server Protocol (LSP 3.17) stdio loop supporting both
    /// `Content-Length: N\r\n\r\n` headers and single-line JSON-RPC messages.
    pub fn run_stdio_loop() -> Result<(), SentrisError> {
        let stdin = io::stdin();
        Self::serve(stdin.lock(), io::stdout())
    }

    pub(crate) fn serve<R: BufRead, W: Write>(
        mut reader: R,
        mut stdout: W,
    ) -> Result<(), SentrisError> {
        let mut server = Self::new()?;
        loop {
            let mut first_line = String::new();
            let bytes_read = reader
                .by_ref()
                .take(MAX_HEADER_BYTES)
                .read_line(&mut first_line)?;
            if bytes_read == 0 {
                break;
            }

            let trimmed = first_line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let raw_payload = if let Some(len_str) = trimmed
                .strip_prefix("Content-Length:")
                .or_else(|| trimmed.strip_prefix("content-length:"))
            {
                let content_len: usize = len_str.trim().parse().unwrap_or(0);
                if content_len > MAX_BODY_BYTES {
                    // Cannot resync without reading the body, so refuse and stop instead of allocating it
                    let body = json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {"code": -32600, "message": format!("Content-Length {content_len} exceeds {MAX_BODY_BYTES} bytes")}
                    })
                    .to_string();
                    let _ = write!(stdout, "Content-Length: {}\r\n\r\n{}", body.len(), body);
                    let _ = stdout.flush();
                    break;
                }
                // Consume remaining header lines until blank line
                loop {
                    let mut header_line = String::new();
                    if reader
                        .by_ref()
                        .take(MAX_HEADER_BYTES)
                        .read_line(&mut header_line)?
                        == 0
                        || header_line.trim().is_empty()
                    {
                        break;
                    }
                }
                let mut buf = vec![0u8; content_len];
                reader.read_exact(&mut buf)?;
                String::from_utf8_lossy(&buf).to_string()
            } else {
                trimmed.to_string()
            };

            let (responses, should_exit) = server.handle_raw_message(&raw_payload);
            for out in responses {
                if let Ok(body) = serde_json::to_string(&out) {
                    let _ = write!(stdout, "Content-Length: {}\r\n\r\n{}", body.len(), body);
                    let _ = stdout.flush();
                }
            }

            if should_exit {
                break;
            }
        }

        Ok(())
    }

    /// Processes a single incoming JSON-RPC LSP frame and returns `(outbound_messages, should_exit)`.
    pub fn handle_raw_message(&mut self, raw_json: &str) -> (Vec<LspOutbound>, bool) {
        let msg: LspMessage = match serde_json::from_str(raw_json) {
            Ok(m) => m,
            Err(err) => {
                return (
                    vec![LspOutbound {
                        jsonrpc: "2.0",
                        id: Some(Value::Null),
                        method: None,
                        params: None,
                        result: None,
                        error: Some(json!({
                            "code": -32700,
                            "message": format!("Parse error: {err}")
                        })),
                    }],
                    false,
                );
            }
        };

        let method = msg.method.as_deref().unwrap_or("");
        match method {
            "initialize" => {
                let res = json!({
                    "capabilities": {
                        "textDocumentSync": 1,
                        "codeActionProvider": {
                            "codeActionKinds": ["quickfix"]
                        }
                    },
                    "serverInfo": {
                        "name": "sentris-lsp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                (
                    vec![LspOutbound {
                        jsonrpc: "2.0",
                        id: msg.id,
                        method: None,
                        params: None,
                        result: Some(res),
                        error: None,
                    }],
                    false,
                )
            }
            "initialized" => (Vec::new(), false),
            "shutdown" => (
                vec![LspOutbound {
                    jsonrpc: "2.0",
                    id: msg.id,
                    method: None,
                    params: None,
                    result: Some(Value::Null),
                    error: None,
                }],
                false,
            ),
            "exit" => (Vec::new(), true),
            "textDocument/didOpen" => {
                if let Some(params) = &msg.params {
                    if let Some(doc) = params.get("textDocument") {
                        let uri = doc.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                        let text = doc.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        self.documents.insert(uri.to_string(), text.to_string());
                        let diag = self.build_diagnostics_notification(uri, text);
                        return (vec![diag], false);
                    }
                }
                (Vec::new(), false)
            }
            "textDocument/didChange" => {
                if let Some(params) = &msg.params {
                    let uri = params
                        .get("textDocument")
                        .and_then(|d| d.get("uri"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(changes) = params.get("contentChanges").and_then(|c| c.as_array()) {
                        if let Some(last_change) = changes.last() {
                            if let Some(text) = last_change.get("text").and_then(|v| v.as_str()) {
                                self.documents.insert(uri.to_string(), text.to_string());
                                let diag = self.build_diagnostics_notification(uri, text);
                                return (vec![diag], false);
                            }
                        }
                    }
                }
                (Vec::new(), false)
            }
            "textDocument/codeAction" => {
                let actions = self.build_code_actions(msg.params.as_ref());
                (
                    vec![LspOutbound {
                        jsonrpc: "2.0",
                        id: msg.id,
                        method: None,
                        params: None,
                        result: Some(Value::Array(actions)),
                        error: None,
                    }],
                    false,
                )
            }
            _ => {
                if let Some(id) = msg.id {
                    (
                        vec![LspOutbound {
                            jsonrpc: "2.0",
                            id: Some(id),
                            method: None,
                            params: None,
                            result: None,
                            error: Some(json!({
                                "code": -32601,
                                "message": format!("Method not supported: {method}")
                            })),
                        }],
                        false,
                    )
                } else {
                    (Vec::new(), false)
                }
            }
        }
    }

    fn uri_to_file_path(uri: &str) -> &str {
        uri.strip_prefix("file://").unwrap_or(uri)
    }

    fn build_diagnostics_notification(&self, uri: &str, text: &str) -> LspOutbound {
        let file_path = Self::uri_to_file_path(uri);
        let findings = self.detector.scan_text(text, file_path);
        let lines: Vec<&str> = text.lines().collect();

        let diagnostics: Vec<Value> = findings
            .iter()
            .map(|f| {
                let line_idx = f.line_number.saturating_sub(1);
                // LSP columns are UTF-16 code units; Finding.column is a byte offset
                let col_start = lines
                    .get(line_idx)
                    .map(|l| utf16_col(l, f.column.saturating_sub(1)))
                    .unwrap_or(0);
                let col_end = col_start + 16;
                let lsp_severity = match f.severity {
                    Severity::Critical | Severity::High => 1, // Error
                    Severity::Medium => 2,                    // Warning
                    Severity::Low => 3,                       // Information
                };
                let env_var = Remediator::env_var_name_for_rule(&f.rule_id);
                let accessor = CodeReplacer::get_env_accessor(file_path, env_var);

                json!({
                    "range": {
                        "start": { "line": line_idx, "character": col_start },
                        "end": { "line": line_idx, "character": col_end }
                    },
                    "severity": lsp_severity,
                    "code": f.rule_id,
                    "source": "sentris",
                    "message": format!(
                        "[Sentris] Hardcoded {} ({}) detected. Quick fix: replace with `{}`",
                        f.rule_id, f.redacted_match, accessor
                    )
                })
            })
            .collect();

        LspOutbound {
            jsonrpc: "2.0",
            id: None,
            method: Some("textDocument/publishDiagnostics"),
            params: Some(json!({
                "uri": uri,
                "diagnostics": diagnostics
            })),
            result: None,
            error: None,
        }
    }

    fn build_code_actions(&self, params: Option<&Value>) -> Vec<Value> {
        let Some(params) = params else {
            return Vec::new();
        };
        let uri = params
            .get("textDocument")
            .and_then(|d| d.get("uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(doc_text) = self.documents.get(uri) else {
            return Vec::new();
        };

        let file_path = Self::uri_to_file_path(uri);
        let findings = self.detector.scan_text(doc_text, file_path);
        let lines: Vec<&str> = doc_text.lines().collect();

        let mut actions = Vec::new();
        for f in findings {
            let line_idx = f.line_number.saturating_sub(1);
            if line_idx >= lines.len() {
                continue;
            }
            let target_line = lines[line_idx];
            let Some(raw_secret) = self.detector.extract_raw_secret(target_line, &f.rule_id) else {
                continue;
            };
            let env_var = Remediator::env_var_name_for_rule(&f.rule_id);
            let patched_line =
                CodeReplacer::replace_secret_in_line(file_path, target_line, &raw_secret, env_var);

            let mut changes = serde_json::Map::new();
            changes.insert(
                uri.to_string(),
                json!([{
                    "range": {
                        "start": { "line": line_idx, "character": 0 },
                        "end": { "line": line_idx, "character": target_line.encode_utf16().count() }
                    },
                    "newText": patched_line
                }]),
            );

            actions.push(json!({
                "title": format!("Sentris: Extract {} to {}", f.rule_id, env_var),
                "kind": "quickfix",
                "isPreferred": true,
                "edit": {
                    "changes": changes
                }
            }));
        }

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_initialize_and_diagnostics_and_code_action() {
        let mut server = LspServer::new().unwrap();

        // 1. initialize
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let (init_out, exit) = server.handle_raw_message(init_req);
        assert!(!exit);
        assert_eq!(init_out.len(), 1);
        assert_eq!(
            init_out[0].result.as_ref().unwrap()["serverInfo"]["name"],
            "sentris-lsp"
        );

        // 2. textDocument/didOpen with a hardcoded Stripe key
        let stripe_key = concat!("sk_live_", "51AbcDefGhIjKlMnOpQrStUvWxYz123456");
        let did_open = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///workspace/src/checkout.ts",
                    "languageId": "typescript",
                    "version": 1,
                    "text": format!("const k = \"{stripe_key}\";\n")
                }
            }
        });
        let (diag_out, _) = server.handle_raw_message(&did_open.to_string());
        assert_eq!(diag_out.len(), 1);
        assert_eq!(diag_out[0].method, Some("textDocument/publishDiagnostics"));
        let diags = diag_out[0].params.as_ref().unwrap()["diagnostics"]
            .as_array()
            .unwrap();
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0]["code"], "stripe-secret-key");
        assert!(diags[0]["message"]
            .as_str()
            .unwrap()
            .contains("process.env.STRIPE_SECRET_KEY"));

        // 3. textDocument/codeAction returns quickfix WorkspaceEdit
        let ca_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": { "uri": "file:///workspace/src/checkout.ts" },
                "range": {
                    "start": { "line": 0, "character": 0 },
                    "end": { "line": 0, "character": 20 }
                },
                "context": { "diagnostics": [] }
            }
        });
        let (ca_out, _) = server.handle_raw_message(&ca_req.to_string());
        assert_eq!(ca_out.len(), 1);
        let actions = ca_out[0].result.as_ref().unwrap().as_array().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "quickfix");
        let edit_text = actions[0]["edit"]["changes"]["file:///workspace/src/checkout.ts"][0]
            ["newText"]
            .as_str()
            .unwrap();
        assert_eq!(edit_text, "const k = process.env.STRIPE_SECRET_KEY;");
    }

    #[test]
    fn oversized_content_length_is_refused_without_allocating() {
        let mut out = Vec::new();
        let input = b"Content-Length: 99999999999\r\n\r\n{}".to_vec();
        LspServer::serve(std::io::Cursor::new(input), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("exceeds"));
    }

    #[test]
    fn utf16_columns_for_non_ascii_lines() {
        // "é" is 2 bytes / 1 UTF-16 unit; "😀" is 4 bytes / 2 units
        assert_eq!(utf16_col("é😀x", 0), 0);
        assert_eq!(utf16_col("é😀x", 2), 1);
        assert_eq!(utf16_col("é😀x", 6), 3);
        assert_eq!(utf16_col("é😀x", 3), 1); // inside a char: floors to boundary
        assert_eq!(utf16_col("abc", 99), 3);
    }
}
