pub mod manifest;
pub mod tools;

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::SentrisError;

/// JSON-RPC 2.0 Request frame for Model Context Protocol (MCP).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response frame for Model Context Protocol (MCP).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

const MAX_LINE_BYTES: usize = 1 << 20;

pub(crate) enum Line {
    Text(String),
    TooLong,
}

/// Reads one `\n`-terminated line without ever buffering more than `max` bytes; oversize lines are drained and reported.
pub(crate) fn read_capped_line<R: BufRead>(r: &mut R, max: usize) -> io::Result<Option<Line>> {
    use std::io::Read;
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > max && !buf.ends_with(b"\n") {
        loop {
            let mut sink = Vec::new();
            let m = r.by_ref().take(64 * 1024).read_until(b'\n', &mut sink)?;
            if m == 0 || sink.ends_with(b"\n") {
                break;
            }
        }
        return Ok(Some(Line::TooLong));
    }
    Ok(Some(Line::Text(String::from_utf8_lossy(&buf).into_owned())))
}

pub struct McpServer;

impl McpServer {
    /// Generates the ready-to-paste MCP configuration snippet for Cursor, Claude Code, and Antigravity.
    pub fn generate_config_snippet() -> String {
        let cfg = json!({
            "mcpServers": {
                "sentris": {
                    "command": "sentris",
                    "args": ["mcp"],
                    "description": "High-performance zero-knowledge secret scanner & autonomous safe remediator"
                }
            }
        });
        serde_json::to_string_pretty(&cfg).unwrap_or_default()
    }

    /// Runs the stdio JSON-RPC 2.0 MCP loop for AI coding agents.
    pub fn run_stdio_loop(offline: bool) -> Result<(), SentrisError> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        let mut input = stdin.lock();
        loop {
            let line = match read_capped_line(&mut input, MAX_LINE_BYTES) {
                Ok(Some(Line::Text(l))) => l,
                Ok(Some(Line::TooLong)) => {
                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0",
                        id: Value::Null,
                        result: None,
                        error: Some(json!({
                            "code": -32600,
                            "message": format!("Request exceeds {MAX_LINE_BYTES} bytes")
                        })),
                    };
                    if let Ok(serialized) = serde_json::to_string(&resp) {
                        let _ = writeln!(stdout, "{serialized}");
                        let _ = stdout.flush();
                    }
                    continue;
                }
                Ok(None) | Err(_) => break,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(resp) = Self::handle_raw_message(trimmed, offline) {
                if let Ok(serialized) = serde_json::to_string(&resp) {
                    let _ = writeln!(stdout, "{serialized}");
                    let _ = stdout.flush();
                }
            }
        }

        Ok(())
    }

    /// Processes a single JSON-RPC 2.0 request line and returns an optional response.
    /// Notifications (requests without an `id`) return `None`.
    pub fn handle_raw_message(raw_json: &str, offline: bool) -> Option<JsonRpcResponse> {
        let req: JsonRpcRequest = match serde_json::from_str(raw_json) {
            Ok(r) => r,
            Err(err) => {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(json!({
                        "code": -32700,
                        "message": format!("Parse error: {err}")
                    })),
                });
            }
        };

        // JSON-RPC notifications (e.g., notifications/initialized) do not expect a response
        let id = req.id?;

        let result = match req.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "sentris-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(Self::list_tools()),
            "tools/call" => Self::call_tool(req.params.as_ref(), offline),
            "resources/list" => Ok(Self::list_resources()),
            "resources/read" => Self::read_resource(req.params.as_ref()),
            "prompts/list" => Ok(Self::list_prompts()),
            "prompts/get" => Self::get_prompt(req.params.as_ref()),
            other => Err((-32601, format!("Method not found: {other}"))),
        };

        match result {
            Ok(val) => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(val),
                error: None,
            }),
            Err((code, msg)) => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(json!({
                    "code": code,
                    "message": msg
                })),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_initialize_and_tools_list() {
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = McpServer::handle_raw_message(init_req, true).expect("Expected response");
        assert_eq!(resp.id, json!(1));
        let res = resp.result.unwrap();
        assert_eq!(res["protocolVersion"], "2024-11-05");
        assert_eq!(res["serverInfo"]["name"], "sentris-mcp");

        let list_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let list_resp = McpServer::handle_raw_message(list_req, true).expect("Expected response");
        let tools = list_resp.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(tools.len(), 6);

        // Without credentials the tool reports an error instead of inventing sample data
        let _guard = crate::keystore::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let empty = tempfile::tempdir().unwrap();
        std::env::set_var("SENTRIS_CONFIG_DIR", empty.path());
        let br_req = r#"{
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "sentris_team_blast_radius",
                "arguments": {}
            }
        }"#;
        let br_resp = McpServer::handle_raw_message(br_req, true).expect("Expected response");
        std::env::remove_var("SENTRIS_CONFIG_DIR");
        assert!(br_resp.result.is_none());
        assert!(br_resp.error.unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("Not logged in"));
    }

    #[test]
    fn test_mcp_scan_path_tool_call() {
        let call_req = r#"{
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "sentris_scan_path",
                "arguments": {
                    "path": "tests/fixtures/sample_leak.ts"
                }
            }
        }"#;
        let resp = McpServer::handle_raw_message(call_req, true).expect("Expected response");
        let res = resp.result.unwrap();
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("stripe-secret-key"));
        assert!(text.contains("STRIPE_SECRET_KEY"));
    }

    #[test]
    fn test_mcp_config_snippet() {
        let snippet = McpServer::generate_config_snippet();
        assert!(snippet.contains("mcpServers"));
        assert!(snippet.contains("sentris"));
    }

    #[test]
    fn test_mcp_resources_prompts_and_agent_manifest() {
        let res_list = r#"{"jsonrpc":"2.0","id":10,"method":"resources/list"}"#;
        let resp = McpServer::handle_raw_message(res_list, true).expect("Expected response");
        let resources = resp.result.unwrap()["resources"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(resources.len(), 3);

        let res_read = r#"{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"sentris://agent/manifest"}}"#;
        let read_resp = McpServer::handle_raw_message(res_read, true).expect("Expected response");
        let manifest_text = read_resp.result.unwrap()["contents"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(manifest_text.contains("cli_commands"));
        assert!(manifest_text.contains("mcp_tools"));

        let prompts_list = r#"{"jsonrpc":"2.0","id":12,"method":"prompts/list"}"#;
        let p_resp = McpServer::handle_raw_message(prompts_list, true).expect("Expected response");
        let prompts = p_resp.result.unwrap()["prompts"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(prompts.len(), 2);

        let prompt_get = r#"{"jsonrpc":"2.0","id":13,"method":"prompts/get","params":{"name":"remediate-repo-secrets","arguments":{"path":"src"}}}"#;
        let pg_resp = McpServer::handle_raw_message(prompt_get, true).expect("Expected response");
        let msg = pg_resp.result.unwrap()["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("sentris_scan_path"));

        let tmp = tempfile::tempdir().unwrap();
        let written = McpServer::setup_workspace_for_agents(tmp.path()).unwrap();
        assert_eq!(written.len(), 2);
        assert!(tmp.path().join(".mcp.json").exists());
        assert!(tmp
            .path()
            .join(".agents/skills/sentris-security/SKILL.md")
            .exists());
    }

    #[test]
    fn oversize_line_is_drained_and_reported_without_buffering_it() {
        let mut data = vec![b'a'; 5000];
        data.extend_from_slice(b"\nnext\n");
        let mut r = std::io::Cursor::new(data);
        assert!(matches!(
            read_capped_line(&mut r, 1024).unwrap(),
            Some(Line::TooLong)
        ));
        match read_capped_line(&mut r, 1024).unwrap() {
            Some(Line::Text(t)) => assert_eq!(t.trim(), "next"),
            _ => panic!("expected the following line"),
        }
        assert!(read_capped_line(&mut r, 1024).unwrap().is_none());
    }
}
