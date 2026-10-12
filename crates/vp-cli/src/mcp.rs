//! `vp mcp`: VisiPass as an MCP server over stdio (JSON-RPC 2.0, one message
//! per line).
//!
//! The tools find, inventory, audit, request, write and check env files, and
//! show grants and the log. None of them returns a secret value, and there is
//! deliberately no tool that reads or runs with one: agents use `vp run` /
//! `vp env run` in the shell for that, where the human sees the command in the
//! approval prompt.

use crate::{ImportOptions, client, env_import};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use vp_core::Failure;
use vp_core::env;
use vp_core::ipc::Request;
use vp_core::model::{Destination, Scope};

const PROTOCOL: &str = "2025-06-18";

const INSTRUCTIONS: &str = "VisiPass lets you work with secrets without seeing them. Tools return op:// references, never values. \
To use a secret, run commands through the shell with `vp run --env NAME=<ref> -- <command>` or `vp env run <file> -- <command>`; \
the human approves in a VisiPass window. If a secret does not exist yet, call request_secret: the human pastes it and you get a reference. \
If a request is denied or cancelled, do not retry; ask the human.";

fn tools() -> Value {
    let scope = json!({
        "vault": { "type": "string", "description": "Limit to this vault" },
    });
    json!([
        {
            "name": "find",
            "description": "Find secret references (op:// refs) by title, tag or website. Many queries in one call. Never returns values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "queries": { "type": "array", "items": { "type": "string" }, "description": "Search terms, e.g. [\"openai\", \"stripe live\"]" },
                    "vault": { "type": "string" }
                },
                "required": ["queries"]
            }
        },
        {
            "name": "inventory",
            "description": "Item and field metadata (titles, kinds, field labels, refs). Never values or URL query strings.",
            "inputSchema": { "type": "object", "properties": scope }
        },
        {
            "name": "audit",
            "description": "Organisation issues: duplicate titles, untagged machine credentials, stale logins, transient URLs.",
            "inputSchema": { "type": "object", "properties": scope }
        },
        {
            "name": "request_secret",
            "description": "Ask the human to paste a secret that does not exist yet (e.g. a new API key). They see a VisiPass window; you get back only the reference.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Item title, e.g. \"Stripe Live Key\"" },
                    "vault": { "type": "string", "description": "Destination vault; ask the human if unsure" },
                    "purpose": { "type": "string", "description": "Why you need it; shown to the human" },
                    "url": { "type": "string" },
                    "notes": { "type": "string" }
                },
                "required": ["title", "vault", "purpose"]
            }
        },
        {
            "name": "env_write",
            "description": "Write an env template of references (NAME=op://...). Replaces the file. Contains no values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file": { "type": "string" },
                    "assignments": { "type": "array", "items": { "type": "string" }, "description": "NAME=op://vault/item/field" }
                },
                "required": ["file", "assignments"]
            }
        },
        {
            "name": "env_check",
            "description": "Check that every reference in an env file resolves. Reports names only.",
            "inputSchema": { "type": "object", "properties": { "file": { "type": "string" } }, "required": ["file"] }
        },
        {
            "name": "env_import",
            "description": "Move plaintext secrets in an env file into the vault and rewrite them as references (one human approval). Use dry_run first to see what would move. Values are read by VisiPass, never returned to you.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file": { "type": "string" },
                    "vault": { "type": "string" },
                    "prefix": { "type": "string", "description": "Item title prefix; defaults to the project name" },
                    "dry_run": { "type": "boolean" },
                    "purpose": { "type": "string" }
                },
                "required": ["file", "vault"]
            }
        },
        {
            "name": "list_grants",
            "description": "Standing permissions the human has given (agent, project, operations, references).",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "recent_requests",
            "description": "The access log: what was requested, by whom, and the outcome. Never values.",
            "inputSchema": { "type": "object", "properties": { "limit": { "type": "integer" } } }
        }
    ])
}

fn text(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .filter(|s| !s.trim().is_empty())
}

fn required(args: &Value, key: &str) -> Result<String, Failure> {
    text(args, key).ok_or_else(|| Failure::new(format!("Missing \"{key}\"")))
}

fn call_tool(name: &str, args: &Value) -> Result<Value, Failure> {
    let scope = || Scope {
        account: None,
        vault: text(args, "vault"),
    };
    match name {
        "find" => {
            let queries: Vec<String> = args
                .get("queries")
                .and_then(Value::as_array)
                .map(|q| {
                    q.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            client::call(Request::Find {
                queries,
                scope: scope(),
            })
        }
        "inventory" => client::call(Request::Inventory { scope: scope() }),
        "audit" => client::call(Request::Audit { scope: scope() }),
        "request_secret" => client::call(Request::RequestSecret {
            destination: Destination {
                title: required(args, "title")?,
                vault: required(args, "vault")?,
                account: None,
                url: text(args, "url"),
                notes: text(args, "notes"),
            },
            purpose: text(args, "purpose"),
        }),
        "env_write" => {
            let file = PathBuf::from(required(args, "file")?);
            let assignments: Vec<env::Assignment> = args
                .get("assignments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(env::parse_assignment)
                .collect::<Result<_, _>>()?;
            if assignments.is_empty() {
                return Err(Failure::new("Give at least one NAME=op://reference"));
            }
            std::fs::write(&file, env::render_env(&assignments)).map_err(|e| {
                Failure::new(format!("Could not write {}: {}", file.display(), e.kind()))
            })?;
            Ok(json!({ "wrote": file, "references": assignments.len() }))
        }
        "env_check" => {
            let file = PathBuf::from(required(args, "file")?);
            let content = std::fs::read_to_string(&file).map_err(|e| {
                Failure::new(format!("Could not read {}: {}", file.display(), e.kind()))
            })?;
            client::call(Request::CheckRefs {
                refs: env::references(&env::parse_env(&content)),
            })
        }
        "env_import" => {
            let file = PathBuf::from(required(args, "file")?);
            env_import(
                &file,
                ImportOptions {
                    vault: required(args, "vault")?,
                    account: None,
                    prefix: text(args, "prefix"),
                    only: Vec::new(),
                    except: Vec::new(),
                    all: false,
                    dry_run: args
                        .get("dry_run")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    purpose: text(args, "purpose"),
                },
            )
        }
        "list_grants" => client::call(Request::Grants),
        "recent_requests" => {
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .min(200) as usize;
            client::call(Request::Log { limit })
        }
        other => Err(Failure::new(format!("Unknown tool \"{other}\""))),
    }
}

fn handle(message: &Value) -> Option<Value> {
    let id = message.get("id").cloned()?; // notifications get no reply
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "visipass", "version": env!("CARGO_PKG_VERSION") },
            "instructions": INSTRUCTIONS,
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            // Tool failures are results the agent can read, not protocol errors.
            Ok(match call_tool(name, &args) {
                Ok(value) => json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
                    "isError": false,
                }),
                Err(e) => json!({ "content": [{ "type": "text", "text": e.0 }], "isError": true }),
            })
        }
        _ => Err(json!({ "code": -32601, "message": format!("Method not found: {method}") })),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    })
}

pub fn serve() -> Result<i32, Failure> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle(&message),
            Err(_) => Some(
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
            ),
        };
        if let Some(reply) = reply
            && writeln!(stdout, "{reply}")
                .and_then(|_| stdout.flush())
                .is_err()
        {
            break;
        }
    }
    Ok(0)
}
