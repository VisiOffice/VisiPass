//! End to end: the real `vp` binary against an in-process visipassd, a
//! scripted approver and a fake `op`. Every test asserts that the fictional
//! sentinel secrets never reach stdout, stderr, op's argv or the access log
//! unless the command's purpose is to deliver them.

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use vp_core::Failure;
use vp_daemon::Daemon;
use vp_daemon::approval::{Approver, Prompt};
use vp_daemon::grants::Decision;
use vp_op::OpBackend;

const OPENAI: &str = "sentinel-openai-1234567890";
const STRIPE: &str = "sentinel-stripe-abcdefghij";
const NEW_KEY: &str = "sentinel-new-key-zyxwvuts";
const SENTINELS: [&str; 3] = [OPENAI, STRIPE, NEW_KEY];

const FAKE_OP: &str = r#"#!/usr/bin/env python3
import json, os, sys
DIR = "__DIR__"
args = sys.argv[1:]
stdin = sys.stdin.read() if not sys.stdin.isatty() else ""
with open(os.path.join(DIR, "calls.jsonl"), "a") as f:
    f.write(json.dumps({"args": args, "stdin": stdin}) + "\n")
V = {"id": "vvvvvvvvvvvvvvvvvvvvvvvvvv", "name": "Dev"}
def item(i, title, value):
    return {"id": i * 26, "title": title, "category": "API_CREDENTIAL", "vault": V, "tags": [],
            "fields": [{"id": "credential", "type": "CONCEALED", "label": "credential", "value": value,
                        "reference": "op://Dev/" + title + "/credential"}]}
ITEMS = [item("o", "OpenAI API Key", "__OPENAI__"), item("s", "Stripe API Key", "__STRIPE__")]
VALUES = {f["reference"]: f["value"] for it in ITEMS for f in it["fields"]}
store = os.path.join(DIR, "created.json")
if args[:2] == ["item", "list"]:
    listed = [{k: it[k] for k in ("id", "title", "category", "vault", "tags")} for it in ITEMS]
    if os.path.exists(store):
        c = json.load(open(store))
        listed.append({k: c[k] for k in ("id", "title", "category", "vault")})
    print(json.dumps(listed))
elif args[:3] == ["item", "get", "-"]:
    wanted = {e["id"] for e in json.loads(stdin)}
    for it in ITEMS:
        if it["id"] in wanted:
            print(json.dumps(it))
elif args[0] == "run":
    n = int(args[-1])
    refs = [os.environ["VISIPASS_SECRET_%d" % i] for i in range(n)]
    if any(r not in VALUES for r in refs):
        sys.stderr.write("fake op: could not resolve a reference")
        sys.exit(1)
    print(json.dumps([VALUES[r] for r in refs]), end="")
elif args[:2] == ["item", "create"]:
    t = json.loads(stdin)
    t.update({"id": "c" * 26, "vault": V})
    json.dump(t, open(store, "w"))
    print(json.dumps({k: t[k] for k in ("id", "title", "category", "vault")}))
elif args[:2] == ["item", "get"] and "--reveal" in args:
    print(json.dumps(json.load(open(store))))
else:
    sys.stderr.write("fake op: unexpected " + " ".join(args))
    sys.exit(2)
"#;

/// Answers prompts from a script and counts them.
#[derive(Clone)]
struct Scripted(Arc<Mutex<(VecDeque<Decision>, usize)>>);

impl Scripted {
    fn asked(&self) -> usize {
        self.0.lock().unwrap().1
    }
}

impl Approver for Scripted {
    fn method(&self) -> &'static str {
        "scripted"
    }
    async fn ask(&self, _prompt: &Prompt) -> Result<Decision, Failure> {
        let mut state = self.0.lock().unwrap();
        state.1 += 1;
        Ok(state.0.pop_front().unwrap_or(Decision::Deny))
    }
    // Pastes NEW_KEY when the next scripted decision allows, nothing when it denies.
    async fn paste(&self, _prompt: &Prompt) -> Result<Option<vp_core::secret::Secret>, Failure> {
        let mut state = self.0.lock().unwrap();
        state.1 += 1;
        Ok(match state.0.pop_front() {
            Some(Decision::Deny) | None => None,
            Some(_) => Some(vp_core::secret::Secret::new(NEW_KEY.to_string())),
        })
    }
}

struct World {
    dir: tempfile::TempDir,
    approver: Scripted,
}

impl World {
    fn new(decisions: &[Decision]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        let script = FAKE_OP
            .replace("__DIR__", dir.path().to_str().unwrap())
            .replace("__OPENAI__", OPENAI)
            .replace("__STRIPE__", STRIPE);
        std::fs::write(&op, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(dir.path().join("state")).unwrap();

        let approver = Scripted(Arc::new(Mutex::new((
            decisions.iter().copied().collect(),
            0,
        ))));
        let socket = dir.path().join("vp.sock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let state = dir.path().join("state");
        let daemon_approver = approver.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let backend = OpBackend::with_program(op, vec!["helper".into()]);
                let daemon = Arc::new(Daemon::new(backend, daemon_approver, &state, socket));
                ready_tx.send(()).unwrap();
                daemon.serve(listener).await;
            });
        });
        ready_rx.recv().unwrap();
        World { dir, approver }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn vp(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vp"))
            .args(args)
            .current_dir(self.dir.path())
            .env("VISIPASS_SOCKET", self.path("vp.sock"))
            .env("VISIPASS_STATE_DIR", self.path("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
        drop(pipe);
        child.wait_with_output().unwrap()
    }

    fn calls(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.path("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// No sentinel in op's argv, ever, or in the access log.
    fn assert_contained(&self) {
        for call in self.calls() {
            let args = call["args"].to_string();
            for s in SENTINELS {
                assert!(!args.contains(s), "secret in op argv: {args}");
            }
        }
        let log = std::fs::read_to_string(self.path("state/access.log")).unwrap_or_default();
        for s in SENTINELS {
            assert!(!log.contains(s), "secret in access log");
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn clean(output: &Output) {
    for s in SENTINELS {
        assert!(
            !text(&output.stdout).contains(s),
            "secret on stdout: {}",
            text(&output.stdout)
        );
        assert!(
            !text(&output.stderr).contains(s),
            "secret on stderr: {}",
            text(&output.stderr)
        );
    }
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "vp failed: {}",
        text(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn find_batches_into_one_listing_and_one_detail_fetch() {
    let world = World::new(&[]);
    let out = world.vp(&["find", "openai", "strpe"], None);
    clean(&out);
    let result = json(&out);
    assert_eq!(
        result["matches"][0]["ref"],
        "op://Dev/OpenAI API Key/credential"
    );
    assert_eq!(result["suggestions"][0]["title"], "Stripe API Key");
    let calls = world.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(
        world.approver.asked(),
        0,
        "discovery needs no VisiPass approval"
    );
    world.assert_contained();
}

#[test]
fn run_masks_output_and_a_standing_grant_skips_the_prompt() {
    let world = World::new(&[Decision::Always]);
    let args = [
        "run",
        "--env",
        "KEY=op://Dev/OpenAI API Key/credential",
        "--",
        "sh",
        "-c",
        "echo key=$KEY; echo err=$KEY >&2",
    ];
    let out = world.vp(&args, None);
    assert!(out.status.success(), "{}", text(&out.stderr));
    clean(&out);
    assert_eq!(text(&out.stdout), "key=<vp:KEY>\n");
    assert_eq!(text(&out.stderr), "err=<vp:KEY>\n");
    assert_eq!(world.approver.asked(), 1);

    let again = world.vp(&args, None);
    clean(&again);
    assert_eq!(world.approver.asked(), 1, "covered by the grant");

    let grants = json(&world.vp(&["grant", "list"], None));
    assert_eq!(grants["grants"].as_array().unwrap().len(), 1);
    assert_eq!(grants["grants"][0]["operations"][0], "run");

    // A new reference is outside the grant, so the human is asked again (and denies).
    let other = world.vp(
        &[
            "run",
            "--env",
            "S=op://Dev/Stripe API Key/credential",
            "--",
            "true",
        ],
        None,
    );
    assert!(!other.status.success());
    assert!(text(&other.stderr).contains("denied"));
    assert_eq!(world.approver.asked(), 2);
    world.assert_contained();
}

#[test]
fn run_passes_the_exit_code_and_strips_tokens() {
    let world = World::new(&[Decision::Once]);
    let out = Command::new(env!("CARGO_BIN_EXE_vp"))
        .args([
            "run",
            "--env",
            "KEY=op://Dev/OpenAI API Key/credential",
            "--",
            "sh",
            "-c",
            "test -z \"$OP_SERVICE_ACCOUNT_TOKEN\" && exit 7",
        ])
        .env("VISIPASS_SOCKET", world.path("vp.sock"))
        .env("OP_SERVICE_ACCOUNT_TOKEN", "ops_fake")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
}

#[test]
fn denied_read_reveals_nothing() {
    let world = World::new(&[Decision::Deny]);
    let out = world.vp(&["read", "op://Dev/OpenAI API Key/credential"], None);
    assert_eq!(out.status.code(), Some(1));
    clean(&out);
    assert!(text(&out.stderr).starts_with("visipass: The human denied"));
    assert!(
        world.calls().is_empty(),
        "op is never called before approval"
    );
    let log = json(&world.vp(&["log"], None));
    assert_eq!(log["intact"], true);
    assert!(
        log["entries"][0]["outcome"]
            .as_str()
            .unwrap()
            .contains("denied")
    );
}

#[test]
fn read_is_the_explicit_way_to_see_a_value() {
    let world = World::new(&[Decision::Once]);
    let out = world.vp(
        &[
            "read",
            "op://Dev/OpenAI API Key/credential",
            "--purpose",
            "debug",
        ],
        None,
    );
    assert_eq!(text(&out.stdout), OPENAI);
    world.assert_contained();
}

#[test]
fn env_files_resolve_with_one_approval() {
    let world = World::new(&[Decision::Once, Decision::Once]);
    let template = world.path("app.env.tpl");
    let w = world.vp(
        &[
            "env",
            "write",
            template.to_str().unwrap(),
            "A=op://Dev/OpenAI API Key/credential",
            "B=op://Dev/Stripe API Key/credential",
        ],
        None,
    );
    assert!(w.status.success());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&template)
        .unwrap()
        .write_all(b"PLAIN=visible\n")
        .unwrap();

    let run = world.vp(
        &[
            "env",
            "run",
            template.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "echo $A $B $PLAIN",
        ],
        None,
    );
    clean(&run);
    assert_eq!(text(&run.stdout), "<vp:A> <vp:B> visible\n");

    let target = world.path(".env");
    let resolved = world.vp(
        &[
            "env",
            "resolve",
            template.to_str().unwrap(),
            "--output",
            target.to_str().unwrap(),
        ],
        None,
    );
    clean(&resolved);
    assert!(text(&resolved.stderr).contains("plaintext"));
    let content = std::fs::read_to_string(&target).unwrap();
    assert!(content.contains(&format!("A=\"{OPENAI}\"")));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        world.approver.asked(),
        2,
        "one prompt per command, not per reference"
    );
    let runs = world
        .calls()
        .iter()
        .filter(|c| c["args"][0] == "run")
        .count();
    assert_eq!(runs, 2, "one op run per command");
    world.assert_contained();
}

#[test]
fn create_sends_the_value_on_stdin_only_and_verifies() {
    let world = World::new(&[Decision::Once]);
    let out = world.vp(
        &[
            "create",
            "api-credential",
            "--title",
            "New Key",
            "--vault",
            "Dev",
            "--stdin",
        ],
        Some(&format!("{NEW_KEY}\n")),
    );
    clean(&out);
    let receipt = json(&out);
    assert_eq!(receipt["verified"], true);
    assert_eq!(
        receipt["ref"],
        format!("op://{}/{}/credential", "v".repeat(26), "c".repeat(26))
    );
    let create = world
        .calls()
        .into_iter()
        .find(|c| c["args"][1] == "create")
        .unwrap();
    assert!(
        create["stdin"].as_str().unwrap().contains(NEW_KEY),
        "value travels on stdin"
    );
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(world.path("created.json")).unwrap())
            .unwrap();
    assert_eq!(
        stored["fields"][0]["value"], NEW_KEY,
        "one trailing newline stripped"
    );
    world.assert_contained();

    let duplicate = world.vp(
        &[
            "create",
            "api-credential",
            "--title",
            "new key",
            "--vault",
            "Dev",
            "--stdin",
        ],
        Some("other-value-123"),
    );
    assert!(!duplicate.status.success());
}

#[test]
fn create_refuses_a_value_as_an_argument_or_from_a_missing_source() {
    let world = World::new(&[]);
    let out = world.vp(
        &["create", "api-credential", "--title", "T", "--vault", "Dev"],
        None,
    );
    assert!(text(&out.stderr).contains("exactly one of --clipboard or --stdin"));
    let out = world.vp(
        &["run", "--env", &format!("K={OPENAI}"), "--", "true"],
        None,
    );
    assert!(!out.status.success());
    clean(&out);
}

#[test]
fn app_only_requests_are_refused_on_the_public_socket() {
    use std::io::{BufRead, BufReader};
    let world = World::new(&[]);
    for request in [
        serde_json::json!({"type": "item", "id": "o".repeat(26), "vault": "Dev"}),
        serde_json::json!({"type": "items"}),
        serde_json::json!({"type": "vaults"}),
        serde_json::json!({"type": "archive", "id": "o".repeat(26), "vault": "Dev"}),
        serde_json::json!({"type": "set-favorite", "id": "o".repeat(26), "vault": "Dev", "favorite": true}),
        serde_json::json!({"type": "save-item", "item": {"title": "x", "category": "LOGIN", "vault": {"id": "v", "name": "Dev"}}}),
    ] {
        let stream = std::os::unix::net::UnixStream::connect(world.path("vp.sock")).unwrap();
        let line = serde_json::json!({"version": 1, "request": request}).to_string() + "\n";
        (&stream).write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply).unwrap();
        clean_text(&reply);
        assert!(reply.contains("Only the VisiPass app"), "{reply}");
    }
    assert!(world.calls().is_empty(), "op is never called");
    world.assert_contained();
}

fn clean_text(text: &str) {
    for s in SENTINELS {
        assert!(!text.contains(s), "secret leaked: {text}");
    }
}

#[test]
fn request_saves_the_pasted_secret_and_returns_only_a_reference() {
    let world = World::new(&[Decision::Once]);
    let out = world.vp(
        &[
            "request",
            "--title",
            "Pasted Key",
            "--vault",
            "Dev",
            "--purpose",
            "deploy",
        ],
        None,
    );
    clean(&out);
    let receipt = json(&out);
    assert_eq!(receipt["verified"], true);
    assert!(receipt["ref"].as_str().unwrap().starts_with("op://"));
    assert_eq!(world.approver.asked(), 1);
    let create = world
        .calls()
        .into_iter()
        .find(|c| c["args"][1] == "create")
        .unwrap();
    assert!(
        create["stdin"].as_str().unwrap().contains(NEW_KEY),
        "value travels to op on stdin"
    );
    world.assert_contained();
    let log = json(&world.vp(&["log"], None));
    assert_eq!(log["entries"][0]["request"], "request");
}

#[test]
fn a_cancelled_request_saves_nothing() {
    let world = World::new(&[Decision::Deny]);
    let out = world.vp(
        &["request", "--title", "Pasted Key", "--vault", "Dev"],
        None,
    );
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("cancelled"));
    assert!(world.calls().is_empty(), "op is never called");
}

#[test]
fn env_import_moves_secrets_and_keeps_settings() {
    let world = World::new(&[Decision::Once]);
    let file = world.path("app.env");
    std::fs::write(
        &file,
        format!("# app\nexport NEW_API_KEY={NEW_KEY}\nPORT=3000\n"),
    )
    .unwrap();
    let dry = json(&world.vp(
        &[
            "env",
            "import",
            file.to_str().unwrap(),
            "--vault",
            "Dev",
            "--prefix",
            "app",
            "--dry-run",
        ],
        None,
    ));
    assert_eq!(dry["wouldImport"][0]["name"], "NEW_API_KEY");
    assert_eq!(dry["kept"][0], "PORT");
    assert_eq!(world.approver.asked(), 0, "a dry run asks nothing");

    let out = world.vp(
        &[
            "env",
            "import",
            file.to_str().unwrap(),
            "--vault",
            "Dev",
            "--prefix",
            "app",
        ],
        None,
    );
    clean(&out);
    let result = json(&out);
    assert_eq!(result["imported"][0]["name"], "NEW_API_KEY");
    let rewritten = std::fs::read_to_string(&file).unwrap();
    assert!(!rewritten.contains(NEW_KEY), "{rewritten}");
    assert!(
        rewritten.contains("export NEW_API_KEY=op://"),
        "{rewritten}"
    );
    assert!(rewritten.contains("PORT=3000"));
    assert_eq!(world.approver.asked(), 1, "one approval for the file");
    world.assert_contained();
}

#[test]
fn env_check_reports_without_revealing() {
    let world = World::new(&[]);
    let file = world.path("check.env");
    std::fs::write(
        &file,
        "A=op://Dev/OpenAI API Key/credential\nB=op://Dev/Missing/credential\n",
    )
    .unwrap();
    let out = world.vp(&["env", "check", file.to_str().unwrap()], None);
    clean(&out);
    assert_eq!(out.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"][0], "op://Dev/OpenAI API Key/credential");
    assert_eq!(result["unresolved"][0], "op://Dev/Missing/credential");
    assert_eq!(world.approver.asked(), 0);
}

#[test]
fn mcp_serves_tools_that_never_return_values() {
    let world = World::new(&[Decision::Once]);
    let messages = [
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "find", "arguments": {"queries": ["openai"]}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "request_secret", "arguments": {"title": "Mcp Key", "vault": "Dev", "purpose": "test"}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}),
    ];
    let input: String = messages.iter().map(|m| m.to_string() + "\n").collect();
    let out = world.vp(&["mcp"], Some(&input));
    clean(&out);
    let replies: Vec<serde_json::Value> = text(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 5, "no reply to the notification");
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "visipass");
    let names: Vec<&str> = replies[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"find") && names.contains(&"request_secret"));
    assert!(
        !names
            .iter()
            .any(|n| n.contains("read") || n.contains("run")),
        "{names:?}"
    );
    assert!(
        replies[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("op://Dev/OpenAI API Key/credential")
    );
    assert_eq!(replies[3]["result"]["isError"], false);
    assert!(
        replies[3]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("\"verified\": true")
    );
    assert_eq!(replies[4]["result"]["isError"], true);
    world.assert_contained();
}

#[test]
fn agent_tokens_run_within_scope_and_never_prompt() {
    let world = World::new(&[Decision::Once]);
    let created = json(&world.vp(
        &[
            "agent", "create", "nightly", "--vault", "Dev", "--ops", "run", "--days", "7",
        ],
        None,
    ));
    assert_eq!(world.approver.asked(), 1, "creating a token asks the human");
    let token = created["token"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();
    let with_token = |args: &[&str], token: &str| {
        Command::new(env!("CARGO_BIN_EXE_vp"))
            .args(args)
            .env("VISIPASS_SOCKET", world.path("vp.sock"))
            .env("VISIPASS_TOKEN", token)
            .output()
            .unwrap()
    };
    let run = with_token(
        &[
            "run",
            "--env",
            "K=op://Dev/OpenAI API Key/credential",
            "--",
            "sh",
            "-c",
            "echo $K; echo token=${VISIPASS_TOKEN:-gone}",
        ],
        &token,
    );
    assert!(run.status.success(), "{}", text(&run.stderr));
    assert_eq!(
        text(&run.stdout),
        "<vp:K>\ntoken=gone\n",
        "masked, and the token is stripped from the child"
    );
    assert_eq!(world.approver.asked(), 1, "a token never prompts");

    let reveal = with_token(&["read", "op://Dev/OpenAI API Key/credential"], &token);
    assert!(!reveal.status.success());
    assert!(text(&reveal.stderr).contains("does not allow"));
    let other_vault = with_token(
        &["run", "--env", "K=op://Private/Bank/password", "--", "true"],
        &token,
    );
    assert!(!other_vault.status.success());
    let mint = with_token(&["agent", "create", "more", "--vault", "Dev"], &token);
    assert!(text(&mint.stderr).contains("cannot create tokens"));
    let bogus = with_token(&["find", "openai"], "vpt_bogus");
    assert!(text(&bogus.stderr).contains("not valid"));

    let listed = json(&world.vp(&["agent", "list"], None));
    assert!(
        !listed.to_string().contains(&token),
        "the secret is never listed"
    );
    json(&world.vp(&["agent", "revoke", &id], None));
    let after = with_token(&["find", "openai"], &token);
    assert!(text(&after.stderr).contains("not valid"));
    let log = std::fs::read_to_string(world.path("state/access.log")).unwrap();
    assert!(!log.contains(&token));
    assert!(log.contains("token nightly"));
}

#[test]
fn doctor_never_prompts() {
    let world = World::new(&[]);
    let out = world.vp(&["doctor"], None);
    assert!(out.status.success());
    assert_eq!(world.approver.asked(), 0);
    assert!(world.calls().is_empty());
}
