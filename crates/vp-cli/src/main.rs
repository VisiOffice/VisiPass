//! vp: find, use and save secrets without exposing them.
//!
//! This file only parses flags, calls visipassd, and prints JSON. Results go to
//! stdout, notices to stderr, and expected errors print `visipass: <message>`
//! with exit code 1. Secrets reach stdout only from `read` and `inject` without
//! `--output`.

mod client;
mod doctor;
mod input;
mod run;

use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use vp_core::env::{self, Assignment};
use vp_core::ipc::{Request, Usage};
use vp_core::model::{Destination, PasswordRequest, Scope};
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;
use vp_core::{Failure, template};

#[derive(Parser)]
#[command(
    name = "vp",
    version,
    about = "Find, use and save secrets without exposing them to coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct ScopeArgs {
    /// Limit results to a vault
    #[arg(long)]
    vault: Option<String>,
    /// 1Password account
    #[arg(long)]
    account: Option<String>,
}

impl From<ScopeArgs> for Scope {
    fn from(a: ScopeArgs) -> Self {
        Scope {
            account: a.account,
            vault: a.vault,
        }
    }
}

#[derive(Args)]
struct Purpose {
    /// Why you need it, shown to the human in the approval prompt
    #[arg(long)]
    purpose: Option<String>,
}

#[derive(Args)]
struct SourceArgs {
    /// Read the clipboard without printing or clearing it
    #[arg(long)]
    clipboard: bool,
    /// Read piped stdin, never an argument
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Find secret references without revealing values; many queries, one approval
    Find {
        /// One or more title or tag queries; quote queries containing spaces
        #[arg(required = true)]
        queries: Vec<String>,
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// List item and field metadata without revealing values
    Inventory {
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Report organisation issues without revealing values
    Audit {
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Run a command with secret references injected into its environment
    Run {
        /// NAME=op://reference; repeat for each secret
        #[arg(long = "env", required = true)]
        env: Vec<String>,
        /// Show injected values in the command's output instead of masking them
        #[arg(long)]
        no_mask: bool,
        #[command(flatten)]
        purpose: Purpose,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Create, resolve, and use env files of secret references
    #[command(subcommand)]
    Env(EnvCommands),
    /// Fill {{ op://... }} references in a template file
    Inject {
        /// Template file
        #[arg(short, long)]
        input: PathBuf,
        /// Write the result here (mode 0600); without it the result goes to stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        purpose: Purpose,
    },
    /// Explicitly write one secret value to stdout. Last resort; prefer run
    Read {
        reference: String,
        #[command(flatten)]
        purpose: Purpose,
    },
    /// Create a new credential from private input
    #[command(subcommand)]
    Create(CreateCommands),
    /// Compare, or update and verify, a login password from private input
    Password {
        item: String,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        account: Option<String>,
        #[command(flatten)]
        source: SourceArgs,
        /// Update and verify; otherwise only compare
        #[arg(long)]
        apply: bool,
        /// Preserve unnamed imported fields under concealed labels; requires --apply
        #[arg(long)]
        repair_imported_fields: bool,
        #[command(flatten)]
        purpose: Purpose,
    },
    /// List or revoke the standing grants the human has given
    #[command(subcommand)]
    Grant(GrantCommands),
    /// Show the access log (never contains values)
    Log {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Open the VisiPass desktop app to browse, add and edit items
    App,
    /// Show whether visipassd is running and how it asks for approval
    Status,
    /// Check the setup without authenticating or prompting; safe to paste into an issue
    Doctor,
    /// Run visipassd in this terminal, so approvals can be answered here
    Daemon {
        /// Stop the running daemon
        #[arg(long, conflicts_with = "restart")]
        stop: bool,
        /// Stop the running daemon, then run a new one here
        #[arg(long)]
        restart: bool,
    },
}

#[derive(Subcommand)]
enum EnvCommands {
    /// Replace an env file with secret references
    Write {
        file: PathBuf,
        /// NAME=op://reference, one per variable
        #[arg(required = true)]
        assignments: Vec<String>,
    },
    /// Run a command from a reference-based env file; one approval for every reference
    Run {
        file: PathBuf,
        #[arg(long)]
        no_mask: bool,
        #[command(flatten)]
        purpose: Purpose,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Materialise references into a plaintext env file (mode 0600)
    Resolve {
        file: PathBuf,
        #[arg(
            long,
            conflicts_with = "in_place",
            required_unless_present = "in_place"
        )]
        output: Option<PathBuf>,
        #[arg(long)]
        in_place: bool,
        #[command(flatten)]
        purpose: Purpose,
    },
}

#[derive(Subcommand)]
enum CreateCommands {
    /// Create and verify an API Credential without revealing its value
    ApiCredential {
        /// Non-secret item title, e.g. "Example API Key"
        #[arg(long)]
        title: String,
        /// Destination vault name or ID; required, no implicit default
        #[arg(long)]
        vault: String,
        #[arg(long)]
        account: Option<String>,
        #[command(flatten)]
        source: SourceArgs,
        /// Optional non-secret website URL
        #[arg(long)]
        url: Option<String>,
        /// Optional non-secret notes
        #[arg(long)]
        notes: Option<String>,
        #[command(flatten)]
        purpose: Purpose,
    },
}

#[derive(Subcommand)]
enum GrantCommands {
    /// List active grants
    List,
    /// Revoke a grant, or all of them
    Revoke {
        #[arg(required_unless_present = "all")]
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

// Parsed here rather than by clap, whose errors echo the rejected value: a
// mistyped --env may hold a pasted secret.
fn assignments(inputs: &[String]) -> Result<Vec<Assignment>, Failure> {
    inputs.iter().map(|i| env::parse_assignment(i)).collect()
}

fn print(value: &Value) -> Result<i32, Failure> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|_| Failure::new("Could not encode the result"))?;
    println!("{text}");
    Ok(0)
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn read_text(path: &Path) -> Result<String, Failure> {
    std::fs::read_to_string(path)
        .map_err(|e| Failure::new(format!("Could not read {}: {}", path.display(), e.kind())))
}

/// Resolves references through the daemon, which checks grants or asks the human.
fn resolve(
    refs: &[SecretRef],
    usage: Usage,
    purpose: Option<String>,
) -> Result<HashMap<SecretRef, Secret>, Failure> {
    if refs.is_empty() {
        return Ok(HashMap::new());
    }
    let result = client::call(Request::Resolve {
        refs: refs.to_vec(),
        usage,
        purpose,
    })?;
    let values: Vec<Secret> =
        serde_json::from_value(result.get("values").cloned().unwrap_or(Value::Null))
            .map_err(|_| Failure::new("visipassd returned an invalid secret batch"))?;
    if values.len() != refs.len() {
        return Err(Failure::new("visipassd returned an invalid secret batch"));
    }
    Ok(refs.iter().cloned().zip(values).collect())
}

/// Writes plaintext atomically with mode 0600.
fn write_private(target: &Path, contents: &Secret) -> Result<(), Failure> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents.expose().as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|e| {
        Failure::new(format!(
            "Could not write {}: {}",
            target.display(),
            e.kind()
        ))
    })
}

fn execute(command: Commands) -> Result<i32, Failure> {
    match command {
        Commands::Find { queries, scope } => print(&client::call(Request::Find {
            queries,
            scope: scope.into(),
        })?),
        Commands::Inventory { scope } => print(&client::call(Request::Inventory {
            scope: scope.into(),
        })?),
        Commands::Audit { scope } => print(&client::call(Request::Audit {
            scope: scope.into(),
        })?),
        Commands::Run {
            env,
            no_mask,
            purpose,
            command,
        } => {
            let env = assignments(&env)?;
            let refs = unique(env.iter().map(|a| a.reference.clone()));
            let values = resolve(
                &refs,
                Usage::Run {
                    command: command.clone(),
                },
                purpose.purpose,
            )?;
            let injected: Vec<(String, Secret)> = env
                .iter()
                .map(|a| (a.name.clone(), values[&a.reference].clone()))
                .collect();
            run::run(&command, &injected, !no_mask)
        }
        Commands::Env(EnvCommands::Write {
            file,
            assignments: inputs,
        }) => {
            let assignments = assignments(&inputs)?;
            std::fs::write(&file, env::render_env(&assignments)).map_err(|e| {
                Failure::new(format!("Could not write {}: {}", file.display(), e.kind()))
            })?;
            eprintln!(
                "Wrote {} secret references to {}",
                assignments.len(),
                file.display()
            );
            Ok(0)
        }
        Commands::Env(EnvCommands::Run {
            file,
            no_mask,
            purpose,
            command,
        }) => {
            let lines = env::parse_env(&read_text(&file)?);
            let refs = env::references(&lines);
            let values = resolve(
                &refs,
                Usage::Run {
                    command: command.clone(),
                },
                purpose.purpose,
            )?;
            let injected = env::environment(&lines, &values)?;
            // Literal assignments in the file are not secrets; mask only resolved references.
            let secret_names: Vec<String> = lines
                .iter()
                .filter_map(|l| match l {
                    env::EnvLine::Reference { name, .. } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            let (secrets, literals): (Vec<_>, Vec<_>) = injected
                .into_iter()
                .partition(|(name, _)| secret_names.contains(name));
            let code = run::run_with_literals(&command, &secrets, &literals, !no_mask)?;
            Ok(code)
        }
        Commands::Env(EnvCommands::Resolve {
            file,
            output,
            in_place,
            purpose,
        }) => {
            let target = absolute(if in_place {
                &file
            } else {
                output.as_deref().unwrap_or(&file)
            });
            let lines = env::parse_env(&read_text(&file)?);
            let refs = env::references(&lines);
            let values = resolve(
                &refs,
                Usage::Materialize {
                    target: target.display().to_string(),
                },
                purpose.purpose,
            )?;
            let (content, count) = env::resolve_env(&lines, &values)?;
            write_private(&target, &content)?;
            eprintln!(
                "Resolved {count} secret references into {}; this file now contains plaintext secrets",
                target.display()
            );
            Ok(0)
        }
        Commands::Inject {
            input,
            output,
            purpose,
        } => {
            let text = read_text(&input)?;
            let refs = template::references(&text)?;
            let usage = match &output {
                Some(path) => Usage::Materialize {
                    target: absolute(path).display().to_string(),
                },
                None => Usage::Reveal,
            };
            let values = resolve(&refs, usage, purpose.purpose)?;
            let rendered = template::render(&text, &values)?;
            match output {
                Some(path) => {
                    write_private(&absolute(&path), &rendered)?;
                    eprintln!(
                        "Injected {} secret references into {}; this file now contains plaintext secrets",
                        refs.len(),
                        path.display()
                    );
                }
                None => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout
                        .write_all(rendered.expose().as_bytes())
                        .and_then(|_| stdout.flush());
                }
            }
            Ok(0)
        }
        Commands::Read { reference, purpose } => {
            let reference = SecretRef::parse(&reference)?;
            let values = resolve(
                std::slice::from_ref(&reference),
                Usage::Reveal,
                purpose.purpose,
            )?;
            let mut stdout = std::io::stdout().lock();
            let _ = stdout
                .write_all(values[&reference].expose().as_bytes())
                .and_then(|_| stdout.flush());
            Ok(0)
        }
        Commands::Create(CreateCommands::ApiCredential {
            title,
            vault,
            account,
            source,
            url,
            notes,
            purpose,
        }) => {
            if title.trim().is_empty() || vault.trim().is_empty() {
                return Err(Failure::new(
                    "A non-empty --title and explicit --vault are required",
                ));
            }
            let source = input::source(source.clipboard, source.stdin)?;
            let raw = input::read(source, "credential", "nothing was created")?;
            // Strip one terminal line ending for pipe/clipboard convenience; other whitespace may be meaningful.
            let value = raw.expose();
            let value = Secret::new(
                value
                    .strip_suffix('\n')
                    .map(|v| v.strip_suffix('\r').unwrap_or(v))
                    .unwrap_or(value)
                    .to_string(),
            );
            let destination = Destination {
                title: title.trim().into(),
                vault: vault.trim().into(),
                account,
                url,
                notes,
            };
            print(&client::call(Request::CreateApiCredential {
                destination,
                value,
                purpose: purpose.purpose,
            })?)
        }
        Commands::Password {
            item,
            vault,
            account,
            source,
            apply,
            repair_imported_fields,
            purpose,
        } => {
            if repair_imported_fields && !apply {
                return Err(Failure::new("--repair-imported-fields requires --apply"));
            }
            let source = input::source(source.clipboard, source.stdin)?;
            // Passwords are exact strings: unlike API credentials, never trim a newline.
            let value = input::read(source, "password", "nothing was changed")?;
            let request = PasswordRequest {
                item,
                vault,
                account,
                apply,
                repair_imported_fields,
            };
            print(&client::call(Request::Password {
                request,
                value,
                purpose: purpose.purpose,
            })?)
        }
        Commands::Grant(GrantCommands::List) => print(&client::call(Request::Grants)?),
        Commands::Grant(GrantCommands::Revoke { id, all }) => {
            print(&client::call(Request::Revoke { id, all })?)
        }
        Commands::Log { limit } => print(&client::call(Request::Log { limit })?),
        Commands::App => {
            let result = client::call(Request::OpenApp)?;
            if result.get("running").and_then(Value::as_bool) == Some(true) {
                vp_core::paths::focus_app_window();
            }
            print(&result)
        }
        Commands::Status => match client::connect(false) {
            Ok(stream) => print(&client::call_with(stream, Request::Status)?),
            Err(_) => print(&serde_json::json!({ "running": false })),
        },
        Commands::Doctor => print(&doctor::doctor()),
        Commands::Daemon { stop, restart } => daemon(stop, restart),
    }
}

fn unique(refs: impl Iterator<Item = SecretRef>) -> Vec<SecretRef> {
    let mut out: Vec<SecretRef> = Vec::new();
    for r in refs {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

fn daemon(stop: bool, restart: bool) -> Result<i32, Failure> {
    if stop || restart {
        if let Ok(stream) = client::connect(false) {
            let status = client::call_with(stream, Request::Status)?;
            let pid = status
                .get("pid")
                .and_then(Value::as_i64)
                .ok_or_else(|| Failure::new("visipassd did not report its PID"))?;
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while client::connect(false).is_ok() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            eprintln!("Stopped visipassd");
        }
        if stop {
            return Ok(0);
        }
    }
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new(client::daemon_program()).exec();
    Err(Failure::new(format!(
        "Could not run visipassd: {}",
        error.kind()
    )))
}

fn main() {
    let cli = Cli::parse();
    let code = match execute(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("visipass: {e}");
            1
        }
    };
    std::process::exit(code);
}
