//! Running a command with secrets in its environment, its output masked.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use vp_core::Failure;
use vp_core::mask::Masker;
use vp_core::secret::Secret;

/// Credentials that authorise VisiPass itself never reach the child.
const STRIPPED: [&str; 4] = [
    "VISIPASS_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "OP_CONNECT_TOKEN",
    "OP_SESSION",
];

fn pump(
    mut from: impl Read + Send + 'static,
    mut to: impl Write + Send + 'static,
    mut masker: Option<Masker>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        loop {
            let n = match from.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let out = match masker.as_mut() {
                Some(m) => m.push(&buffer[..n]),
                None => buffer[..n].to_vec(),
            };
            if to.write_all(&out).and_then(|_| to.flush()).is_err() {
                return;
            }
        }
        if let Some(m) = masker.as_mut() {
            let _ = to.write_all(&m.finish());
            let _ = to.flush();
        }
    })
}

/// Runs `command` with `env` added and returns its exit code (128 + signal if killed).
pub fn run(command: &[String], env: &[(String, Secret)], mask: bool) -> Result<i32, Failure> {
    run_with_literals(command, env, &[], mask)
}

/// As `run`, plus non-secret variables that are set but never masked.
pub fn run_with_literals(
    command: &[String],
    secrets: &[(String, Secret)],
    literals: &[(String, Secret)],
    mask: bool,
) -> Result<i32, Failure> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| Failure::new("Give a command after --"))?;
    let masker = || {
        if mask {
            Masker::new(secrets.iter().map(|(k, v)| (k.as_str(), v.expose())))
        } else {
            None
        }
    };
    let (out_mask, err_mask) = (masker(), masker());
    let mut child_command = Command::new(program);
    child_command.args(args).stdin(Stdio::inherit());
    for name in STRIPPED {
        child_command.env_remove(name);
    }
    // op signs in per account as OP_SESSION_<account>.
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|n| n.starts_with("OP_SESSION_")) {
            child_command.env_remove(name);
        }
    }
    child_command.envs(literals.iter().chain(secrets).map(|(k, v)| (k, v.expose())));
    child_command.stdout(if out_mask.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    child_command.stderr(if err_mask.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let mut child = child_command
        .spawn()
        .map_err(|e| Failure::new(format!("Could not run {program}: {}", e.kind())))?;
    // Ctrl-C goes to the child (same process group); vp stays to drain and mask its output.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    let pumps: Vec<_> = [
        child
            .stdout
            .take()
            .map(|s| pump(s, std::io::stdout(), out_mask)),
        child
            .stderr
            .take()
            .map(|s| pump(s, std::io::stderr(), err_mask)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let status = child
        .wait()
        .map_err(|_| Failure::new(format!("Lost track of {program}")))?;
    for p in pumps {
        let _ = p.join();
    }
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}
