//! Talks to visipassd, starting it if needed.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vp_core::Failure;
use vp_core::ipc::{Envelope, PROTOCOL_VERSION, Request, Response};

// An approval can wait two minutes, and the backend may prompt as well.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(330);

pub use vp_core::paths::{socket, state_dir};

/// visipassd next to this binary, else on PATH.
pub fn daemon_program() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("visipassd")))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("visipassd"))
}

fn start_daemon() -> Result<(), Failure> {
    let state = state_dir();
    let _ = std::fs::create_dir_all(&state);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join("visipassd.log"))
        .ok();
    let mut command = Command::new(daemon_program());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log.map(Stdio::from).unwrap_or(Stdio::null()));
    // Detach from the agent's session so the daemon outlives the shell that started it.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|_| Failure::new("Could not start visipassd; is it installed next to vp?"))?;
    Ok(())
}

pub fn connect(autostart: bool) -> Result<UnixStream, Failure> {
    let path = socket();
    if let Ok(stream) = UnixStream::connect(&path) {
        return Ok(stream);
    }
    if !autostart {
        return Err(Failure::new("visipassd is not running"));
    }
    start_daemon()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(&path) {
            return Ok(stream);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(Failure::new(
        "visipassd did not start; see visipassd.log in the VisiPass state directory",
    ))
}

pub fn call_with(stream: UnixStream, request: Request) -> Result<Value, Failure> {
    let lost = || {
        Failure::new(
            "Lost the connection to visipassd. Do not retry a write; check with vp find first",
        )
    };
    let mut line = serde_json::to_string(&Envelope {
        version: PROTOCOL_VERSION,
        request,
        token: std::env::var("VISIPASS_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .map(vp_core::secret::Secret::new),
    })
    .map_err(|_| Failure::new("Could not encode the request"))?;
    line.push('\n');
    let mut writer = &stream;
    writer.write_all(line.as_bytes()).map_err(|_| lost())?;
    stream
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|_| lost())?;
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .map_err(|_| lost())?;
    match serde_json::from_str::<Response>(&reply).map_err(|_| lost())? {
        Response::Ok { result, .. } => Ok(result),
        Response::Err { error, .. } => Err(Failure::new(error)),
    }
}

pub fn call(request: Request) -> Result<Value, Failure> {
    call_with(connect(true)?, request)
}
