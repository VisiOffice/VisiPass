//! The app's private channel to visipassd: a socket pair the daemon created
//! and passed as fd 3. Only this channel may read and change values.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use vp_core::Failure;
use vp_core::ipc::{Envelope, PROTOCOL_VERSION, Request, Response};

pub struct Client {
    stream: Mutex<(BufReader<UnixStream>, UnixStream)>,
}

impl Client {
    /// The channel visipassd handed over, if this process was launched by it.
    pub fn inherited() -> Option<Self> {
        let fd: i32 = std::env::var("VISIPASS_APP_FD").ok()?.parse().ok()?;
        // SAFETY: only adopt the descriptor if it really is a socket.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0
            || (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK
        {
            return None;
        }
        // Children the app starts (a browser for a link) must not inherit it.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let reader = BufReader::new(stream.try_clone().ok()?);
        Some(Self {
            stream: Mutex::new((reader, stream)),
        })
    }

    /// One request, one response, in order. Blocking: call from a background task.
    pub fn call(&self, request: Request) -> Result<Value, Failure> {
        let lost = || {
            Failure::new(
                "Lost the connection to visipassd. Close the app and open it again with `vp app`",
            )
        };
        let mut line = serde_json::to_string(&Envelope {
            version: PROTOCOL_VERSION,
            request,
            token: None,
        })
        .map_err(|_| lost())?;
        line.push('\n');
        let mut guard = self.stream.lock().map_err(|_| lost())?;
        let (reader, writer) = &mut *guard;
        writer.write_all(line.as_bytes()).map_err(|_| lost())?;
        let mut reply = String::new();
        if reader.read_line(&mut reply).map_err(|_| lost())? == 0 {
            return Err(lost());
        }
        match serde_json::from_str::<Response>(&reply).map_err(|_| lost())? {
            Response::Ok { result, .. } => Ok(result),
            Response::Err { error, .. } => Err(Failure::new(error)),
        }
    }
}

/// Started from a launcher rather than by visipassd: ask the daemon to open
/// the real instance (starting the daemon if needed), then exit.
pub fn hand_off() -> Result<(), Failure> {
    let socket = vp_core::paths::socket();
    let connect = || UnixStream::connect(&socket);
    let stream = match connect() {
        Ok(stream) => stream,
        Err(_) => {
            let daemon = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|d| d.join("visipassd")))
                .filter(|p| p.is_file())
                .unwrap_or_else(|| "visipassd".into());
            let state = vp_core::paths::state_dir();
            let _ = std::fs::create_dir_all(&state);
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(state.join("visipassd.log"))
                .ok();
            let mut command = std::process::Command::new(daemon);
            command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(
                    log.map(std::process::Stdio::from)
                        .unwrap_or(std::process::Stdio::null()),
                );
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            command
                .spawn()
                .map_err(|_| Failure::new("Could not start visipassd"))?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Ok(stream) = connect() {
                    break stream;
                }
                if std::time::Instant::now() > deadline {
                    return Err(Failure::new("visipassd did not start"));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    let line = serde_json::to_string(&Envelope {
        version: PROTOCOL_VERSION,
        request: Request::OpenApp { quick: false },
        token: None,
    })
    .map_err(|_| Failure::new("Could not encode the request"))?
        + "\n";
    (&stream)
        .write_all(line.as_bytes())
        .map_err(|_| Failure::new("Could not reach visipassd"))?;
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .map_err(|_| Failure::new("Could not reach visipassd"))?;
    match serde_json::from_str::<Response>(&reply) {
        Ok(Response::Ok { result, .. }) => {
            if result.get("running").and_then(Value::as_bool) == Some(true) {
                vp_core::paths::focus_app_window();
            }
            Ok(())
        }
        Ok(Response::Err { error, .. }) => Err(Failure::new(error)),
        Err(_) => Err(Failure::new("visipassd sent an unexpected reply")),
    }
}
