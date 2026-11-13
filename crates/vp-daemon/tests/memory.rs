//! crypto §6.1: a running visipassd's memory is closed to the user's other
//! processes. Linux shows it through /proc: a process that is not dumpable has
//! its /proc files owned by root, so the user can no longer read them.

#[cfg(target_os = "linux")]
#[test]
fn other_processes_of_the_user_cannot_read_the_daemon() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if unsafe { libc::geteuid() } == 0 {
        return; // root reads anything; the property is about the user's own processes
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("vp.sock");
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_visipassd"))
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("VISIPASS_SOCKET", &socket)
        .env("VISIPASS_STATE_DIR", dir.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !socket.exists() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "visipassd did not start");

    let environ = std::fs::read(format!("/proc/{}/environ", daemon.id()));
    let mem = std::fs::File::open(format!("/proc/{}/mem", daemon.id()));
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    assert_eq!(
        environ.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        mem.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
