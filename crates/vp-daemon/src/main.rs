use std::io::IsTerminal;
use std::sync::Arc;
use tokio::net::UnixListener;
use vp_daemon::approval::Desktop;
use vp_daemon::phones::{Phones, WithPhones};
use vp_daemon::routed::{Routed, WindowUnlock};
use vp_daemon::{Daemon, paths};
use vp_native::{NativeBackend, Paths};
use vp_op::OpBackend;

const DUMP_SECRETS: &str = "__dump-secrets";

fn fail(message: &str) -> ! {
    eprintln!("visipassd: {message}");
    std::process::exit(1)
}

/// crypto §6.1: no core dumps, and no other process of this user (an agent
/// included) can read this one's memory through ptrace or /proc/<pid>/mem.
/// First thing, before any key or secret exists; children reset it on exec.
fn close_memory() {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        fail("could not turn off core dumps");
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        fail("could not close its memory to other processes");
    }
    // The hardened runtime (packaging/macos) already refuses task_for_pid to
    // the same user; this also refuses a debugger attaching by ptrace.
    #[cfg(target_os = "macos")]
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        fail("could not close its memory to debuggers");
    }
}

fn main() {
    close_memory();
    let args: Vec<String> = std::env::args().collect();
    // The helper `op run` executes to hand resolved references back to the daemon.
    if args.get(1).map(String::as_str) == Some(DUMP_SECRETS) {
        let count = args.get(2).and_then(|n| n.parse().ok()).unwrap_or(0);
        std::process::exit(if vp_op::dump_secrets(count) { 0 } else { 1 });
    }
    match args.get(1).map(String::as_str) {
        None => {}
        Some("--version") => {
            println!("visipassd {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(_) => fail("usage: visipassd [--version]. Start it with `vp daemon`"),
    }

    unsafe { libc::umask(0o077) };
    // Nothing the daemon runs should resolve relative to a repository it was started in.
    if std::env::set_current_dir("/").is_err() {
        fail("could not leave the starting directory");
    }
    // Before any thread starts: the prompt and the app inherit the session found
    // here, not whatever display the caller that started the daemon had set.
    let display = vp_daemon::approval::find_display();
    for (name, value) in &display {
        unsafe { std::env::set_var(name, value) };
    }
    let human_terminal =
        std::io::stdin().is_terminal() && vp_daemon::procinfo::human_terminal(std::process::id());
    let approver = Desktop::detect(!display.is_empty(), human_terminal);
    if matches!(approver, Desktop::Unavailable) && std::io::stdin().is_terminal() {
        eprintln!(
            "visipassd: no desktop session, and this terminal cannot answer approvals: it is not a terminal window, SSH or console login, or a coding agent started it"
        );
    }
    let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|_| fail("could not start"));
    runtime.block_on(run(approver));
}

/// Listens for paired phones once the unlocked vault has any, so a phone can
/// reach visipassd after a restart without waiting for the next question.
async fn listen_for_phones(phones: Arc<Phones>) {
    loop {
        if matches!(phones.pairings(), Ok(Some(p)) if !p.is_empty()) {
            if let Err(e) = phones.listen().await {
                eprintln!("visipassd: {e}");
            }
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}

async fn run(approver: Desktop) {
    let socket = paths::socket();
    let state = paths::state_dir();
    for dir in [socket.parent(), Some(state.as_path())]
        .into_iter()
        .flatten()
    {
        if paths::private_dir(dir).is_err() {
            fail(&format!("could not create {}", dir.display()));
        }
    }
    if tokio::net::UnixStream::connect(&socket).await.is_ok() {
        eprintln!("visipassd: already running at {}", socket.display());
        return;
    }
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .unwrap_or_else(|_| fail(&format!("could not listen on {}", socket.display())));

    let exe =
        std::env::current_exe().unwrap_or_else(|_| fail("could not locate its own executable"));
    // VisiPass's own vault once `vp init` has made one; 1Password until then.
    let native = NativeBackend::new(Paths::standard(), WindowUnlock(approver.clone()));
    tokio::spawn(vp_daemon::session::watch(native.clone()));
    // Phones are asked alongside the desktop; unlocking stays at the computer.
    let phones = Phones::new(native.clone(), vp_daemon::phones::PORT);
    tokio::spawn(listen_for_phones(phones.clone()));
    let backend = Routed {
        op: OpBackend::new(vec![exe.into_os_string(), DUMP_SECRETS.into()]),
        native,
    };
    eprintln!(
        "visipassd {} listening on {} (approvals: {})",
        env!("CARGO_PKG_VERSION"),
        socket.display(),
        vp_daemon::approval::Approver::method(&approver)
    );
    let approver = WithPhones {
        desktop: approver,
        phones: phones.clone(),
    };
    let daemon =
        Arc::new(Daemon::new(backend, approver, &state, socket.clone()).with_phones(phones));

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap_or_else(|_| fail("could not install signal handlers"));
    tokio::select! {
        _ = daemon.serve(listener) => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    let _ = std::fs::remove_file(&socket);
}
