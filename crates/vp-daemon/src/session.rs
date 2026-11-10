//! Locks VisiPass's own vault when the screen locks, the machine sleeps, or the
//! computer has been idle (no keyboard, mouse or touch) for the auto-lock time
//! (`vp auto-lock`; ten minutes unless the human chose otherwise).
//!
//! Four sources, any of which locks:
//! - The Wayland compositor's idle notification (ext-idle-notify; Hyprland, Sway,
//!   KDE, niri), as 1Password locks after the computer is idle. While it is held
//!   the vault's own last-use timer stands down; without one (no Wayland, or a
//!   compositor without the protocol) the vault locks after that long unused.
//! - Hyprland, asked every few seconds while the vault is unlocked. Omarchy's lock
//!   screen tells nobody else, but Hyprland always knows a session lock is up.
//! - logind's `Lock` signal and `LockedHint`, which other desktops send.
//! - logind's `PrepareForSleep`, held off by a delay inhibitor until the keys are gone.
//!
//! Every source only ever locks, so a false alarm costs a master password, never a key.
//! The human may turn off locking with the screen (`vp auto-lock --screen-lock off`),
//! for a computer driven from elsewhere; sleep always locks.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The vault, as far as the watcher cares.
pub trait Lockable: Send + Sync + 'static {
    fn is_unlocked(&self) -> bool;
    /// Keeps the Account Key within a quick-unlock window.
    fn lock(&self);
    /// Erases the Account Key too.
    fn lock_fully(&self);
    /// Whether the computer's idle time is being watched for it.
    fn computer_idle_watched(&self, _watched: bool) {}
    /// No input since `since`, or (`None`) input again; the vault decides
    /// whether that is long enough to lock.
    fn computer_idle(&self, since: Option<std::time::Instant>) {
        if since.is_some() {
            self.lock();
        }
    }
    /// Whether a screen lock locks the vault.
    fn locks_with_screen(&self) -> bool {
        true
    }
}

impl<U: vp_native::Unlock + Send + Sync + 'static> Lockable for vp_native::NativeBackend<U> {
    fn is_unlocked(&self) -> bool {
        vp_native::NativeBackend::is_unlocked(self)
    }
    fn lock(&self) {
        vp_native::NativeBackend::lock(self)
    }
    fn lock_fully(&self) {
        vp_native::NativeBackend::lock_fully(self)
    }
    fn computer_idle_watched(&self, watched: bool) {
        vp_native::NativeBackend::computer_idle_watched(self, watched)
    }
    fn computer_idle(&self, since: Option<std::time::Instant>) {
        vp_native::NativeBackend::computer_idle(self, since)
    }
    fn locks_with_screen(&self) -> bool {
        vp_native::NativeBackend::locks_with_screen(self)
    }
}

const POLL: Duration = Duration::from_secs(2);
const ASK_TIMEOUT: Duration = Duration::from_millis(500);

/// Runs until the daemon exits.
pub async fn watch<V: Lockable + Clone>(vault: V) {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let polling = {
        let vault = vault.clone();
        async move {
            if let Some(runtime) = runtime {
                watch_hyprland(vault, runtime.join("hypr"), POLL).await
            }
        }
    };
    #[cfg(target_os = "linux")]
    let idle = idle::watch(vault.clone(), idle::PROBE);
    #[cfg(not(target_os = "linux"))]
    let idle = std::future::ready(());
    tokio::join!(polling, logind::watch(vault), idle);
}

/// The computer's idle time, from the Wayland compositor.
#[cfg(target_os = "linux")]
pub mod idle {
    use super::Lockable;
    use std::time::Duration;
    use wayland_client::globals::{GlobalListContents, registry_queue_init};
    use wayland_client::protocol::{wl_registry, wl_seat};
    use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
    use wayland_protocols::ext::idle_notify::v1::client::{
        ext_idle_notification_v1, ext_idle_notifier_v1,
    };

    /// How long to wait before looking for a compositor again.
    const RETRY: Duration = Duration::from_secs(15);

    /// How long without input before the compositor tells us the computer is
    /// idle. The vault then counts from when input stopped, against whatever
    /// auto-lock time is set, so changing it needs no new notification.
    pub const PROBE: Duration = Duration::from_secs(60);

    /// Tells the vault each time the computer goes idle for `after` and each
    /// time input comes back, for the daemon's whole life, reconnecting when
    /// the compositor restarts.
    pub async fn watch<V: Lockable + Clone>(vault: V, after: Duration) {
        loop {
            let (done, ended) = tokio::sync::oneshot::channel();
            let watching = vault.clone();
            // Its own thread: the Wayland loop blocks for as long as the
            // compositor runs, and must not hold up the daemon's exit.
            std::thread::spawn(move || {
                let _ = run(watching, after);
                let _ = done.send(());
            });
            let _ = ended.await;
            vault.computer_idle_watched(false);
            tokio::time::sleep(RETRY).await;
        }
    }

    struct State<V> {
        vault: V,
        after: Duration,
    }

    /// Connects to the session's compositor and asks to be told when the
    /// computer has been idle for `after`. Returns when the connection ends.
    pub fn run<V: Lockable>(vault: V, after: Duration) -> Result<(), String> {
        let socket = crate::approval::find_display()
            .into_iter()
            .find(|(name, _)| *name == "WAYLAND_DISPLAY")
            .map(|(_, path)| path)
            .ok_or("no Wayland session")?;
        let stream = std::os::unix::net::UnixStream::connect(&socket).map_err(|e| e.to_string())?;
        let connection = Connection::from_socket(stream).map_err(|e| e.to_string())?;
        let (globals, mut queue) =
            registry_queue_init::<State<V>>(&connection).map_err(|e| e.to_string())?;
        let qh = queue.handle();
        let notifier: ext_idle_notifier_v1::ExtIdleNotifierV1 = globals
            .bind(&qh, 1..=2, ())
            .map_err(|_| "the compositor has no idle notifications")?;
        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ()).map_err(|e| e.to_string())?;
        let ms = u32::try_from(after.as_millis()).unwrap_or(u32::MAX);
        // Version 2 counts only input, so a video that keeps the screen awake
        // does not keep the vault open; version 1 honours such inhibitors.
        let _notification = if notifier.version() >= 2 {
            notifier.get_input_idle_notification(ms, &seat, &qh, ())
        } else {
            notifier.get_idle_notification(ms, &seat, &qh, ())
        };
        connection.flush().map_err(|e| e.to_string())?;
        vault.computer_idle_watched(true);
        let mut state = State { vault, after };
        loop {
            queue
                .blocking_dispatch(&mut state)
                .map_err(|e| e.to_string())?;
        }
    }

    impl<V: Lockable> Dispatch<ext_idle_notification_v1::ExtIdleNotificationV1, ()> for State<V> {
        fn event(
            state: &mut Self,
            _: &ext_idle_notification_v1::ExtIdleNotificationV1,
            event: ext_idle_notification_v1::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            match event {
                ext_idle_notification_v1::Event::Idled => {
                    let since = std::time::Instant::now()
                        .checked_sub(state.after)
                        .unwrap_or_else(std::time::Instant::now);
                    let was = state.vault.is_unlocked();
                    state.vault.computer_idle(Some(since));
                    if was && !state.vault.is_unlocked() {
                        eprintln!("visipassd: the computer was idle, so the vault locked");
                    }
                }
                ext_idle_notification_v1::Event::Resumed => state.vault.computer_idle(None),
                _ => {}
            }
        }
    }

    impl<V: Lockable> Dispatch<wl_registry::WlRegistry, GlobalListContents> for State<V> {
        fn event(
            _: &mut Self,
            _: &wl_registry::WlRegistry,
            _: wl_registry::Event,
            _: &GlobalListContents,
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }

    impl<V: Lockable> Dispatch<ext_idle_notifier_v1::ExtIdleNotifierV1, ()> for State<V> {
        fn event(
            _: &mut Self,
            _: &ext_idle_notifier_v1::ExtIdleNotifierV1,
            _: ext_idle_notifier_v1::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }

    impl<V: Lockable> Dispatch<wl_seat::WlSeat, ()> for State<V> {
        fn event(
            _: &mut Self,
            _: &wl_seat::WlSeat,
            _: wl_seat::Event,
            _: &(),
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }
}

/// Locks the vault whenever a Hyprland instance under `hypr_dir` reports a session lock.
pub async fn watch_hyprland<V: Lockable>(vault: V, hypr_dir: PathBuf, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        if vault.is_unlocked() && vault.locks_with_screen() && hyprland_locked(&hypr_dir).await {
            vault.lock();
            eprintln!("visipassd: the screen locked, so the vault locked");
        }
    }
}

/// Whether any running Hyprland has a session lock up. Every instance is asked,
/// because the daemon can outlive the Hyprland that was running when it started.
async fn hyprland_locked(hypr_dir: &Path) -> bool {
    let Ok(instances) = std::fs::read_dir(hypr_dir) else {
        return false;
    };
    for instance in instances.flatten() {
        let socket = instance.path().join(".socket.sock");
        if let Ok(Some(true)) = tokio::time::timeout(ASK_TIMEOUT, ask_locked(&socket)).await {
            return true;
        }
    }
    false
}

async fn ask_locked(socket: &Path) -> Option<bool> {
    let mut stream = UnixStream::connect(socket).await.ok()?;
    stream.write_all(b"j/locked").await.ok()?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.ok()?;
    let reply: serde_json::Value = serde_json::from_slice(&reply).ok()?;
    reply.get("locked")?.as_bool()
}

mod logind {
    use super::Lockable;
    use futures_util::StreamExt;
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedFd, OwnedValue};
    use zbus::{Connection, MatchRule, MessageStream, message};

    #[zbus::proxy(
        interface = "org.freedesktop.login1.Manager",
        default_service = "org.freedesktop.login1",
        default_path = "/org/freedesktop/login1"
    )]
    trait Manager {
        fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> zbus::Result<OwnedFd>;
        #[zbus(signal)]
        fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
    }

    const SESSION: &str = "org.freedesktop.login1.Session";

    /// Without a system bus (a container, a test) there is nothing to watch.
    pub async fn watch<V: Lockable>(vault: V) {
        let Ok(bus) = Connection::system().await else {
            return;
        };
        let Ok(manager) = ManagerProxy::new(&bus).await else {
            return;
        };
        let inhibit = || async {
            manager
                .inhibit(
                    "sleep",
                    "VisiPass",
                    "Lock the vault before sleeping",
                    "delay",
                )
                .await
                .ok()
        };
        let mut inhibitor = inhibit().await;
        let Ok(mut sleeps) = manager.receive_prepare_for_sleep().await else {
            return;
        };
        let session_signals = async {
            let rule = MatchRule::builder()
                .msg_type(message::Type::Signal)
                .sender("org.freedesktop.login1")
                .ok()?
                .build();
            MessageStream::for_match_rule(rule, &bus, None).await.ok()
        };
        let Some(mut session_signals) = session_signals.await else {
            return;
        };

        loop {
            tokio::select! {
                Some(signal) = sleeps.next() => {
                    let Ok(args) = signal.args() else { continue };
                    if *args.start() {
                        // Quick unlock does not survive sleep (§4.3, §6.2).
                        vault.lock_fully();
                        // Closing the inhibitor lets the sleep go ahead.
                        inhibitor = None;
                    } else if inhibitor.is_none() {
                        inhibitor = inhibit().await;
                    }
                }
                Some(Ok(message)) = session_signals.next() => {
                    if locks(&message) && vault.is_unlocked() && vault.locks_with_screen() {
                        vault.lock();
                        eprintln!("visipassd: the session locked, so the vault locked");
                    }
                }
                else => return,
            }
        }
    }

    /// A session's `Lock` signal, or its `LockedHint` turning true.
    fn locks(message: &zbus::Message) -> bool {
        let header = message.header();
        let interface = header.interface().map(|i| i.as_str());
        let member = header.member().map(|m| m.as_str());
        match (interface, member) {
            (Some(SESSION), Some("Lock")) => true,
            (Some("org.freedesktop.DBus.Properties"), Some("PropertiesChanged")) => {
                let Ok((changed_interface, changed, _)) =
                    message
                        .body()
                        .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                else {
                    return false;
                };
                changed_interface == SESSION
                    && changed
                        .get("LockedHint")
                        .and_then(|v| bool::try_from(v).ok())
                        .unwrap_or(false)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::UnixListener;

    #[derive(Clone, Default)]
    struct Vault(Arc<AtomicBool>);

    impl Lockable for Vault {
        fn is_unlocked(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
        fn lock(&self) {
            self.0.store(false, Ordering::SeqCst)
        }
        fn lock_fully(&self) {
            self.lock()
        }
    }

    /// Against this session's real compositor: hold still for a second.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a Wayland session with ext-idle-notify"]
    fn the_compositor_says_when_the_computer_is_idle() {
        let vault = Vault(Arc::new(AtomicBool::new(true)));
        let watching = vault.clone();
        std::thread::spawn(move || idle::run(watching, Duration::from_secs(1)));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while vault.is_unlocked() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!vault.is_unlocked());
    }

    /// A Hyprland that answers `j/locked` with `locked`.
    fn hyprland(dir: &Path, instance: &str, locked: Arc<AtomicBool>) {
        let path = dir.join(instance);
        std::fs::create_dir_all(&path).unwrap();
        let listener = UnixListener::bind(path.join(".socket.sock")).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 8];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"j/locked");
                let reply = format!("{{\"locked\": {}}}", locked.load(Ordering::SeqCst));
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });
    }

    #[tokio::test]
    async fn a_hyprland_session_lock_locks_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        // A dead instance from before a Hyprland restart, and the live one.
        std::fs::create_dir_all(dir.path().join("old")).unwrap();
        std::fs::write(dir.path().join("old/.socket.sock"), "").unwrap();
        let screen = Arc::new(AtomicBool::new(false));
        hyprland(dir.path(), "live", screen.clone());

        let vault = Vault::default();
        vault.0.store(true, Ordering::SeqCst);
        tokio::spawn(watch_hyprland(
            vault.clone(),
            dir.path().to_path_buf(),
            Duration::from_millis(20),
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(vault.is_unlocked(), "an unlocked screen leaves it alone");

        screen.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!vault.is_unlocked());
    }

    #[tokio::test]
    async fn no_hyprland_means_no_lock() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!hyprland_locked(&dir.path().join("missing")).await);
        assert!(!hyprland_locked(dir.path()).await);
    }
}
