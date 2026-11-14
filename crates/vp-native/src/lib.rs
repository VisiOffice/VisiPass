//! VisiPass's own vault as a [`Backend`]: items encrypted by `vp-store`, unlocked
//! with the master password (asked for through [`Unlock`]) and the Secret Key
//! kept on this device.
//!
//! Item and vault IDs follow 1Password's shape, and items imported from
//! 1Password keep their IDs, so an `op://vault/item/field` reference resolves
//! the same way against either backend.

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};
use vp_core::Failure;
use vp_core::backend::Backend;
use vp_core::bucket::{BucketConfig, BucketKeys};
use vp_core::model::{
    Destination, Field, FieldMeta, Item, ItemDetail, ItemSummary, Listed, PasskeyInfo,
    PasswordOutcome, PasswordRequest, Receipt, Scope, SectionMeta, SectionRef, Url, UrlEntry,
    VaultRef,
};
use vp_core::passkey;
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;
use vp_crypto::{KdfParams, Key, SecretKey};
use vp_store::{AccountKey, Rev, Store, Unlocked, Write};
use zeroize::Zeroizing;

/// Asks the human for the master password. `None` if they cancel.
pub trait Unlock: Send + Sync + 'static {
    /// Asks for the master password. `purpose` says what unlocking is for when
    /// it is more than unlocking ("turn on quick unlock for 8 hours").
    fn password(
        &self,
        retry: bool,
        purpose: Option<&str>,
    ) -> impl Future<Output = Result<Option<Secret>, Failure>> + Send;

    /// Quick unlock (§4.3): asks the system to confirm the human is present, by
    /// fingerprint or login password.
    fn confirm_presence(&self) -> impl Future<Output = Presence> + Send {
        async { Presence::Unavailable }
    }
}

/// The answer to [`Unlock::confirm_presence`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    /// The human dismissed the check: the unlock is cancelled.
    Dismissed,
    /// No check could be made, or it failed: ask for the master password instead.
    Unavailable,
}

const UNLOCK_ATTEMPTS: usize = 3;
/// How often sync looks for other devices' changes while unlocked.
pub const SYNC_EVERY: Duration = Duration::from_secs(60);
/// How often a bucket is checked when nothing here changed: each check is a
/// few requests, which providers count, and nobody is waiting on it.
pub const BUCKET_POLL: Duration = Duration::from_secs(300);
/// After the human cancels an unlock, requests that were waiting for it (and new
/// ones) fail at once for this long instead of each opening another prompt.
pub const QUIET_AFTER_CANCEL: Duration = Duration::from_secs(15);
const QUIET: &str = "VisiPass is locked: unlocking was just cancelled. Try again in a few seconds";
/// How long the computer may sit idle before the vault locks, as 1Password's
/// default. Without a way to see the computer's idle time (see
/// `NativeBackend::computer_idle_watched`), the vault counts from its own last use.
pub use vp_core::backend::AutoLock;
pub const QUICK_UNLOCK_DEFAULT: Duration = Duration::from_secs(8 * 60 * 60);
pub const QUICK_UNLOCK_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Where the vault, its Secret Key and its sequence number live.
#[derive(Clone, Debug)]
pub struct Paths {
    pub vault: PathBuf,
    pub secret_key: PathBuf,
    pub sequence: PathBuf,
    /// This device's settings for the vault, such as the quick-unlock window.
    pub settings: PathBuf,
}

impl Paths {
    pub fn standard() -> Self {
        Self {
            vault: vp_core::paths::vault_file(),
            secret_key: vp_core::paths::secret_key_file(),
            sequence: vp_core::paths::state_dir().join("sequence"),
            settings: vp_core::paths::state_dir().join("vault-settings.json"),
        }
    }

    pub fn exists(&self) -> bool {
        self.vault.is_file()
    }
}

/// Sync storage the embedding program supplies (one this crate has no settings
/// for): called once per round, from a blocking thread. Its rounds run like a
/// bucket's, so the vault is never locked while it waits on a network.
pub type SyncStorage = Arc<dyn Fn() -> Result<Box<dyn vp_sync::Storage>, Failure> + Send + Sync>;

/// Where this device keeps its Secret Key (§4.4). [`SecretKeyFile`], a 0600
/// file, unless the platform has a better place (its own keystore).
pub trait SecretKeyStore: Send + Sync + 'static {
    /// The Secret Key in its display form, or `None` if this device has none.
    fn read(&self) -> Result<Option<Zeroizing<String>>, Failure>;
    /// Saves a new one. Refused if one is already there: nothing replaces it.
    fn create(&self, shown: &str) -> Result<(), Failure>;
    fn remove(&self);
    /// Where it is, for messages: "at /home/me/.local/share/visipass/secret-key".
    fn location(&self) -> String;
}

/// The Secret Key in a 0600 file (§4.4).
pub struct SecretKeyFile(pub PathBuf);

impl SecretKeyStore for SecretKeyFile {
    fn read(&self) -> Result<Option<Zeroizing<String>>, Failure> {
        match std::fs::read_to_string(&self.0) {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Failure::new(format!("Could not read {}", self.0.display()))),
        }
    }

    fn create(&self, shown: &str) -> Result<(), Failure> {
        write_private(&self.0, format!("{shown}\n").as_bytes())
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(&self.0);
    }

    fn location(&self) -> String {
        format!("at {}", self.0.display())
    }
}

// ---- What an item looks like inside its two ciphertexts -------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Overview {
    title: String,
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    archived: bool,
    /// Public descriptions of the item's passkeys, so a page's request finds
    /// them without decrypting every item's details.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    passkeys: Vec<PasskeyInfo>,
}

#[derive(Default, Serialize, Deserialize)]
struct Details {
    #[serde(default)]
    sections: Vec<SectionRef>,
    #[serde(default)]
    fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    passkeys: Vec<StoredPasskey>,
}

/// A passkey with its private key, inside the item's details. Changed only by
/// the browser's requests: an item save carries the stored ones over.
#[derive(Clone, Serialize, Deserialize)]
struct StoredPasskey {
    credential_id: String,
    rp_id: String,
    /// base64url, the site's opaque ID for the account.
    user_handle: String,
    #[serde(default)]
    user_display_name: String,
    /// The P-256 scalar, base64url.
    key: Secret,
}

#[derive(Serialize, Deserialize)]
struct VaultAttrs {
    name: String,
}

fn overview_of(item: &Item) -> Overview {
    Overview {
        title: item.title.clone(),
        category: item.category.clone(),
        tags: item.tags.clone(),
        urls: item.urls.clone(),
        favorite: item.favorite,
        username: item
            .fields
            .iter()
            .find(|f| f.purpose.as_deref() == Some("USERNAME"))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_string())
            .filter(|v| !v.is_empty()),
        created_at: item.created_at.clone(),
        updated_at: item.updated_at.clone(),
        archived: false,
        passkeys: Vec::new(),
    }
}

/// An imported item's overview: as [`overview_of`], plus the public side of
/// the passkeys its export carried (a save ignores `Item::passkeys`; an import
/// is the one write that brings passkeys in).
fn imported_overview(item: &Item) -> Overview {
    Overview {
        passkeys: item
            .imported_passkeys
            .iter()
            .map(|p| p.info.clone())
            .collect(),
        ..overview_of(item)
    }
}

fn stored(p: &passkey::Imported) -> StoredPasskey {
    StoredPasskey {
        credential_id: p.info.credential_id.clone(),
        rp_id: p.info.rp_id.clone(),
        user_handle: p.user_handle.clone(),
        user_display_name: p.user_display_name.clone(),
        key: p.key.clone(),
    }
}

fn encode<T: Serialize>(value: &T) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(value).expect("item types always serialise"))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(bytes).map_err(|_| Failure::new("A vault item could not be read"))
}

/// 26 characters of lowercase base32, the shape of a 1Password ID.
pub fn new_id() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes: [u8; 26] = vp_crypto::random();
    bytes
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect()
}

fn failure(e: vp_store::Error) -> Failure {
    Failure::new(e.0)
}

fn reference(vault_id: &str, item_id: &str, field: &Field) -> String {
    match field.section.as_ref().and_then(|s| s.id.as_deref()) {
        Some(section) if !section.is_empty() => {
            format!("op://{vault_id}/{item_id}/{section}/{}", field.id)
        }
        _ => format!("op://{vault_id}/{item_id}/{}", field.id),
    }
}

// ---- State ------------------------------------------------------------------

/// An item ID with its encoded overview and details, ready to write.
type Encoded = (String, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

struct Entry {
    vault_id: String,
    item_id: String,
    /// The current revision shown: the newest when sync brought in a conflict.
    rev: Rev,
    overview: Overview,
    /// The item's other current revisions, while it is in conflict.
    others: Vec<Rev>,
}

/// Held only while unlocked; dropping it erases the keys (§6.1).
struct Opened {
    unlocked: Unlocked,
    vaults: Vec<VaultRef>,
    entries: Vec<Entry>,
}

impl Opened {
    fn vault(&self, name_or_id: &str) -> Result<&VaultRef, Failure> {
        self.vaults
            .iter()
            .find(|v| v.id == name_or_id)
            .or_else(|| {
                self.vaults
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case(name_or_id))
            })
            .ok_or_else(|| Failure::new(format!("No vault named {name_or_id}")))
    }

    fn entry(&self, vault_id: &str, title_or_id: &str) -> Result<&Entry, Failure> {
        let in_vault = || self.entries.iter().filter(|e| e.vault_id == vault_id);
        if let Some(entry) = in_vault().find(|e| e.item_id == title_or_id) {
            return Ok(entry);
        }
        let mut titled = in_vault().filter(|e| e.overview.title == title_or_id);
        match (titled.next(), titled.next()) {
            (Some(entry), None) => Ok(entry),
            (Some(_), Some(_)) => Err(Failure::new(format!(
                "More than one item is titled {title_or_id}; use its ID"
            ))),
            (None, _) => Err(Failure::new(format!("No item {title_or_id} in that vault"))),
        }
    }

    fn entry_mut(&mut self, vault_id: &str, item_id: &str) -> Option<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|e| e.vault_id == vault_id && e.item_id == item_id)
    }
}

struct State {
    store: Option<Store>,
    opened: Option<Opened>,
    last_use: Instant,
    /// How long the Account Key outlives a lock after a master-password unlock.
    quick_unlock: Option<Duration>,
    /// The Account Key, kept for quick unlock while the vault is otherwise locked.
    kept: Option<AccountKey>,
    /// When the current quick-unlock window ends; set by a master-password unlock.
    window_end: Option<Instant>,
    /// Bumped by every full lock, so a quick unlock that raced one is dropped.
    epoch: u64,
    /// No unlock prompts until then; set when the human cancels one.
    quiet_until: Option<Instant>,
    /// The last sync round: when, and what it did or why it failed.
    last_sync: Option<(SystemTime, Result<vp_sync::Report, String>)>,
    /// When the vault locks by itself. The default until an unlock has checked
    /// the stored setting's tag.
    auto_lock: AutoLock,
    /// The stored setting and its tag, not yet checked.
    stored_auto_lock: Option<(AutoLock, String)>,
    /// Since when the computer has had no keyboard or mouse input, while that
    /// is watched.
    idle_since: Option<Instant>,
}

impl State {
    fn window_open(&self) -> bool {
        self.window_end.is_some_and(|end| Instant::now() < end)
    }

    /// Erases every key and decrypted overview, except the Account Key when a
    /// quick-unlock window is open and `fully` is false.
    fn lock(&mut self, fully: bool) {
        let keep = !fully && self.window_open();
        if let Some(opened) = self.opened.take()
            && keep
        {
            self.kept = Some(opened.unlocked.into_account_key());
        }
        if !keep {
            self.kept = None;
            self.window_end = None;
            self.epoch += 1;
        }
    }

    /// Takes the stored auto-lock setting once an unlock can check its tag; a
    /// setting whose tag does not match (edited by hand, or by anything else
    /// running as the user) is ignored and the default stays.
    fn adopt_auto_lock(&mut self) {
        let (Some(opened), Some((stored, tag))) = (&self.opened, self.stored_auto_lock.take())
        else {
            return;
        };
        if vp_store::hex(&opened.unlocked.settings_tag(&auto_lock_bytes(&stored))) == tag
            && stored.check().is_ok()
        {
            self.auto_lock = stored;
        } else {
            eprintln!(
                "visipassd: the stored auto-lock setting failed its check; using the default"
            );
        }
    }

    /// After a master-password unlock.
    fn opened_with_password(&mut self, opened: Opened) {
        self.opened = Some(opened);
        self.adopt_auto_lock();
        self.kept = None;
        self.last_use = Instant::now();
        self.window_end = self.quick_unlock.map(|window| Instant::now() + window);
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quick_unlock_secs: Option<u64>,
    /// When the vault locks by itself, and its tag under the account's keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_lock: Option<AutoLock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_lock_tag: Option<String>,
    /// The folder sync writes to (§11.1), if it is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_folder: Option<PathBuf>,
    /// The bucket sync writes to, if it is on. Its keys are in the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_bucket: Option<BucketConfig>,
}

/// What the Emergency Kit prints (§5.1).
pub struct EmergencyKit {
    /// The account ID, grouped for reading aloud.
    pub account_id: String,
    pub secret_key: Zeroizing<String>,
    pub vault_file: PathBuf,
}

/// Quick unlock's state, for `vp status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickUnlock {
    pub window: Duration,
    /// Time left in the current window, if one is open.
    pub remaining: Option<Duration>,
}

struct Inner<U> {
    paths: Paths,
    secret_keys: Box<dyn SecretKeyStore>,
    params: KdfParams,
    unlock: U,
    state: Mutex<State>,
    /// One unlock at a time.
    gate: tokio::sync::Mutex<()>,
    /// One bucket round at a time: they let go of the vault while on the network.
    bucket_round: Mutex<()>,
    /// Set by [`NativeBackend::set_sync_storage`]; used before any setting.
    sync_storage: Mutex<Option<SyncStorage>>,
    quiet_after_cancel: Duration,
    /// Woken by every commit, so sync sends it at once.
    changed: Arc<tokio::sync::Notify>,
    /// Something watches the computer's own idle time; the vault then locks
    /// after the auto-lock time without input, and its own last-use timer stands down.
    idle_watched: std::sync::atomic::AtomicBool,
}

impl<U> Inner<U> {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expire_if_idle(&self) {
        let mut state = self.state();
        let watched = self.idle_watched.load(std::sync::atomic::Ordering::Relaxed);
        let after = Duration::from_secs(state.auto_lock.minutes * 60);
        let idle = if watched {
            state
                .idle_since
                .is_some_and(|since| since.elapsed() >= after)
        } else {
            state.last_use.elapsed() >= after
        };
        if state.opened.is_some() && idle {
            state.lock(false);
        }
        if state.opened.is_none() && state.kept.is_some() && !state.window_open() {
            state.lock(true);
        }
    }
}

pub struct NativeBackend<U> {
    inner: Arc<Inner<U>>,
}

/// Another handle on the same vault: locking one locks both.
impl<U> Clone for NativeBackend<U> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<U: Unlock> NativeBackend<U> {
    pub fn new(paths: Paths, unlock: U) -> Self {
        Self::with_params(paths, unlock, KdfParams::DEFAULT)
    }

    /// `params` applies to a vault created by [`NativeBackend::init`]; an existing
    /// vault keeps the parameters stored with it.
    pub fn with_params(paths: Paths, unlock: U, params: KdfParams) -> Self {
        Self::build(paths, unlock, params, QUIET_AFTER_CANCEL)
    }

    /// For tests: how long a cancelled unlock keeps further prompts away.
    pub fn with_quiet_after_cancel(
        paths: Paths,
        unlock: U,
        params: KdfParams,
        quiet: Duration,
    ) -> Self {
        Self::build(paths, unlock, params, quiet)
    }

    /// With the Secret Key kept somewhere other than `paths.secret_key`, and
    /// how long a cancelled unlock keeps further prompts away.
    pub fn with_secret_key_store(
        paths: Paths,
        unlock: U,
        params: KdfParams,
        quiet_after_cancel: Duration,
        secret_keys: impl SecretKeyStore,
    ) -> Self {
        Self::build_with(
            paths,
            unlock,
            params,
            quiet_after_cancel,
            Box::new(secret_keys),
        )
    }

    fn build(paths: Paths, unlock: U, params: KdfParams, quiet_after_cancel: Duration) -> Self {
        let secret_keys = Box::new(SecretKeyFile(paths.secret_key.clone()));
        Self::build_with(paths, unlock, params, quiet_after_cancel, secret_keys)
    }

    fn build_with(
        paths: Paths,
        unlock: U,
        params: KdfParams,
        quiet_after_cancel: Duration,
        secret_keys: Box<dyn SecretKeyStore>,
    ) -> Self {
        let settings = load_settings(&paths.settings);
        let quick_unlock = settings
            .quick_unlock_secs
            .map(|secs| Duration::from_secs(secs).min(QUICK_UNLOCK_MAX));
        let stored_auto_lock = settings.auto_lock.zip(settings.auto_lock_tag);
        let inner = Arc::new(Inner {
            paths,
            secret_keys,
            params,
            unlock,
            state: Mutex::new(State {
                store: None,
                opened: None,
                last_use: Instant::now(),
                quick_unlock,
                kept: None,
                window_end: None,
                epoch: 0,
                quiet_until: None,
                last_sync: None,
                auto_lock: AutoLock::DEFAULT,
                stored_auto_lock,
                idle_since: None,
            }),
            gate: tokio::sync::Mutex::new(()),
            quiet_after_cancel,
            changed: Arc::new(tokio::sync::Notify::new()),
            idle_watched: std::sync::atomic::AtomicBool::new(false),
            bucket_round: Mutex::new(()),
            sync_storage: Mutex::new(None),
        });
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak: Weak<Inner<U>> = Arc::downgrade(&inner);
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    match weak.upgrade() {
                        Some(inner) => inner.expire_if_idle(),
                        None => break,
                    }
                }
            });
            // Sync sends each commit at once and looks for other devices'
            // changes every minute, while the vault is unlocked.
            let weak: Weak<Inner<U>> = Arc::downgrade(&inner);
            let changed = inner.changed.clone();
            runtime.spawn(async move {
                loop {
                    let woken = tokio::time::timeout(SYNC_EVERY, changed.notified())
                        .await
                        .is_ok();
                    match weak.upgrade() {
                        Some(inner) => {
                            let backend = NativeBackend { inner };
                            if woken || !backend.bucket_checked_recently() {
                                let _ = backend.sync_round().await;
                            }
                        }
                        None => break,
                    }
                }
            });
        }
        Self { inner }
    }

    pub fn exists(&self) -> bool {
        self.inner.paths.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.state().opened.is_some()
    }

    /// Whether the computer's own idle time is watched (true while the daemon
    /// holds a compositor's idle notification). Then the vault locks after the
    /// auto-lock time without keyboard or mouse, however long since VisiPass was
    /// last used; otherwise after that long without a request.
    pub fn computer_idle_watched(&self, watched: bool) {
        // Either way the last-use timer starts again from now, so a watch that
        // ends does not lock at once for a request made long ago.
        {
            let mut state = self.inner.state();
            state.last_use = Instant::now();
            state.idle_since = None;
        }
        self.inner
            .idle_watched
            .store(watched, std::sync::atomic::Ordering::Relaxed);
    }

    /// The computer has had no input since `since`, or (`None`) has input again.
    pub fn computer_idle(&self, since: Option<Instant>) {
        self.inner.state().idle_since = since;
        self.inner.expire_if_idle();
    }

    /// When the vault locks by itself, as it applies now.
    pub fn auto_lock(&self) -> AutoLock {
        self.inner.state().auto_lock
    }

    /// Whether a screen lock locks the vault.
    pub fn locks_with_screen(&self) -> bool {
        self.inner.state().auto_lock.screen_lock
    }

    /// Changes when the vault locks by itself. The setting is stored with a tag
    /// under the account's keys, from the open vault or, given `password`, from
    /// unlocking with it (which also opens a locked vault). Keeping the vault
    /// open longer than now needs `password`: the caller asks the human for it.
    pub async fn set_auto_lock(
        &self,
        auto_lock: AutoLock,
        password: Option<Secret>,
    ) -> Result<(), Failure> {
        auto_lock.check()?;
        let bytes = auto_lock_bytes(&auto_lock);
        let tag = match password {
            Some(password) => {
                // A locked vault opens with the same password, so the human
                // types it once (after a restart, say), not again for the next request.
                let _gate = self.inner.gate.lock().await;
                let secret = self.secret_key()?;
                self.open_store()?;
                let inner = self.inner.clone();
                tokio::task::spawn_blocking(move || {
                    let mut state = inner.state();
                    let store = state
                        .store
                        .as_ref()
                        .ok_or_else(|| Failure::new("Could not open the vault"))?;
                    let unlocked = store.unlock(password.expose(), &secret).map_err(failure)?;
                    let tag = unlocked.settings_tag(&bytes);
                    if state.opened.is_none() {
                        let opened = load(store, unlocked)?;
                        state.opened_with_password(opened);
                    }
                    Ok::<_, Failure>(tag)
                })
                .await
                .map_err(|_| Failure::new("Checking the password failed"))??
            }
            None => {
                let state = self.inner.state();
                if auto_lock.looser_than(&state.auto_lock) {
                    return Err(Failure::new(
                        "Keeping the vault open longer needs the master password",
                    ));
                }
                let opened = state
                    .opened
                    .as_ref()
                    .ok_or_else(|| Failure::new("Unlock VisiPass first"))?;
                opened.unlocked.settings_tag(&bytes)
            }
        };
        self.update_settings(|s| {
            s.auto_lock = Some(auto_lock);
            s.auto_lock_tag = Some(vp_store::hex(&tag));
        })?;
        let mut state = self.inner.state();
        state.auto_lock = auto_lock;
        state.stored_auto_lock = None;
        state.last_use = Instant::now();
        Ok(())
    }

    /// Checks the master password before something only the human may do
    /// (pairing a phone). A locked vault opens with it, so the human types it once.
    pub async fn confirm_password(&self, password: Secret) -> Result<(), Failure> {
        let _gate = self.inner.gate.lock().await;
        let secret = self.secret_key()?;
        self.open_store()?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = inner.state();
            let store = state
                .store
                .as_ref()
                .ok_or_else(|| Failure::new("Could not open the vault"))?;
            let unlocked = store.unlock(password.expose(), &secret).map_err(failure)?;
            if state.opened.is_none() {
                let opened = load(store, unlocked)?;
                state.opened_with_password(opened);
            }
            state.last_use = Instant::now();
            Ok(())
        })
        .await
        .map_err(|_| Failure::new("Checking the password failed"))?
    }

    /// The phones paired with this device, as `(pairing_id, record)`; `None`
    /// while the vault is locked. Never asks to unlock: phones are asked only
    /// while the vault is open.
    pub fn phones(&self) -> Result<Option<vp_store::PhoneRecords>, Failure> {
        let state = self.inner.state();
        match &state.opened {
            Some(opened) => opened.unlocked.phones().map(Some).map_err(failure),
            None => Ok(None),
        }
    }

    /// Pairs a phone (sealing its record in the vault), or with `None` removes
    /// it. Returns whether it was paired before. Needs the vault open.
    pub fn set_phone(&self, pairing_id: &[u8; 16], record: Option<&[u8]>) -> Result<bool, Failure> {
        let mut state = self.inner.state();
        let state = &mut *state;
        let (Some(store), Some(opened)) = (state.store.as_mut(), state.opened.as_mut()) else {
            return Err(Failure::new("VisiPass is locked"));
        };
        store
            .set_phone(&mut opened.unlocked, pairing_id, record)
            .map_err(failure)
    }

    /// Locks. Within a quick-unlock window the Account Key stays, so the next
    /// unlock needs only the system's presence check.
    pub fn lock(&self) {
        self.inner.state().lock(false);
    }

    /// Erases every key, the Account Key included, and closes any quick-unlock
    /// window: for sleep and `vp lock --full`.
    pub fn lock_fully(&self) {
        self.inner.state().lock(true);
    }

    pub fn quick_unlock(&self) -> Option<QuickUnlock> {
        let state = self.inner.state();
        let window = state.quick_unlock?;
        let remaining = state
            .window_end
            .and_then(|end| end.checked_duration_since(Instant::now()));
        Some(QuickUnlock { window, remaining })
    }

    /// Turns quick unlock on (asking for the master password, which also starts
    /// the first window) or off.
    pub async fn set_quick_unlock(&self, window: Option<Duration>) -> Result<(), Failure> {
        if let Some(window) = window
            && !(Duration::from_secs(60)..=QUICK_UNLOCK_MAX).contains(&window)
        {
            return Err(Failure::new(
                "Choose a quick-unlock window of 1 to 24 hours",
            ));
        }
        let previous = {
            let mut state = self.inner.state();
            let previous = state.quick_unlock;
            state.lock(true);
            state.quick_unlock = window;
            previous
        };
        let purpose = window.map(|w| {
            let hours = w.as_secs().div_ceil(3600);
            format!(
                "turn on quick unlock for {hours} hour{}: after a lock, your fingerprint or Linux login password unlocks VisiPass",
                if hours == 1 { "" } else { "s" }
            )
        });
        if let Some(purpose) = &purpose
            && let Err(e) = self.open_for(Some(purpose)).await
        {
            self.inner.state().quick_unlock = previous;
            return Err(e);
        }
        self.update_settings(|s| s.quick_unlock_secs = window.map(|w| w.as_secs()))
    }

    fn update_settings(&self, change: impl FnOnce(&mut Settings)) -> Result<(), Failure> {
        let mut settings = load_settings(&self.inner.paths.settings);
        change(&mut settings);
        let json = serde_json::to_vec_pretty(&settings).map_err(|e| Failure::new(e.to_string()))?;
        if let Some(dir) = self.inner.paths.settings.parent() {
            private_dir(dir)?;
        }
        replace_private(&self.inner.paths.settings, &json)
    }

    /// Creates the vault and its Secret Key. Returns the Secret Key in its
    /// display form, for the Emergency Kit.
    pub async fn init(&self, password: Secret) -> Result<Zeroizing<String>, Failure> {
        let _gate = self.inner.gate.lock().await;
        let paths = &self.inner.paths;
        if paths.exists() || self.inner.secret_keys.read()?.is_some() {
            return Err(Failure::new(format!(
                "A VisiPass vault already exists at {}",
                paths.vault.display()
            )));
        }
        if password.expose().chars().count() < 10 {
            return Err(Failure::new(
                "Choose a master password of at least 10 characters",
            ));
        }
        for dir in [paths.vault.parent(), paths.sequence.parent()]
            .into_iter()
            .flatten()
        {
            private_dir(dir)?;
        }
        let secret = SecretKey::generate();
        let shown = secret.display();
        self.inner.secret_keys.create(&shown)?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let paths = &inner.paths;
            let (store, unlocked) = Store::create(
                &paths.vault,
                &paths.sequence,
                password.expose(),
                &secret,
                inner.params,
            )
            .map_err(failure)?;
            let mut state = inner.state();
            state.store = Some(store);
            state.opened_with_password(Opened {
                unlocked,
                vaults: Vec::new(),
                entries: Vec::new(),
            });
            Ok::<_, Failure>(())
        })
        .await
        .map_err(|_| Failure::new("Creating the vault failed"))??;
        Ok(shown)
    }

    /// Unlocks if needed, asking the human for the master password.
    async fn open(&self) -> Result<(), Failure> {
        self.open_for(None).await
    }

    async fn open_for(&self, purpose: Option<&str>) -> Result<(), Failure> {
        let _gate = self.inner.gate.lock().await;
        self.inner.expire_if_idle();
        if self.open_store()? {
            return Ok(());
        }
        if self
            .inner
            .state()
            .quiet_until
            .is_some_and(|until| Instant::now() < until)
        {
            return Err(Failure::new(QUIET));
        }
        if self.quick_unlock_with_kept_key().await? {
            return Ok(());
        }
        let secret = Arc::new(self.secret_key()?);
        for attempt in 0..UNLOCK_ATTEMPTS {
            let Some(password) = self.inner.unlock.password(attempt > 0, purpose).await? else {
                self.quiet();
                return Err(Failure::new("Unlocking VisiPass was cancelled"));
            };
            let inner = self.inner.clone();
            let secret = secret.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut state = inner.state();
                let store = state.store.as_ref().expect("opened above");
                let unlocked = store.unlock(password.expose(), &secret).map_err(failure)?;
                let opened = load(store, unlocked)?;
                state.opened_with_password(opened);
                Ok::<_, Failure>(())
            })
            .await
            .map_err(|_| Failure::new("Unlocking failed"))?;
            match result {
                Ok(()) => return Ok(()),
                Err(e) if e.0.starts_with("Wrong master password") => continue,
                Err(e) => return Err(e),
            }
        }
        self.quiet();
        Err(Failure::new("Wrong master password; VisiPass stays locked"))
    }

    /// Opens the database if it is not open yet. `true` if the vault is already
    /// unlocked (and counts as used).
    fn open_store(&self) -> Result<bool, Failure> {
        let mut state = self.inner.state();
        if state.opened.is_some() {
            state.last_use = Instant::now();
            return Ok(true);
        }
        if state.store.is_none() {
            if !self.inner.paths.exists() {
                return Err(Failure::new(
                    "There is no VisiPass vault yet. Run `vp init` to create one",
                ));
            }
            let paths = &self.inner.paths;
            state.store = Some(Store::open(&paths.vault, &paths.sequence).map_err(failure)?);
        }
        Ok(false)
    }

    /// The open vault's Account Key wrapped under a key this device keeps in
    /// hardware (see `vp_store::Unlocked::wrap_for_device`), for
    /// [`NativeBackend::unlock_with_device_key`]. Never asks to unlock.
    pub fn wrap_for_device(&self, wrap_key: &Key, context: &[u8]) -> Result<Vec<u8>, Failure> {
        let state = self.inner.state();
        let opened = state
            .opened
            .as_ref()
            .ok_or_else(|| Failure::new("VisiPass is locked"))?;
        Ok(opened.unlocked.wrap_for_device(wrap_key, context))
    }

    /// Unlocks with an Account Key from [`NativeBackend::wrap_for_device`], with
    /// every check a password unlock makes. Fails, leaving the vault locked, if
    /// `wrap_key` or `context` differ or the Account Key has been rotated since.
    pub async fn unlock_with_device_key(
        &self,
        wrap_key: Key,
        context: Vec<u8>,
        wrapped: Vec<u8>,
    ) -> Result<(), Failure> {
        let _gate = self.inner.gate.lock().await;
        if self.open_store()? {
            return Ok(());
        }
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = inner.state();
            let store = state.store.as_ref().expect("opened above");
            let unlocked = store
                .unlock_with_device_key(&wrap_key, &context, &wrapped)
                .map_err(failure)?;
            let opened = load(store, unlocked)?;
            state.opened = Some(opened);
            state.adopt_auto_lock();
            state.last_use = Instant::now();
            Ok(())
        })
        .await
        .map_err(|_| Failure::new("Unlocking failed"))?
    }

    fn quiet(&self) {
        self.inner.state().quiet_until = Some(Instant::now() + self.inner.quiet_after_cancel);
    }

    /// Checks the master password afresh, without changing whether the vault is
    /// unlocked, and returns what the Emergency Kit shows.
    pub async fn emergency_kit(&self, password: Secret) -> Result<EmergencyKit, Failure> {
        if !self.inner.paths.exists() {
            return Err(Failure::new(
                "There is no VisiPass vault yet. Run `vp init` to create one",
            ));
        }
        let secret = self.secret_key()?;
        let paths = self.inner.paths.clone();
        let account_id = tokio::task::spawn_blocking(move || {
            let store = Store::open(&paths.vault, &paths.sequence).map_err(failure)?;
            let unlocked = store.unlock(password.expose(), &secret).map_err(failure)?;
            Ok::<_, Failure>(unlocked.account_id())
        })
        .await
        .map_err(|_| Failure::new("Checking the password failed"))??;
        let hex: String = account_id.iter().map(|b| format!("{b:02X}")).collect();
        let grouped = hex
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-");
        Ok(EmergencyKit {
            account_id: grouped,
            secret_key: self.secret_key()?.display(),
            vault_file: self.inner.paths.vault.clone(),
        })
    }

    fn secret_key(&self) -> Result<SecretKey, Failure> {
        let keys = &self.inner.secret_keys;
        let text = keys.read()?.ok_or_else(|| {
            Failure::new(format!(
                "This device has no Secret Key {}. Restore it from your Emergency Kit",
                keys.location()
            ))
        })?;
        SecretKey::parse(&text).map_err(|e| Failure::new(e.0))
    }

    /// Reopens the vault with the kept Account Key once the system confirms the
    /// human is present. `false` when the master password is needed instead.
    async fn quick_unlock_with_kept_key(&self) -> Result<bool, Failure> {
        let (key, epoch) = {
            let mut state = self.inner.state();
            if !state.window_open() {
                state.kept = None;
                return Ok(false);
            }
            match state.kept.take() {
                Some(key) => (key, state.epoch),
                None => return Ok(false),
            }
        };
        match self.inner.unlock.confirm_presence().await {
            Presence::Confirmed => {}
            Presence::Dismissed => {
                let mut state = self.inner.state();
                if state.epoch == epoch && state.window_open() {
                    state.kept = Some(key);
                }
                state.quiet_until = Some(Instant::now() + self.inner.quiet_after_cancel);
                return Err(Failure::new("Unlocking VisiPass was cancelled"));
            }
            // The key is gone, so the window is over; the master password starts a new one.
            Presence::Unavailable => {
                self.inner.state().window_end = None;
                return Ok(false);
            }
        }
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = inner.state();
            if state.epoch != epoch {
                return false;
            }
            let store = state.store.as_ref().expect("opened before");
            let Ok(unlocked) = store.unlock_with_key(key) else {
                return false;
            };
            let Ok(opened) = load(store, unlocked) else {
                return false;
            };
            state.opened = Some(opened);
            state.adopt_auto_lock();
            state.last_use = Instant::now();
            true
        })
        .await
        .map_err(|_| Failure::new("Unlocking failed"))
    }

    /// Runs `f` against the unlocked vault.
    async fn with<T>(
        &self,
        f: impl FnOnce(&mut Store, &mut Opened) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let was_unlocked = self.is_unlocked();
        self.open().await?;
        if !was_unlocked {
            // Sync waits for the keys; now it has them.
            self.inner.changed.notify_one();
        }
        let mut state = self.inner.state();
        let state = &mut *state;
        match (state.store.as_mut(), state.opened.as_mut()) {
            (Some(store), Some(opened)) => {
                let before = opened.unlocked.sequence();
                let result = f(store, opened);
                if opened.unlocked.sequence() != before {
                    self.inner.changed.notify_one();
                }
                result
            }
            _ => Err(Failure::new("VisiPass locked while answering; try again")),
        }
    }

    /// Copies items into the vault, creating the vault if needed and keeping
    /// every item's ID. An item whose ID is already present is skipped, never
    /// overwritten. Returns (created, skipped).
    pub async fn import(
        &self,
        vault: &VaultRef,
        items: Vec<Item>,
    ) -> Result<(usize, usize), Failure> {
        let vault = vault.clone();
        self.with(move |store, opened| {
            if !opened.unlocked.has_vault(&vault.id) {
                store
                    .create_vault(
                        &mut opened.unlocked,
                        &vault.id,
                        &encode(&VaultAttrs {
                            name: vault.name.clone(),
                        }),
                    )
                    .map_err(failure)?;
                opened.vaults.push(vault.clone());
            }
            let fresh: Vec<&Item> = items
                .iter()
                .filter(|i| !opened.unlocked.has_item(&vault.id, &i.id))
                .collect();
            let skipped = items.len() - fresh.len();
            let encoded: Vec<Encoded> = fresh
                .iter()
                .map(|item| {
                    (
                        item.id.clone(),
                        encode(&imported_overview(item)),
                        encode(&Details {
                            sections: item.sections.clone(),
                            fields: item.fields.clone(),
                            passkeys: item.imported_passkeys.iter().map(stored).collect(),
                        }),
                    )
                })
                .collect();
            let writes: Vec<Write> = encoded
                .iter()
                .map(|(id, overview, details)| Write {
                    item_id: id,
                    overview,
                    details,
                    replaces: &[],
                })
                .collect();
            let revs = store
                .put_items(&mut opened.unlocked, &vault.id, &writes)
                .map_err(failure)?;
            for (item, rev) in fresh.into_iter().zip(revs) {
                opened.entries.push(Entry {
                    vault_id: vault.id.clone(),
                    item_id: item.id.clone(),
                    rev,
                    overview: imported_overview(item),
                    others: Vec::new(),
                });
            }
            Ok((encoded.len(), skipped))
        })
        .await
    }
}

/// Decrypts every overview after unlock, to build the search index (§7.2).
fn load(store: &Store, unlocked: Unlocked) -> Result<Opened, Failure> {
    let (vaults, entries) = index(store, &unlocked)?;
    Ok(Opened {
        unlocked,
        vaults,
        entries,
    })
}

/// Every vault and one entry per item. An item in conflict shows its most
/// recently updated revision and keeps the others beside it.
fn index(store: &Store, unlocked: &Unlocked) -> Result<(Vec<VaultRef>, Vec<Entry>), Failure> {
    let mut vaults = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    for (vault_id, attrs) in store.vaults(unlocked).map_err(failure)? {
        let attrs: VaultAttrs = decode(&attrs)?;
        for overview in store.overviews(unlocked, &vault_id).map_err(failure)? {
            let decoded: Overview = decode(&overview.plaintext)?;
            match entries.last_mut() {
                Some(entry) if entry.vault_id == vault_id && entry.item_id == overview.item_id => {
                    if (&decoded.updated_at, overview.rev) > (&entry.overview.updated_at, entry.rev)
                    {
                        entry.others.push(entry.rev);
                        entry.rev = overview.rev;
                        entry.overview = decoded;
                    } else {
                        entry.others.push(overview.rev);
                    }
                }
                _ => entries.push(Entry {
                    vault_id: vault_id.clone(),
                    item_id: overview.item_id,
                    rev: overview.rev,
                    overview: decoded,
                    others: Vec::new(),
                }),
            }
        }
        vaults.push(VaultRef {
            id: vault_id,
            name: attrs.name,
        });
    }
    Ok((vaults, entries))
}

/// After sync changed the vault underneath.
fn reindex(store: &Store, opened: &mut Opened) -> Result<(), Failure> {
    let (vaults, entries) = index(store, &opened.unlocked)?;
    opened.vaults = vaults;
    opened.entries = entries;
    Ok(())
}

/// The details of the revision an item's entry shows.
fn details(
    store: &Store,
    opened: &Opened,
    vault_id: &str,
    item_id: &str,
) -> Result<Details, Failure> {
    let rev = opened
        .entries
        .iter()
        .find(|e| e.vault_id == vault_id && e.item_id == item_id)
        .map(|e| e.rev)
        .ok_or_else(|| Failure::new(format!("No item {item_id} in that vault")))?;
    details_at(store, opened, vault_id, item_id, &rev)
}

fn details_at(
    store: &Store,
    opened: &Opened,
    vault_id: &str,
    item_id: &str,
    rev: &Rev,
) -> Result<Details, Failure> {
    decode(
        &store
            .details(&opened.unlocked, vault_id, item_id, rev)
            .map_err(failure)?,
    )
}

fn assemble(vault: &VaultRef, item_id: &str, overview: &Overview, details: Details) -> Item {
    Item {
        imported_passkeys: Vec::new(),
        passkeys: overview.passkeys.clone(),
        id: item_id.to_string(),
        title: overview.title.clone(),
        category: overview.category.clone(),
        vault: vault.clone(),
        tags: overview.tags.clone(),
        urls: overview.urls.clone(),
        favorite: overview.favorite,
        created_at: overview.created_at.clone(),
        updated_at: overview.updated_at.clone(),
        sections: details.sections,
        fields: details.fields,
    }
}

/// Writes one item and reads it back: values, title and category must match.
/// An existing item's new revision replaces the one its entry shows, so a
/// conflict's other side stays until the human settles it.
fn save(
    store: &mut Store,
    opened: &mut Opened,
    vault: &VaultRef,
    item_id: &str,
    overview: Overview,
    fields: Details,
) -> Result<Item, Failure> {
    let replaces: Vec<Rev> = opened
        .entries
        .iter()
        .find(|e| e.vault_id == vault.id && e.item_id == item_id)
        .map(|e| vec![e.rev])
        .unwrap_or_default();
    save_replacing(store, opened, vault, item_id, overview, fields, &replaces)
}

fn save_replacing(
    store: &mut Store,
    opened: &mut Opened,
    vault: &VaultRef,
    item_id: &str,
    overview: Overview,
    fields: Details,
    replaces: &[Rev],
) -> Result<Item, Failure> {
    let expected: Vec<(String, Option<String>)> = fields
        .fields
        .iter()
        .map(|f| {
            (
                f.id.clone(),
                f.value.as_ref().map(|v| v.expose().to_string()),
            )
        })
        .collect();
    let expected = Zeroizing::new(
        expected
            .into_iter()
            .map(|(i, v)| format!("{i}\u{0}{}", v.unwrap_or_default()))
            .chain(
                fields
                    .passkeys
                    .iter()
                    .map(|p| format!("{}\u{0}{}", p.credential_id, p.key.expose())),
            )
            .collect::<Vec<_>>()
            .join("\u{1}"),
    );
    let rev = store
        .put_item(
            &mut opened.unlocked,
            &vault.id,
            item_id,
            &encode(&overview),
            &encode(&fields),
            replaces,
        )
        .map_err(failure)?;
    let unverified = || {
        Failure::new(
            "The save is unverified: the item read back differently. Check it before retrying",
        )
    };
    let back = details_at(store, opened, &vault.id, item_id, &rev).map_err(|_| unverified())?;
    let got = Zeroizing::new(
        back.fields
            .iter()
            .map(|f| {
                format!(
                    "{}\u{0}{}",
                    f.id,
                    f.value.as_ref().map(|v| v.expose()).unwrap_or_default()
                )
            })
            .chain(
                back.passkeys
                    .iter()
                    .map(|p| format!("{}\u{0}{}", p.credential_id, p.key.expose())),
            )
            .collect::<Vec<_>>()
            .join("\u{1}"),
    );
    if got != expected {
        return Err(unverified());
    }
    let item = assemble(vault, item_id, &overview, back);
    match opened.entry_mut(&vault.id, item_id) {
        Some(entry) => {
            entry.rev = rev;
            entry.overview = overview;
            entry.others.retain(|r| !replaces.contains(r));
        }
        None => opened.entries.push(Entry {
            vault_id: vault.id.clone(),
            item_id: item_id.to_string(),
            rev,
            overview,
            others: Vec::new(),
        }),
    }
    Ok(item)
}

fn private_dir(dir: &std::path::Path) -> Result<(), Failure> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| Failure::new(format!("Could not create {}", dir.display())))
}

fn write_private(path: &std::path::Path, contents: &[u8]) -> Result<(), Failure> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Failure::new(format!("Could not create {}", path.display())))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|_| Failure::new(format!("Could not write {}", path.display())))
}

/// Writes beside `path` and renames over it, so a crash leaves the old file or the new one.
fn replace_private(path: &std::path::Path, contents: &[u8]) -> Result<(), Failure> {
    let temporary = path.with_extension("new");
    let _ = std::fs::remove_file(&temporary);
    write_private(&temporary, contents)?;
    std::fs::rename(&temporary, path)
        .map_err(|_| Failure::new(format!("Could not write {}", path.display())))
}

/// Missing or unreadable settings mean the defaults: quick unlock off.
/// What the auto-lock tag covers.
fn auto_lock_bytes(auto_lock: &AutoLock) -> Vec<u8> {
    vp_crypto::ad(
        "VisiPass auto-lock",
        &[
            vp_crypto::Part::Uint(auto_lock.minutes),
            vp_crypto::Part::Uint(u64::from(auto_lock.screen_lock)),
        ],
    )
}

fn load_settings(path: &std::path::Path) -> Settings {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn in_scope(scope: &Scope, vault: &VaultRef) -> bool {
    scope
        .vault
        .as_deref()
        .is_none_or(|v| v == vault.id || v.eq_ignore_ascii_case(&vault.name))
}

impl<U: Unlock> Backend for NativeBackend<U> {
    fn name(&self) -> &'static str {
        "visipass"
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<Listed>, Failure> {
        let scope = scope.clone();
        self.with(move |_, opened| {
            if let Some(v) = scope.vault.as_deref() {
                opened.vault(v)?;
            }
            Ok(opened
                .entries
                .iter()
                .filter(|e| !e.overview.archived)
                .filter_map(|e| {
                    let vault = opened.vaults.iter().find(|v| v.id == e.vault_id)?;
                    in_scope(&scope, vault).then(|| Listed {
                        summary: ItemSummary {
                            id: e.item_id.clone(),
                            title: e.overview.title.clone(),
                            category: e.overview.category.clone(),
                            vault: vault.clone(),
                            tags: e.overview.tags.clone(),
                            urls: e
                                .overview
                                .urls
                                .iter()
                                .map(|u| Url {
                                    href: u.href.clone(),
                                })
                                .collect(),
                            favorite: e.overview.favorite,
                            updated_at: e.overview.updated_at.clone(),
                            additional_information: e.overview.username.clone(),
                        },
                        raw: serde_json::json!({ "id": e.item_id, "vault": { "id": vault.id } }),
                    })
                })
                .collect())
        })
        .await
    }

    async fn details(
        &self,
        entries: &[Listed],
        _scope: &Scope,
    ) -> Result<Vec<ItemDetail>, Failure> {
        let wanted: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.summary.vault.id.clone(), e.summary.id.clone()))
            .collect();
        self.with(move |store, opened| {
            wanted
                .iter()
                .map(|(vault_id, item_id)| {
                    let vault = opened.vault(vault_id)?.clone();
                    let entry = opened.entry(vault_id, item_id)?;
                    let d = details(store, opened, vault_id, item_id)?;
                    let sections = d.sections.clone();
                    Ok(ItemDetail {
                        id: item_id.clone(),
                        title: entry.overview.title.clone(),
                        category: entry.overview.category.clone(),
                        vault,
                        tags: entry.overview.tags.clone(),
                        urls: entry
                            .overview
                            .urls
                            .iter()
                            .map(|u| Url {
                                href: u.href.clone(),
                            })
                            .collect(),
                        created_at: entry.overview.created_at.clone(),
                        updated_at: entry.overview.updated_at.clone(),
                        fields: d
                            .fields
                            .iter()
                            .map(|f| FieldMeta {
                                id: f.id.clone(),
                                label: f.label.clone(),
                                kind: f.kind.clone(),
                                purpose: f.purpose.clone(),
                                reference: Some(reference(vault_id, item_id, f)),
                                section: f.section.as_ref().map(|s| SectionMeta {
                                    label: s.label.clone().or_else(|| {
                                        sections
                                            .iter()
                                            .find(|x| x.id.is_some() && x.id == s.id)
                                            .and_then(|x| x.label.clone())
                                    }),
                                }),
                            })
                            .collect(),
                    })
                })
                .collect()
        })
        .await
    }

    async fn resolve(&self, refs: &[SecretRef]) -> Result<Vec<Secret>, Failure> {
        let refs = refs.to_vec();
        self.with(move |store, opened| refs.iter().map(|r| resolve_one(store, opened, r)).collect())
            .await
    }

    async fn create_api_credential(
        &self,
        destination: &Destination,
        value: Secret,
    ) -> Result<Receipt, Failure> {
        let destination = destination.clone();
        self.with(move |store, opened| {
            let title = destination.title.trim().to_string();
            if title.is_empty() || value.is_blank() {
                return Err(Failure::new("A title and a non-empty value are required"));
            }
            let vault = opened.vault(&destination.vault)?.clone();
            if opened.entries.iter().any(|e| {
                e.vault_id == vault.id && e.overview.title == title && !e.overview.archived
            }) {
                return Err(Failure::new(format!(
                    "An item titled {title} already exists in {}; choose another title",
                    vault.name
                )));
            }
            let mut fields = vp_core::model::template("API_CREDENTIAL");
            for field in &mut fields {
                match field.id.as_str() {
                    "credential" => field.value = Some(value.clone()),
                    "notesPlain" => {
                        field.value =
                            Some(Secret::new(destination.notes.clone().unwrap_or_default()))
                    }
                    _ => {}
                }
            }
            let now = vp_core::time::now_rfc3339();
            let overview = Overview {
                title: title.clone(),
                category: "API_CREDENTIAL".into(),
                tags: Vec::new(),
                urls: destination
                    .url
                    .iter()
                    .map(|u| UrlEntry {
                        href: u.clone(),
                        label: None,
                        primary: true,
                    })
                    .collect(),
                favorite: false,
                username: None,
                created_at: Some(now.clone()),
                updated_at: Some(now),
                archived: false,
                passkeys: Vec::new(),
            };
            let id = new_id();
            save(
                store,
                opened,
                &vault,
                &id,
                overview,
                Details {
                    sections: Vec::new(),
                    fields,
                    passkeys: Vec::new(),
                },
            )?;
            Ok(Receipt {
                reference: format!("op://{}/{id}/credential", vault.id),
                id,
                title,
                vault: vault.name,
                kind: "api-credential".into(),
                field: "credential".into(),
                verified: true,
            })
        })
        .await
    }

    async fn vaults(&self, _account: Option<&str>) -> Result<Vec<VaultRef>, Failure> {
        self.with(|_, opened| Ok(opened.vaults.clone())).await
    }

    async fn create_vault(&self, name: &str) -> Result<VaultRef, Failure> {
        let name = name.trim().to_string();
        self.with(move |store, opened| {
            if opened
                .vaults
                .iter()
                .any(|v| v.name.eq_ignore_ascii_case(&name))
            {
                return Err(Failure::new(format!(
                    "A vault named \"{name}\" already exists"
                )));
            }
            let vault = VaultRef { id: new_id(), name };
            store
                .create_vault(
                    &mut opened.unlocked,
                    &vault.id,
                    &encode(&VaultAttrs {
                        name: vault.name.clone(),
                    }),
                )
                .map_err(failure)?;
            opened.vaults.push(vault.clone());
            Ok(vault)
        })
        .await
    }

    async fn item(&self, id: &str, vault: &str) -> Result<Item, Failure> {
        let (id, vault) = (id.to_string(), vault.to_string());
        self.with(move |store, opened| {
            let vault = opened.vault(&vault)?.clone();
            let entry = opened.entry(&vault.id, &id)?;
            let (item_id, overview) = (entry.item_id.clone(), entry.overview.clone());
            let d = details(store, opened, &vault.id, &item_id)?;
            Ok(assemble(&vault, &item_id, &overview, d))
        })
        .await
    }

    async fn save_item(&self, item: &Item) -> Result<Item, Failure> {
        let item = item.clone();
        self.with(move |store, opened| {
            if item.title.trim().is_empty() {
                return Err(Failure::new("An item needs a title"));
            }
            let vault = opened
                .vault(if item.vault.id.is_empty() {
                    &item.vault.name
                } else {
                    &item.vault.id
                })?
                .clone();
            let now = vp_core::time::now_rfc3339();
            let (id, created_at, passkeys) = if item.id.is_empty() {
                (new_id(), Some(now.clone()), Vec::new())
            } else {
                let entry = opened.entry(&vault.id, &item.id)?;
                (
                    entry.item_id.clone(),
                    entry.overview.created_at.clone(),
                    entry.overview.passkeys.clone(),
                )
            };
            // Passkeys change only through the browser; keep the stored ones.
            let stored = if passkeys.is_empty() {
                Vec::new()
            } else {
                details(store, opened, &vault.id, &id)?.passkeys
            };
            let mut overview = overview_of(&item);
            overview.created_at = created_at;
            overview.updated_at = Some(now);
            overview.passkeys = passkeys;
            save(
                store,
                opened,
                &vault,
                &id,
                overview,
                Details {
                    sections: item.sections.clone(),
                    fields: item.fields.clone(),
                    passkeys: stored,
                },
            )
        })
        .await
    }

    async fn set_favorite(&self, id: &str, vault: &str, favorite: bool) -> Result<(), Failure> {
        self.update_overview(id, vault, move |o| o.favorite = favorite)
            .await
    }

    async fn archive(&self, id: &str, vault: &str) -> Result<(), Failure> {
        self.update_overview(id, vault, |o| o.archived = true).await
    }

    async fn password(
        &self,
        request: &PasswordRequest,
        value: Secret,
    ) -> Result<PasswordOutcome, Failure> {
        let request = request.clone();
        self.with(move |store, opened| {
            if request.item.trim().is_empty() || request.vault.trim().is_empty() {
                return Err(Failure::new("An item and explicit vault are required"));
            }
            let vault = opened.vault(&request.vault)?.clone();
            let entry = opened.entry(&vault.id, &request.item)?;
            let (item_id, overview) = (entry.item_id.clone(), entry.overview.clone());
            let mut d = details(store, opened, &vault.id, &item_id)?;
            let positions: Vec<usize> = d
                .fields
                .iter()
                .enumerate()
                .filter(|(_, f)| f.purpose.as_deref() == Some("PASSWORD"))
                .map(|(i, _)| i)
                .collect();
            if overview.category != "LOGIN" || positions.len() != 1 {
                return Err(Failure::new(
                    "Expected a Login with exactly one built-in password; nothing was changed",
                ));
            }
            let field = &mut d.fields[positions[0]];
            let same = field.value.as_ref().map(|v| v.expose()) == Some(value.expose());
            let mut outcome = PasswordOutcome {
                id: item_id.clone(),
                title: overview.title.clone(),
                vault: vault.name.clone(),
                reference: format!("op://{}/{item_id}/password", vault.id),
                matches: None,
                changed: None,
                verified: None,
            };
            if !request.apply {
                outcome.matches = Some(same);
                return Ok(outcome);
            }
            if !same {
                field.value = Some(value);
                let mut overview = overview;
                overview.updated_at = Some(vp_core::time::now_rfc3339());
                save(store, opened, &vault, &item_id, overview, d)?;
            }
            outcome.changed = Some(!same);
            outcome.verified = Some(true);
            Ok(outcome)
        })
        .await
    }
}

impl<U: Unlock> NativeBackend<U> {
    async fn update_overview(
        &self,
        id: &str,
        vault: &str,
        change: impl FnOnce(&mut Overview) + Send,
    ) -> Result<(), Failure> {
        let (id, vault) = (id.to_string(), vault.to_string());
        self.with(move |store, opened| {
            let vault = opened.vault(&vault)?.clone();
            let entry = opened.entry(&vault.id, &id)?;
            let (item_id, mut overview) = (entry.item_id.clone(), entry.overview.clone());
            let d = details(store, opened, &vault.id, &item_id)?;
            change(&mut overview);
            save(store, opened, &vault, &item_id, overview, d).map(|_| ())
        })
        .await
    }
}

// ---- Passkeys -------------------------------------------------------------------

impl<U: Unlock> NativeBackend<U> {
    /// The passkeys saved for `rp_id`, outside the archive. Reads overviews only.
    pub async fn passkeys(&self, rp_id: &str) -> Result<Vec<passkey::Found>, Failure> {
        let rp_id = rp_id.to_string();
        self.with(move |_, opened| {
            let mut found = Vec::new();
            for entry in opened.entries.iter().filter(|e| !e.overview.archived) {
                let Ok(vault) = opened.vault(&entry.vault_id) else {
                    continue;
                };
                for p in entry.overview.passkeys.iter().filter(|p| p.rp_id == rp_id) {
                    found.push(passkey::Found {
                        passkey: p.clone(),
                        item: entry.item_id.clone(),
                        vault: vault.name.clone(),
                        title: entry.overview.title.clone(),
                    });
                }
            }
            Ok(found)
        })
        .await
    }

    /// Makes a passkey and saves it: into `creation.item` when given (a login
    /// in that vault), otherwise into a new login named for the site.
    pub async fn create_passkey(
        &self,
        creation: &passkey::Creation,
    ) -> Result<passkey::Registration, Failure> {
        let creation = creation.clone();
        self.with(move |store, opened| {
            let vault = opened.vault(&creation.vault)?.clone();
            let now = vp_core::time::now_rfc3339();
            let (item_id, mut overview, mut d) = match creation.item.as_deref() {
                Some(item) => {
                    let entry = opened.entry(&vault.id, item)?;
                    if entry.overview.category != "LOGIN" || entry.overview.archived {
                        return Err(Failure::new("A passkey can be added only to a login"));
                    }
                    let (item_id, overview) = (entry.item_id.clone(), entry.overview.clone());
                    let d = details(store, opened, &vault.id, &item_id)?;
                    (item_id, overview, d)
                }
                None => {
                    let mut fields = vp_core::model::template("LOGIN");
                    if let Some(f) = fields
                        .iter_mut()
                        .find(|f| f.purpose.as_deref() == Some("USERNAME"))
                    {
                        f.value = Some(Secret::new(creation.user_name.clone()));
                    }
                    let overview = Overview {
                        title: creation.rp_id.clone(),
                        category: "LOGIN".into(),
                        tags: Vec::new(),
                        urls: vec![UrlEntry {
                            href: creation.origin.clone(),
                            label: None,
                            primary: true,
                        }],
                        favorite: false,
                        username: Some(creation.user_name.clone()).filter(|u| !u.is_empty()),
                        created_at: Some(now.clone()),
                        updated_at: None,
                        archived: false,
                        passkeys: Vec::new(),
                    };
                    (
                        new_id(),
                        overview,
                        Details {
                            fields,
                            ..Details::default()
                        },
                    )
                }
            };
            let key = passkey::Key::generate()?;
            let credential_id = passkey::new_credential_id()?;
            overview.passkeys.push(PasskeyInfo {
                credential_id: credential_id.clone(),
                rp_id: creation.rp_id.clone(),
                user_name: creation.user_name.clone(),
                created_at: Some(now.clone()),
            });
            overview.updated_at = Some(now);
            d.passkeys.push(StoredPasskey {
                credential_id: credential_id.clone(),
                rp_id: creation.rp_id.clone(),
                user_handle: creation.user_handle.clone(),
                user_display_name: creation.user_display_name.clone(),
                key: Secret::new(key.export().to_string()),
            });
            save(store, opened, &vault, &item_id, overview, d)?;
            passkey::register(&key, &credential_id, &creation, &item_id, &vault.name)
        })
        .await
    }

    /// Adds passkeys from an export to a login already in the vault (imported
    /// before, or the same site, username and password), leaving out any it
    /// holds already (same credential ID and site). Returns how many it added.
    pub async fn add_imported_passkeys(
        &self,
        vault_id: &str,
        item_id: &str,
        passkeys: Vec<passkey::Imported>,
    ) -> Result<usize, Failure> {
        let (vault_id, item_id) = (vault_id.to_string(), item_id.to_string());
        self.with(move |store, opened| {
            // A login matched outside this vault (in 1Password) takes none.
            let Ok(vault) = opened.vault(&vault_id).cloned() else {
                return Ok(0);
            };
            let Ok(entry) = opened.entry(&vault.id, &item_id) else {
                return Ok(0);
            };
            if entry.overview.category != "LOGIN" || entry.overview.archived {
                return Ok(0);
            }
            let (item_id, mut overview) = (entry.item_id.clone(), entry.overview.clone());
            let mut d = details(store, opened, &vault.id, &item_id)?;
            let new: Vec<&passkey::Imported> = passkeys
                .iter()
                .filter(|p| {
                    !d.passkeys
                        .iter()
                        .any(|s| s.credential_id == p.info.credential_id && s.rp_id == p.info.rp_id)
                })
                .collect();
            if new.is_empty() {
                return Ok(0);
            }
            for p in &new {
                overview.passkeys.retain(|o| {
                    !(o.credential_id == p.info.credential_id && o.rp_id == p.info.rp_id)
                });
                overview.passkeys.push(p.info.clone());
                d.passkeys.push(stored(p));
            }
            overview.updated_at = Some(vp_core::time::now_rfc3339());
            save(store, opened, &vault, &item_id, overview, d)?;
            Ok(new.len())
        })
        .await
    }

    /// Signs a sign-in with the saved passkey `request.credential_id` for `request.rp_id`.
    pub async fn sign_passkey(
        &self,
        request: &passkey::Request,
    ) -> Result<passkey::Assertion, Failure> {
        let request = request.clone();
        self.with(move |store, opened| {
            let missing = || Failure::new("That passkey is not in VisiPass");
            let entry = opened
                .entries
                .iter()
                .filter(|e| !e.overview.archived)
                .find(|e| {
                    e.overview.passkeys.iter().any(|p| {
                        p.credential_id == request.credential_id && p.rp_id == request.rp_id
                    })
                })
                .ok_or_else(missing)?;
            let d = details(store, opened, &entry.vault_id, &entry.item_id)?;
            let stored = d
                .passkeys
                .iter()
                .find(|p| p.credential_id == request.credential_id && p.rp_id == request.rp_id)
                .ok_or_else(missing)?;
            let key = passkey::Key::import(stored.key.expose())?;
            Ok(passkey::assert(&key, &request, &stored.user_handle))
        })
        .await
    }
}

/// `op://vault/item/[section/]field[?attribute=otp]`, by name or ID.
fn resolve_one(store: &Store, opened: &Opened, r: &SecretRef) -> Result<Secret, Failure> {
    let missing = || Failure::new(format!("Could not resolve {r}. Check it with vp find"));
    let text = r.as_str();
    let rest = text
        .strip_prefix("op://")
        .or_else(|| text.strip_prefix("vp://"))
        .ok_or_else(missing)?;
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let parts: Vec<&str> = path.split('/').collect();
    let (vault, item, section, field) = match parts.as_slice() {
        [v, i, f] => (*v, *i, None, *f),
        [v, i, s, f] => (*v, *i, Some(*s), *f),
        _ => return Err(missing()),
    };
    let vault = opened.vault(vault).map_err(|_| missing())?;
    let entry = opened.entry(&vault.id, item).map_err(|_| missing())?;
    let d = details(store, opened, &vault.id, &entry.item_id)?;
    let in_section = |f: &&Field| match section {
        None => true,
        Some(s) => f.section.as_ref().is_some_and(|x| {
            x.id.as_deref() == Some(s)
                || x.label
                    .as_deref()
                    .is_some_and(|l| l.eq_ignore_ascii_case(s))
        }),
    };
    let found = d
        .fields
        .iter()
        .filter(in_section)
        .find(|f| f.id == field)
        .or_else(|| {
            d.fields.iter().filter(in_section).find(|f| {
                f.label
                    .as_deref()
                    .is_some_and(|l| l.eq_ignore_ascii_case(field))
                    || f.display_label().eq_ignore_ascii_case(field)
            })
        })
        .ok_or_else(missing)?;
    let value = found
        .value
        .clone()
        .unwrap_or_else(|| Secret::new(String::new()));
    let wants_otp = query.split('&').any(|p| {
        p.eq_ignore_ascii_case("attribute=otp") || p.eq_ignore_ascii_case("attribute=totp")
    });
    if wants_otp {
        let totp = vp_core::totp::Totp::parse(value.expose())?;
        return Ok(Secret::new(totp.now().0));
    }
    Ok(value)
}

// ---- Sync (§11.1) ---------------------------------------------------------------

fn unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sync_folder_checked(folder: &std::path::Path) -> Result<PathBuf, Failure> {
    folder.canonicalize().ok().filter(|f| f.is_dir()).ok_or_else(|| {
        Failure::new(format!(
            "{} is not a folder. Choose the folder your sync service keeps in step on every device, such as ~/Dropbox or a Syncthing folder",
            folder.display()
        ))
    })
}

/// The vault item holding a bucket's keys (§11.1), so they sync and can be
/// rotated like any other secret.
fn bucket_item_title(config: &BucketConfig) -> String {
    format!("VisiPass sync storage: {}", config.bucket)
}
const BUCKET_ACCESS_FIELD: &str = "accessKeyId";
const BUCKET_SECRET_FIELD: &str = "secretAccessKey";

fn bucket_entry<'a>(opened: &'a Opened, config: &BucketConfig) -> Option<&'a Entry> {
    let title = bucket_item_title(config);
    opened
        .entries
        .iter()
        .find(|e| e.overview.title == title && !e.overview.archived)
}

fn bucket_keys(
    store: &Store,
    opened: &Opened,
    config: &BucketConfig,
) -> Result<BucketKeys, Failure> {
    let missing = || {
        Failure::new(format!(
            "The vault has no complete item titled \"{}\", which holds the keys to the sync bucket",
            bucket_item_title(config)
        ))
    };
    let entry = bucket_entry(opened, config).ok_or_else(missing)?;
    let found = details_at(store, opened, &entry.vault_id, &entry.item_id, &entry.rev)?;
    let value = |id: &str| {
        found
            .fields
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.value.clone())
            .ok_or_else(missing)
    };
    Ok(BucketKeys {
        access_key: value(BUCKET_ACCESS_FIELD)?,
        secret_key: value(BUCKET_SECRET_FIELD)?,
    })
}

/// Saves the keys in the vault, replacing the ones there if they differ.
fn keep_bucket_keys(
    store: &mut Store,
    opened: &mut Opened,
    config: &BucketConfig,
    keys: &BucketKeys,
) -> Result<(), Failure> {
    if let Ok(kept) = bucket_keys(store, opened, config)
        && kept.access_key.expose() == keys.access_key.expose()
        && kept.secret_key.expose() == keys.secret_key.expose()
    {
        return Ok(());
    }
    let existing = bucket_entry(opened, config).map(|e| {
        (
            e.vault_id.clone(),
            e.item_id.clone(),
            e.overview.created_at.clone(),
        )
    });
    let (vault, id, created_at) = match existing {
        Some((vault, id, created_at)) => (opened.vault(&vault)?.clone(), id, created_at),
        None => {
            let vault =
                opened.vaults.first().cloned().ok_or_else(|| {
                    Failure::new("The vault has no place to keep the bucket's keys")
                })?;
            (vault, new_id(), None)
        }
    };
    let now = vp_core::time::now_rfc3339();
    let field = |id: &str, label: &str, kind: &str, value: &Secret| Field {
        id: id.into(),
        label: Some(label.into()),
        kind: kind.into(),
        purpose: None,
        section: None,
        value: Some(value.clone()),
        reference: None,
    };
    let overview = Overview {
        title: bucket_item_title(config),
        category: "API_CREDENTIAL".into(),
        tags: Vec::new(),
        urls: vec![UrlEntry {
            href: config.endpoint.clone(),
            label: None,
            primary: true,
        }],
        favorite: false,
        username: None,
        created_at: created_at.or_else(|| Some(now.clone())),
        updated_at: Some(now),
        archived: false,
        passkeys: Vec::new(),
    };
    save(
        store,
        opened,
        &vault,
        &id,
        overview,
        Details {
            sections: Vec::new(),
            fields: vec![
                field(
                    BUCKET_ACCESS_FIELD,
                    "access key id",
                    "STRING",
                    &keys.access_key,
                ),
                field(
                    BUCKET_SECRET_FIELD,
                    "secret access key",
                    "CONCEALED",
                    &keys.secret_key,
                ),
            ],
            passkeys: Vec::new(),
        },
    )?;
    Ok(())
}

/// One round through a bucket. Only the steps touching the vault hold its
/// lock, so a slow or absent network holds up nothing else ([`vp_sync::Mirror`]).
/// `None` if the vault is locked.
fn bucket_cycle<U: Unlock>(
    inner: &Inner<U>,
    config: &BucketConfig,
    first: impl FnOnce(&mut Store, &mut Unlocked, &vp_sync::Mirror) -> vp_store::Result<vp_sync::Report>,
) -> Option<Result<vp_sync::Report, Failure>> {
    let keys = {
        let state = inner.state();
        bucket_keys(state.store.as_ref()?, state.opened.as_ref()?, config)
    };
    let config = config.clone();
    remote_cycle(
        inner,
        move || {
            vp_sync::Bucket::new(config, keys?)
                .map(|b| Box::new(b) as Box<dyn vp_sync::Storage>)
                .map_err(failure)
        },
        first,
    )
}

/// A round against storage on a network: fetch with the vault's lock let go,
/// run the round against the copy, send with the lock let go, then confirm.
fn remote_cycle<U: Unlock>(
    inner: &Inner<U>,
    storage: impl FnOnce() -> Result<Box<dyn vp_sync::Storage>, Failure>,
    first: impl FnOnce(&mut Store, &mut Unlocked, &vp_sync::Mirror) -> vp_store::Result<vp_sync::Report>,
) -> Option<Result<vp_sync::Report, Failure>> {
    let _one_at_a_time = inner.bucket_round.lock().unwrap_or_else(|e| e.into_inner());
    let position = inner.state().opened.as_ref()?.unlocked.position();
    let step =
        |run: &mut dyn FnMut(&mut Store, &mut Unlocked) -> vp_store::Result<vp_sync::Report>| {
            let mut state = inner.state();
            let state = &mut *state;
            let (Some(store), Some(opened)) = (state.store.as_mut(), state.opened.as_mut()) else {
                return Err(Failure::new("VisiPass locked during the sync round"));
            };
            let report = run(store, &mut opened.unlocked).map_err(failure)?;
            if report.applied > 0 {
                reindex(store, opened)?;
            }
            Ok(report)
        };
    let cycle = || {
        let remote = storage()?;
        let mirror = vp_sync::Mirror::fetch(remote.as_ref(), &position).map_err(failure)?;
        let mut first = Some(first);
        let mut report = step(&mut |store, unlocked| {
            first.take().expect("the first step runs once")(store, unlocked, &mirror)
        })?;
        // Another pass confirms what went out. A name another machine holds
        // queues again under a new ID, hence more than one.
        for _ in 0..3 {
            if !mirror.has_outgoing() {
                break;
            }
            report.written += mirror.send().map_err(failure)?;
            let next = step(&mut |store, unlocked| vp_sync::round(store, unlocked, &mirror))?;
            report.applied += next.applied;
            report.new_device_id |= next.new_device_id;
            report.devices = next.devices;
        }
        Ok(report)
    };
    Some(cycle())
}

impl<U: Unlock> NativeBackend<U> {
    /// Syncs through storage the embedding program supplies, before any
    /// folder or bucket in this device's settings; `None` stops using it. Not
    /// remembered: set it each time the program starts.
    pub fn set_sync_storage(&self, storage: Option<SyncStorage>) {
        *self
            .inner
            .sync_storage
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = storage;
        self.inner.changed.notify_one();
    }

    /// Makes this device's vault from the account in `storage`, given the
    /// Secret Key and master password, and syncs through it from then on.
    /// Refused if this device already has a vault.
    pub async fn sync_join_with(
        &self,
        storage: SyncStorage,
        secret: SecretKey,
        password: Secret,
    ) -> Result<vp_sync::Report, Failure> {
        let make = storage.clone();
        let report = self
            .join_from(move || make(), secret, password, |_| {})
            .await?;
        self.set_sync_storage(Some(storage));
        Ok(report)
    }

    /// The folder sync goes through, if it is on.
    pub fn sync_folder(&self) -> Option<PathBuf> {
        load_settings(&self.inner.paths.settings).sync_folder
    }

    /// Turns sync on through `folder` on the device that has the vault: writes
    /// the account record and a snapshot there, then syncs.
    pub async fn sync_setup(&self, folder: &std::path::Path) -> Result<vp_sync::Report, Failure> {
        let folder = sync_folder_checked(folder)?;
        if let Some(bucket) = load_settings(&self.inner.paths.settings).sync_bucket {
            return Err(Failure::new(format!(
                "Sync already goes through {}. Turn it off first with `vp sync off`",
                bucket.location()
            )));
        }
        if let Some(current) = self.sync_folder()
            && current != folder
        {
            return Err(Failure::new(format!(
                "Sync already goes through {}. Turn it off first with `vp sync off`",
                current.display()
            )));
        }
        self.open_for(Some(&format!("turn on sync through {}", folder.display())))
            .await?;
        let storage = vp_sync::Folder::new(&folder);
        let report = self
            .with(|store, opened| {
                let report =
                    vp_sync::setup(store, &mut opened.unlocked, &storage).map_err(failure)?;
                if report.applied > 0 {
                    reindex(store, opened)?;
                }
                Ok(report)
            })
            .await?;
        self.update_settings(|s| s.sync_folder = Some(folder))?;
        self.inner.state().last_sync = Some((SystemTime::now(), Ok(report.clone())));
        Ok(report)
    }

    /// Turns sync on through a bucket, checking first that the keys reach it.
    /// A device syncing through a folder moves over, bringing every file, so
    /// its other devices can follow whenever they next run this.
    pub async fn sync_setup_bucket(
        &self,
        config: BucketConfig,
        keys: BucketKeys,
    ) -> Result<vp_sync::Report, Failure> {
        config.check().map_err(Failure::new)?;
        let settings = load_settings(&self.inner.paths.settings);
        if let Some(current) = settings.sync_bucket.filter(|c| *c != config) {
            return Err(Failure::new(format!(
                "Sync already goes through {}. Turn it off first with `vp sync off`",
                current.location()
            )));
        }
        let moving = settings.sync_folder;
        self.open_for(Some(&format!("turn on sync through {}", config.location())))
            .await?;
        let (bucket, checking) = (config.clone(), keys.clone());
        tokio::task::spawn_blocking(move || {
            let bucket = vp_sync::Bucket::new(bucket, checking).map_err(failure)?;
            vp_sync::Storage::list(&bucket, "").map_err(failure)?;
            if let Some(folder) = moving {
                vp_sync::copy_all(&vp_sync::Folder::new(&folder), &bucket).map_err(failure)?;
            }
            Ok::<_, Failure>(())
        })
        .await
        .map_err(|_| Failure::new("Reaching the bucket failed"))??;
        let kept = config.clone();
        self.with(move |store, opened| keep_bucket_keys(store, opened, &kept, &keys))
            .await?;
        let inner = self.inner.clone();
        let target = config.clone();
        let report = tokio::task::spawn_blocking(move || {
            bucket_cycle(&inner, &target, |store, unlocked, mirror| {
                vp_sync::setup(store, unlocked, mirror)
            })
        })
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| Err(Failure::new("VisiPass locked while turning on sync")))?;
        self.update_settings(|s| {
            s.sync_bucket = Some(config);
            s.sync_folder = None;
        })?;
        self.inner.state().last_sync = Some((SystemTime::now(), Ok(report.clone())));
        Ok(report)
    }

    /// Makes this device's vault from another device's sync folder, given the
    /// Secret Key and master password, and turns sync on. Refused if this
    /// device already has a vault.
    pub async fn sync_join(
        &self,
        folder: &std::path::Path,
        secret: SecretKey,
        password: Secret,
    ) -> Result<vp_sync::Report, Failure> {
        let folder = sync_folder_checked(folder)?;
        let from = folder.clone();
        self.join_from(
            move || Ok(Box::new(vp_sync::Folder::new(&from)) as Box<dyn vp_sync::Storage>),
            secret,
            password,
            |s| s.sync_folder = Some(folder),
        )
        .await
    }

    /// The same from a bucket, whose keys the person typed for this.
    pub async fn sync_join_bucket(
        &self,
        config: BucketConfig,
        keys: BucketKeys,
        secret: SecretKey,
        password: Secret,
    ) -> Result<vp_sync::Report, Failure> {
        let (bucket, typed) = (config.clone(), keys.clone());
        let saved = config.clone();
        let report = self
            .join_from(
                move || {
                    vp_sync::Bucket::new(bucket, typed)
                        .map(|b| Box::new(b) as Box<dyn vp_sync::Storage>)
                        .map_err(failure)
                },
                secret,
                password,
                |s| s.sync_bucket = Some(saved),
            )
            .await?;
        // Normally the keys came in with the vault.
        self.with(move |store, opened| {
            if bucket_keys(store, opened, &config).is_err() {
                keep_bucket_keys(store, opened, &config, &keys)?;
            }
            Ok(())
        })
        .await?;
        Ok(report)
    }

    async fn join_from(
        &self,
        storage: impl FnOnce() -> Result<Box<dyn vp_sync::Storage>, Failure> + Send + 'static,
        secret: SecretKey,
        password: Secret,
        remember: impl FnOnce(&mut Settings),
    ) -> Result<vp_sync::Report, Failure> {
        let _gate = self.inner.gate.lock().await;
        let paths = self.inner.paths.clone();
        if paths.exists() || self.inner.secret_keys.read()?.is_some() {
            return Err(Failure::new(format!(
                "This device already has a VisiPass vault at {}. Joining makes a new one, so it was refused",
                paths.vault.display()
            )));
        }
        for dir in [paths.vault.parent(), paths.sequence.parent()]
            .into_iter()
            .flatten()
        {
            private_dir(dir)?;
        }
        self.inner.secret_keys.create(&secret.display())?;
        let inner = self.inner.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let paths = &inner.paths;
            let (store, unlocked, report) = vp_sync::join(
                storage()?.as_ref(),
                &paths.vault,
                &paths.sequence,
                password.expose(),
                &secret,
            )
            .map_err(failure)?;
            let opened = load(&store, unlocked)?;
            let mut state = inner.state();
            state.store = Some(store);
            state.opened_with_password(opened);
            state.last_sync = Some((SystemTime::now(), Ok(report.clone())));
            Ok::<_, Failure>(report)
        })
        .await
        .map_err(|_| Failure::new("Joining failed"))
        .and_then(|r| r);
        match joined {
            Ok(report) => {
                self.update_settings(remember)?;
                Ok(report)
            }
            Err(e) => {
                self.inner.secret_keys.remove();
                Err(e)
            }
        }
    }

    /// A timer tick need not touch a bucket checked a moment ago.
    fn bucket_checked_recently(&self) -> bool {
        load_settings(&self.inner.paths.settings)
            .sync_bucket
            .is_some()
            && self
                .inner
                .state()
                .last_sync
                .as_ref()
                .is_some_and(|(at, _)| at.elapsed().is_ok_and(|e| e < BUCKET_POLL))
    }

    /// One sync round, if sync is on and the vault is unlocked. Never asks to
    /// unlock: sync needs the keys, and waits for the human to unlock.
    pub async fn sync_round(&self) -> Option<Result<vp_sync::Report, Failure>> {
        let external = self
            .inner
            .sync_storage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(storage) = external {
            let inner = self.inner.clone();
            return tokio::task::spawn_blocking(move || {
                let result = remote_cycle(
                    &inner,
                    move || storage(),
                    |store, unlocked, mirror| vp_sync::round(store, unlocked, mirror),
                )?;
                inner.state().last_sync =
                    Some((SystemTime::now(), result.clone().map_err(|e| e.0.clone())));
                Some(result)
            })
            .await
            .ok()
            .flatten();
        }
        let settings = load_settings(&self.inner.paths.settings);
        if let Some(config) = settings.sync_bucket {
            let inner = self.inner.clone();
            return tokio::task::spawn_blocking(move || {
                let result = bucket_cycle(&inner, &config, |store, unlocked, mirror| {
                    vp_sync::round(store, unlocked, mirror)
                })?;
                inner.state().last_sync =
                    Some((SystemTime::now(), result.clone().map_err(|e| e.0.clone())));
                Some(result)
            })
            .await
            .ok()
            .flatten();
        }
        let folder = settings.sync_folder?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut state = inner.state();
            let state = &mut *state;
            let (Some(store), Some(opened)) = (state.store.as_mut(), state.opened.as_mut()) else {
                return None;
            };
            let result =
                vp_sync::round(store, &mut opened.unlocked, &vp_sync::Folder::new(&folder))
                    .map_err(failure)
                    .and_then(|report| {
                        if report.applied > 0 {
                            reindex(store, opened)?;
                        }
                        Ok(report)
                    });
            state.last_sync = Some((SystemTime::now(), result.clone().map_err(|e| e.0.clone())));
            Some(result)
        })
        .await
        .ok()
        .flatten()
    }

    /// Stops syncing on this device. The files already in the storage stay.
    pub fn sync_off(&self) -> Result<(), Failure> {
        self.set_sync_storage(None);
        self.update_settings(|s| {
            s.sync_folder = None;
            s.sync_bucket = None;
        })
    }

    /// Sync on this device, for `vp sync status`. Holds no values.
    pub fn sync_status(&self) -> serde_json::Value {
        use serde_json::json;
        let settings = load_settings(&self.inner.paths.settings);
        let bucket = settings.sync_bucket;
        let folder = settings.sync_folder;
        let state = self.inner.state();
        let external = self
            .inner
            .sync_storage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let mut status = json!({
            "on": folder.is_some() || bucket.is_some() || external,
            "external": external,
            "folder": folder,
            "unlocked": state.opened.is_some(),
        });
        if let Some(bucket) = &bucket {
            status["bucket"] = json!(bucket.location());
            status["endpoint"] = json!(bucket.endpoint);
        }
        if let Some(opened) = &state.opened {
            let position = opened.unlocked.position();
            status["device"] = json!(vp_store::hex(&position.device));
            status["sent"] = json!(position.seq);
            status["conflicts"] = json!(
                opened
                    .entries
                    .iter()
                    .filter(|e| !e.others.is_empty())
                    .count()
            );
        }
        if let Some((at, result)) = &state.last_sync {
            status["lastRound"] = match result {
                Ok(report) => json!({
                    "at": vp_core::time::rfc3339(unix(*at)),
                    "written": report.written,
                    "applied": report.applied,
                    "newDeviceId": report.new_device_id,
                    "devices": report.devices.iter().map(|d| json!({
                        "device": vp_store::hex(&d.device),
                        "applied": d.seq,
                        "available": d.available,
                        "heard": d.heard.map(|t| vp_core::time::rfc3339(unix(t))),
                        "forked": d.forked,
                        "refused": d.refused,
                    })).collect::<Vec<_>>(),
                }),
                Err(e) => json!({ "at": vp_core::time::rfc3339(unix(*at)), "error": e }),
            };
        }
        status
    }

    /// Every item in conflict, each version in full (the shown one first),
    /// with the revision that names it. For the app only: it carries values.
    pub async fn conflicts(&self) -> Result<Vec<Vec<(String, Item)>>, Failure> {
        self.with(|store, opened| {
            let mut out = Vec::new();
            for entry in opened.entries.iter().filter(|e| !e.others.is_empty()) {
                let vault = opened.vault(&entry.vault_id)?.clone();
                let mut versions = Vec::new();
                for rev in std::iter::once(entry.rev).chain(entry.others.iter().copied()) {
                    let overview: Overview = decode(
                        &store
                            .overview(&opened.unlocked, &vault.id, &entry.item_id, &rev)
                            .map_err(failure)?,
                    )?;
                    let d = details_at(store, opened, &vault.id, &entry.item_id, &rev)?;
                    versions.push((
                        rev.to_string(),
                        assemble(&vault, &entry.item_id, &overview, d),
                    ));
                }
                out.push(versions);
            }
            Ok(out)
        })
        .await
    }

    /// Settles a conflict: the version `keep` becomes the item, replacing
    /// every current version, which stay in its history.
    pub async fn resolve_conflict(
        &self,
        id: &str,
        vault: &str,
        keep: &str,
    ) -> Result<Item, Failure> {
        let (id, vault) = (id.to_string(), vault.to_string());
        let keep: Rev = keep.parse().map_err(failure)?;
        self.with(move |store, opened| {
            let vault = opened.vault(&vault)?.clone();
            let item_id = opened.entry(&vault.id, &id)?.item_id.clone();
            let heads = opened.unlocked.heads(&vault.id, &item_id);
            if !heads.contains(&keep) {
                return Err(Failure::new(
                    "That version is no longer current (perhaps it was settled on another device); look again",
                ));
            }
            let mut overview: Overview = decode(
                &store
                    .overview(&opened.unlocked, &vault.id, &item_id, &keep)
                    .map_err(failure)?,
            )?;
            overview.updated_at = Some(vp_core::time::now_rfc3339());
            let d = details_at(store, opened, &vault.id, &item_id, &keep)?;
            save_replacing(store, opened, &vault, &item_id, overview, d, &heads)
        })
        .await
    }
}
