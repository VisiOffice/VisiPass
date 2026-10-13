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
use std::time::{Duration, Instant};
use vp_core::Failure;
use vp_core::backend::Backend;
use vp_core::model::{
    Destination, Field, FieldMeta, Item, ItemDetail, ItemSummary, Listed, PasswordOutcome,
    PasswordRequest, Receipt, Scope, SectionMeta, SectionRef, Url, UrlEntry, VaultRef,
};
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;
use vp_crypto::{KdfParams, SecretKey};
use vp_store::{AccountKey, Store, Unlocked, Write};
use zeroize::Zeroizing;

/// Asks the human for the master password. `None` if they cancel.
pub trait Unlock: Send + Sync + 'static {
    fn password(&self, retry: bool)
    -> impl Future<Output = Result<Option<Secret>, Failure>> + Send;

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
pub const IDLE_LOCK: Duration = Duration::from_secs(10 * 60);
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
}

#[derive(Serialize, Deserialize)]
struct Details {
    #[serde(default)]
    sections: Vec<SectionRef>,
    #[serde(default)]
    fields: Vec<Field>,
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
    overview: Overview,
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

    /// After a master-password unlock.
    fn opened_with_password(&mut self, opened: Opened) {
        self.opened = Some(opened);
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
    params: KdfParams,
    unlock: U,
    state: Mutex<State>,
    /// One unlock at a time.
    gate: tokio::sync::Mutex<()>,
}

impl<U> Inner<U> {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expire_if_idle(&self) {
        let mut state = self.state();
        if state.opened.is_some() && state.last_use.elapsed() >= IDLE_LOCK {
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
        let quick_unlock = load_settings(&paths.settings)
            .quick_unlock_secs
            .map(|secs| Duration::from_secs(secs).min(QUICK_UNLOCK_MAX));
        let inner = Arc::new(Inner {
            paths,
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
            }),
            gate: tokio::sync::Mutex::new(()),
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
        }
        Self { inner }
    }

    pub fn exists(&self) -> bool {
        self.inner.paths.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.state().opened.is_some()
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
            .and_then(|end| end.checked_duration_since(Instant::now()))
            .filter(|_| state.opened.is_some() || state.kept.is_some());
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
        if window.is_some()
            && let Err(e) = self.open().await
        {
            self.inner.state().quick_unlock = previous;
            return Err(e);
        }
        let settings = Settings {
            quick_unlock_secs: window.map(|w| w.as_secs()),
        };
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
        if paths.exists() || paths.secret_key.exists() {
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
        write_private(&paths.secret_key, format!("{}\n", *shown).as_bytes())?;
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
        let _gate = self.inner.gate.lock().await;
        self.inner.expire_if_idle();
        {
            let mut state = self.inner.state();
            if state.opened.is_some() {
                state.last_use = Instant::now();
                return Ok(());
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
        }
        if self.quick_unlock_with_kept_key().await? {
            return Ok(());
        }
        let secret_text = Zeroizing::new(
            std::fs::read_to_string(&self.inner.paths.secret_key).map_err(|_| {
                Failure::new(format!(
                    "This device has no Secret Key at {}. Restore it from your Emergency Kit",
                    self.inner.paths.secret_key.display()
                ))
            })?,
        );
        let secret = SecretKey::parse(&secret_text).map_err(|e| Failure::new(e.0))?;
        let secret = Arc::new(secret);
        for attempt in 0..UNLOCK_ATTEMPTS {
            let Some(password) = self.inner.unlock.password(attempt > 0).await? else {
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
        Err(Failure::new("Wrong master password; VisiPass stays locked"))
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
                return Err(Failure::new("Unlocking VisiPass was cancelled"));
            }
            Presence::Unavailable => return Ok(false),
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
        self.open().await?;
        let mut state = self.inner.state();
        let state = &mut *state;
        match (state.store.as_mut(), state.opened.as_mut()) {
            (Some(store), Some(opened)) => f(store, opened),
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
                        encode(&overview_of(item)),
                        encode(&Details {
                            sections: item.sections.clone(),
                            fields: item.fields.clone(),
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
                })
                .collect();
            store
                .put_items(&mut opened.unlocked, &vault.id, &writes)
                .map_err(failure)?;
            for item in fresh {
                opened.entries.push(Entry {
                    vault_id: vault.id.clone(),
                    item_id: item.id.clone(),
                    overview: overview_of(item),
                });
            }
            Ok((encoded.len(), skipped))
        })
        .await
    }
}

/// Decrypts every overview after unlock, to build the search index (§7.2).
fn load(store: &Store, unlocked: Unlocked) -> Result<Opened, Failure> {
    let mut vaults = Vec::new();
    let mut entries = Vec::new();
    for (vault_id, attrs) in store.vaults(&unlocked).map_err(failure)? {
        let attrs: VaultAttrs = decode(&attrs)?;
        for overview in store.overviews(&unlocked, &vault_id).map_err(failure)? {
            entries.push(Entry {
                vault_id: vault_id.clone(),
                item_id: overview.item_id,
                overview: decode(&overview.plaintext)?,
            });
        }
        vaults.push(VaultRef {
            id: vault_id,
            name: attrs.name,
        });
    }
    Ok(Opened {
        unlocked,
        vaults,
        entries,
    })
}

fn details(
    store: &Store,
    opened: &Opened,
    vault_id: &str,
    item_id: &str,
) -> Result<Details, Failure> {
    decode(
        &store
            .details(&opened.unlocked, vault_id, item_id)
            .map_err(failure)?,
    )
}

fn assemble(vault: &VaultRef, item_id: &str, overview: &Overview, details: Details) -> Item {
    Item {
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
fn save(
    store: &mut Store,
    opened: &mut Opened,
    vault: &VaultRef,
    item_id: &str,
    overview: Overview,
    fields: Details,
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
            .collect::<Vec<_>>()
            .join("\u{1}"),
    );
    store
        .put_item(
            &mut opened.unlocked,
            &vault.id,
            item_id,
            &encode(&overview),
            &encode(&fields),
        )
        .map_err(failure)?;
    let unverified = || {
        Failure::new(
            "The save is unverified: the item read back differently. Check it before retrying",
        )
    };
    let back = details(store, opened, &vault.id, item_id).map_err(|_| unverified())?;
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
            .collect::<Vec<_>>()
            .join("\u{1}"),
    );
    if got != expected {
        return Err(unverified());
    }
    let item = assemble(vault, item_id, &overview, back);
    match opened.entry_mut(&vault.id, item_id) {
        Some(entry) => entry.overview = overview,
        None => opened.entries.push(Entry {
            vault_id: vault.id.clone(),
            item_id: item_id.to_string(),
            overview,
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
            let (id, created_at) = if item.id.is_empty() {
                (new_id(), Some(now.clone()))
            } else {
                let entry = opened.entry(&vault.id, &item.id)?;
                (entry.item_id.clone(), entry.overview.created_at.clone())
            };
            let mut overview = overview_of(&item);
            overview.created_at = created_at;
            overview.updated_at = Some(now);
            save(
                store,
                opened,
                &vault,
                &id,
                overview,
                Details {
                    sections: item.sections.clone(),
                    fields: item.fields.clone(),
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
