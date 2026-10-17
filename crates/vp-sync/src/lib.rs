//! Sync through storage each person already has (§11.1 of
//! `docs/crypto-design.md`): no VisiPass server. The storage holds one folder
//! per account; inside, each device writes only its own files, and never
//! changes a file once written:
//!
//! ```text
//! visipass-sync/<account_id>/
//!   accounts/<device_id>-<ak_generation>.vpa   account record (clear but signed)
//!   devices/<device_id>/<seq>.vpc              change files, seq = 1, 2, 3 ...
//!   snapshots/<device_id>/<seq>.vps            everything, as of that seq
//! ```
//!
//! So a sync service never sees two devices write one file, and needs no
//! transactions. Everything here is untrusted: the store checks every file.

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use vp_store::sync::{Applied, Sealed};
use vp_store::{Error, Result, Store, Unlocked, hex, unhex};

/// A device writes a new snapshot once its log has grown this much.
pub const SNAPSHOT_EVERY: u64 = 1000;

/// What [`Storage::create`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Created {
    Written,
    /// The name was taken; these are the bytes there.
    Exists(Vec<u8>),
}

/// Where sync files live. Paths are relative, `/`-separated.
pub trait Storage {
    /// The names in a directory, or none if it does not exist. Names that
    /// start with a dot (files still being written) are left out.
    fn list(&self, dir: &str) -> Result<Vec<String>>;
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>>;
    /// Writes a new file, never replacing one.
    fn create(&self, path: &str, bytes: &[u8]) -> Result<Created>;
    /// When the storage last changed the file, as it says.
    fn modified(&self, path: &str) -> Option<SystemTime>;
}

/// A folder a sync service keeps in step across machines (iCloud Drive,
/// Dropbox, Google Drive, OneDrive, Syncthing), or any folder at all.
pub struct Folder {
    root: PathBuf,
}

impl Folder {
    /// Sync files go in `visipass-sync` inside the folder chosen.
    pub fn new(chosen: &Path) -> Folder {
        Folder {
            root: chosen.join("visipass-sync"),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .filter(|p| !p.is_empty())
            .fold(self.root.clone(), |path, part| path.join(part))
    }
}

fn io(what: &str, path: &Path) -> Error {
    Error(format!("Could not {what} {}", path.display()))
}

impl Storage for Folder {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let path = self.path(dir);
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(io("read", &path)),
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        Ok(names)
    }

    fn read(&self, relative: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(relative);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(io("read", &path)),
        }
    }

    /// A temporary file beside the target, flushed to disk, then linked into
    /// place: linking fails if the name exists, so nothing is ever replaced,
    /// and a reader never sees a half-written file under the real name.
    fn create(&self, relative: &str, bytes: &[u8]) -> Result<Created> {
        use std::io::Write;
        use std::os::unix::fs::DirBuilderExt;
        let target = self.path(relative);
        let dir = target.parent().unwrap_or(&self.root).to_path_buf();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|_| io("create", &dir))?;
        if let Some(existing) = self.read(relative)? {
            return Ok(Created::Exists(existing));
        }
        let temporary = dir.join(format!(".tmp-{}", hex(&vp_crypto::random::<8>())));
        let written = std::fs::File::create(&temporary)
            .and_then(|mut f| f.write_all(bytes).and_then(|_| f.sync_all()));
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
            return Err(io("write", &target));
        }
        let placed = match std::fs::hard_link(&temporary, &target) {
            Ok(()) => Ok(Created::Written),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self
                .read(relative)?
                .map(Created::Exists)
                .ok_or_else(|| io("write", &target)),
            // Some synced folders cannot hard-link; the check above stands in.
            Err(_) => std::fs::rename(&temporary, &target)
                .map(|_| Created::Written)
                .map_err(|_| io("write", &target)),
        };
        let _ = std::fs::remove_file(&temporary);
        if let Ok(dir) = std::fs::File::open(&dir) {
            let _ = dir.sync_all();
        }
        placed
    }

    fn modified(&self, relative: &str) -> Option<SystemTime> {
        std::fs::metadata(self.path(relative)).ok()?.modified().ok()
    }
}

// ---- Names ----------------------------------------------------------------

fn numbered(seq: u64, extension: &str) -> String {
    format!("{seq:016x}.{extension}")
}

fn number_of(name: &str, extension: &str) -> Option<u64> {
    let digits = name.strip_suffix(extension)?.strip_suffix('.')?;
    (digits.len() == 16)
        .then(|| u64::from_str_radix(digits, 16).ok())
        .flatten()
}

fn change_path(account: &str, device: &[u8; 16], seq: u64) -> String {
    format!("{account}/devices/{}/{}", hex(device), numbered(seq, "vpc"))
}

fn snapshot_path(account: &str, device: &[u8; 16], seq: u64) -> String {
    format!(
        "{account}/snapshots/{}/{}",
        hex(device),
        numbered(seq, "vps")
    )
}

/// Every numbered file of one device in a directory, in order.
fn numbered_files(storage: &dyn Storage, dir: &str, extension: &str) -> Result<Vec<u64>> {
    let mut seqs: Vec<u64> = storage
        .list(dir)?
        .iter()
        .filter_map(|name| number_of(name, extension))
        .collect();
    seqs.sort();
    Ok(seqs)
}

fn devices_in(storage: &dyn Storage, dir: &str) -> Result<Vec<[u8; 16]>> {
    Ok(storage
        .list(dir)?
        .iter()
        .filter_map(|name| unhex::<16>(name))
        .collect())
}

// ---- Rounds -----------------------------------------------------------------

/// Another device, as this round found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceReport {
    pub device: [u8; 16],
    /// Its last change file applied here.
    pub seq: u64,
    /// Its newest change file in the storage.
    pub available: u64,
    /// When the storage last got a file from it.
    pub heard: Option<SystemTime>,
    /// Its log forked: sync with it has stopped.
    pub forked: bool,
    /// Its next file did not verify, and why. A sync service may show a file
    /// before it has finished copying it, so this is retried every round.
    pub refused: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Files this device wrote.
    pub written: usize,
    /// Revisions that came in.
    pub applied: usize,
    /// This device found another machine writing under its ID and took a new one.
    pub new_device_id: bool,
    pub devices: Vec<DeviceReport>,
}

/// First sync on the device that has the vault: the account record, a
/// snapshot, then a round.
pub fn setup(store: &mut Store, u: &mut Unlocked, storage: &dyn Storage) -> Result<Report> {
    let position = u.position();
    let account = hex(&position.account_id);
    let record = store.account_record(u)?;
    let name = format!(
        "{account}/accounts/{}-{}.vpa",
        hex(&position.device),
        position.ak_generation
    );
    storage.create(&name, &record)?;
    if position.snapshot.is_none() {
        let snapshot = store.snapshot(u)?;
        storage.create(
            &snapshot_path(&account, &snapshot.device, snapshot.seq),
            &snapshot.bytes,
        )?;
    }
    round(store, u, storage)
}

/// One sync round: send what this device has not sent, then apply every
/// other device's new change files in order.
pub fn round(store: &mut Store, u: &mut Unlocked, storage: &dyn Storage) -> Result<Report> {
    let mut report = Report::default();
    let account = hex(&u.position().account_id);
    // A folder whose sync service is not running (an unmounted drive, say)
    // must not quietly become a second, separate sync folder.
    if storage.list(&format!("{account}/accounts"))?.is_empty() {
        return Err(Error(
            "The sync folder does not hold this vault's account record. Is the folder available on this device? Run `vp sync setup <folder>` to start over".into(),
        ));
    }

    // Another machine writing under this device's ID shows up as files this
    // device did not write.
    let position = u.position();
    let outbox = store.outbox(u)?;
    let own = numbered_files(
        storage,
        &format!("{account}/devices/{}", hex(&position.device)),
        "vpc",
    )?;
    for seq in own.into_iter().filter(|s| *s > position.seq) {
        let ours = outbox.iter().any(|o| o.seq == seq);
        if !ours {
            store.new_device_id(u)?;
            report.new_device_id = true;
            break;
        }
    }

    for _ in 0..2 {
        store.commit_change(u)?;
        let mut taken = false;
        for Sealed { device, seq, bytes } in store.outbox(u)? {
            match storage.create(&change_path(&account, &device, seq), &bytes)? {
                Created::Written => {
                    report.written += 1;
                    store.confirm(seq)?;
                }
                Created::Exists(there) if there == bytes => store.confirm(seq)?,
                Created::Exists(_) => {
                    taken = true;
                    break;
                }
            }
        }
        if !taken {
            break;
        }
        store.new_device_id(u)?;
        report.new_device_id = true;
    }

    let me = u.position().device;
    let mut devices = devices_in(storage, &format!("{account}/devices"))?;
    for followed in u.position().devices {
        if !devices.contains(&followed.device) {
            devices.push(followed.device);
        }
    }
    for device in devices {
        if device == me {
            continue;
        }
        let dir = format!("{account}/devices/{}", hex(&device));
        let seqs = numbered_files(storage, &dir, "vpc")?;
        let known = |u: &Unlocked| {
            u.position()
                .devices
                .into_iter()
                .find(|d| d.device == device)
        };
        let mut refused = None;
        for &seq in &seqs {
            if known(u).is_some_and(|d| d.forked || seq <= d.seq) {
                continue;
            }
            let Some(bytes) = storage.read(&change_path(&account, &device, seq))? else {
                break;
            };
            match store.apply_change(u, device, seq, &bytes) {
                Ok(Applied::Changes(n)) => report.applied += n,
                Ok(Applied::Already) => {}
                Ok(Applied::Gap) | Ok(Applied::Forked) => break,
                Err(e) => {
                    refused = Some(e.0);
                    break;
                }
            }
        }
        let state = known(u);
        report.devices.push(DeviceReport {
            device,
            seq: state.as_ref().map_or(0, |d| d.seq),
            available: seqs.last().copied().unwrap_or(0),
            heard: seqs
                .last()
                .and_then(|s| storage.modified(&change_path(&account, &device, *s))),
            forked: state.is_some_and(|d| d.forked),
            refused,
        });
    }

    let position = u.position();
    if position.seq >= position.snapshot.unwrap_or(0) + SNAPSHOT_EVERY {
        let snapshot = store.snapshot(u)?;
        storage.create(
            &snapshot_path(&account, &snapshot.device, snapshot.seq),
            &snapshot.bytes,
        )?;
        report.written += 1;
    }
    Ok(report)
}

/// Makes this device's vault from the storage: the account record unlocks
/// with the master password and Secret Key, the newest snapshot that verifies
/// fills it, and a round brings in everything since. Nothing is left behind
/// if it fails.
pub fn join(
    storage: &dyn Storage,
    vault: &Path,
    sequence_file: &Path,
    password: &str,
    secret_key: &vp_crypto::SecretKey,
) -> Result<(Store, Unlocked, Report)> {
    let mut records = Vec::new();
    for account in storage.list("")? {
        if unhex::<16>(&account).is_none() {
            continue;
        }
        for name in storage.list(&format!("{account}/accounts"))? {
            if name.ends_with(".vpa")
                && let Some(bytes) = storage.read(&format!("{account}/accounts/{name}"))?
            {
                records.push(bytes);
            }
        }
    }
    if records.is_empty() {
        return Err(Error(
            "There is no VisiPass sync data in that folder. Set sync up first on the device that has your vault: vp sync setup <folder>".into(),
        ));
    }
    let (mut store, mut u) = Store::join(vault, sequence_file, &records, password, secret_key)?;
    let filled = (|| {
        let account = hex(&u.position().account_id);
        let mut snapshots = Vec::new();
        for device in devices_in(storage, &format!("{account}/snapshots"))? {
            let dir = format!("{account}/snapshots/{}", hex(&device));
            if let Some(&seq) = numbered_files(storage, &dir, "vps")?.last() {
                let path = snapshot_path(&account, &device, seq);
                snapshots.push((storage.modified(&path), seq, device, path));
            }
        }
        snapshots.sort_by(|a, b| b.cmp(a));
        let mut last_error = Error("No snapshot of the vault is in the storage yet".into());
        for (_, seq, device, path) in snapshots {
            let Some(bytes) = storage.read(&path)? else {
                continue;
            };
            match store.apply_snapshot(&mut u, device, seq, &bytes) {
                Ok(_) => return round(&mut store, &mut u, storage),
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    })();
    match filled {
        Ok(report) => Ok((store, u, report)),
        Err(e) => {
            drop(store);
            let _ = std::fs::remove_file(vault);
            let _ = std::fs::remove_file(sequence_file);
            Err(e)
        }
    }
}
