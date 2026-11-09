//! Lets a sync round run against slow storage without waiting on it. The
//! vault's lock is held for a whole round, and everything that uses the vault
//! waits for that lock, so a round must not wait on a network: [`Mirror::fetch`]
//! brings in what the round will need, the round runs against the copy and
//! leaves what it writes queued, and [`Mirror::send`] delivers that after. Run
//! the round once more and it sees the result: a queued file now there with
//! the same bytes is confirmed, and with other bytes is another machine's.

use crate::{Created, Storage, change_path, devices_in, number_of};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::SystemTime;
use vp_store::sync::Position;
use vp_store::{Result, hex};

pub struct Mirror<'a> {
    remote: &'a dyn Storage,
    listed: RefCell<HashMap<String, Vec<String>>>,
    files: RefCell<HashMap<String, Vec<u8>>>,
    modified: HashMap<String, SystemTime>,
    outgoing: RefCell<Vec<(String, Vec<u8>)>>,
}

impl<'a> Mirror<'a> {
    /// Everything a round from `position` reads: the listings, and every
    /// other device's change files it has not applied.
    pub fn fetch(remote: &'a dyn Storage, position: &Position) -> Result<Mirror<'a>> {
        let account = hex(&position.account_id);
        let mut mirror = Mirror {
            remote,
            listed: RefCell::default(),
            files: RefCell::default(),
            modified: HashMap::new(),
            outgoing: RefCell::default(),
        };
        let mut listed = HashMap::new();
        for section in ["accounts", "devices", "snapshots"] {
            let dir = format!("{account}/{section}");
            listed.insert(dir.clone(), remote.list(&dir)?);
        }
        let own = format!("{account}/devices/{}", hex(&position.device));
        listed.insert(own.clone(), remote.list(&own)?);

        let mut devices: Vec<[u8; 16]> = listed[&format!("{account}/devices")]
            .iter()
            .filter_map(|name| vp_store::unhex::<16>(name))
            .collect();
        for followed in &position.devices {
            if !devices.contains(&followed.device) {
                devices.push(followed.device);
            }
        }
        for device in devices.into_iter().filter(|d| *d != position.device) {
            let dir = format!("{account}/devices/{}", hex(&device));
            let names = remote.list(&dir)?;
            let mut seqs: Vec<u64> = names.iter().filter_map(|n| number_of(n, "vpc")).collect();
            seqs.sort();
            listed.insert(dir, names);
            let known = position.devices.iter().find(|d| d.device == device);
            if !known.is_some_and(|d| d.forked) {
                for &seq in seqs.iter().filter(|s| known.is_none_or(|d| **s > d.seq)) {
                    let path = change_path(&account, &device, seq);
                    match remote.read(&path)? {
                        Some(bytes) => mirror.files.get_mut().insert(path, bytes),
                        None => break,
                    };
                }
            }
            if let Some(last) = seqs.last() {
                let path = change_path(&account, &device, *last);
                if let Some(time) = remote.modified(&path) {
                    mirror.modified.insert(path, time);
                }
            }
        }
        *mirror.listed.get_mut() = listed;
        Ok(mirror)
    }

    pub fn has_outgoing(&self) -> bool {
        !self.outgoing.borrow().is_empty()
    }

    /// Delivers what the round queued; how many files are new in the storage.
    pub fn send(&self) -> Result<usize> {
        let mut written = 0;
        for (path, bytes) in self.outgoing.take() {
            match self.remote.create(&path, &bytes)? {
                Created::Written | Created::Queued => {
                    written += 1;
                    self.files.borrow_mut().insert(path, bytes);
                }
                Created::Exists(there) => {
                    self.files.borrow_mut().insert(path, there);
                }
            }
        }
        Ok(written)
    }
}

impl Storage for Mirror<'_> {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        Ok(self.listed.borrow().get(dir).cloned().unwrap_or_default())
    }

    fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.files.borrow().get(path).cloned())
    }

    fn create(&self, path: &str, bytes: &[u8]) -> Result<Created> {
        if let Some(there) = self.files.borrow().get(path) {
            return Ok(Created::Exists(there.clone()));
        }
        let mut outgoing = self.outgoing.borrow_mut();
        if !outgoing.iter().any(|(queued, _)| queued == path) {
            outgoing.push((path.to_string(), bytes.to_vec()));
            if let Some((dir, name)) = path.rsplit_once('/') {
                let mut listed = self.listed.borrow_mut();
                let names = listed.entry(dir.to_string()).or_default();
                if !names.iter().any(|n| n == name) {
                    names.push(name.to_string());
                    names.sort();
                }
            }
        }
        Ok(Created::Queued)
    }

    fn modified(&self, path: &str) -> Option<SystemTime> {
        self.modified.get(path).copied()
    }
}

/// Copies every sync file to new storage, keeping each device's whole log, so
/// devices that have not caught up can still move over. A file already there
/// is left alone; one that differs means the storage belongs to something else.
pub fn copy_all(from: &dyn Storage, to: &dyn Storage) -> Result<usize> {
    let mut copied = 0;
    let mut copy_dir = |dir: &str, files: Vec<String>| -> Result<()> {
        let present = to.list(dir)?;
        for name in files.iter().filter(|name| !present.contains(name)) {
            let path = format!("{dir}/{name}");
            let Some(bytes) = from.read(&path)? else {
                continue;
            };
            match to.create(&path, &bytes)? {
                Created::Written | Created::Queued => copied += 1,
                Created::Exists(there) if there == bytes => {}
                Created::Exists(_) => {
                    return Err(vp_store::Error(format!(
                        "The new storage already holds a different {path}, so nothing more was copied"
                    )));
                }
            }
        }
        Ok(())
    };
    for account in from.list("")? {
        if vp_store::unhex::<16>(&account).is_none() {
            continue;
        }
        let records = format!("{account}/accounts");
        copy_dir(&records, from.list(&records)?)?;
        for section in ["devices", "snapshots"] {
            let parent = format!("{account}/{section}");
            for device in devices_in(from, &parent)? {
                let dir = format!("{parent}/{}", hex(&device));
                copy_dir(&dir, from.list(&dir)?)?;
            }
        }
    }
    Ok(copied)
}
