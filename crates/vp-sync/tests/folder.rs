//! Two or three devices syncing through one shared folder, as a sync service
//! would keep it.

use std::path::{Path, PathBuf};
use vp_crypto::{KdfParams, SecretKey};
use vp_store::{Store, Unlocked};
use vp_sync::{Created, Folder, Storage};

const CHEAP: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 1,
    p: 1,
};
const PASSWORD: &str = "hunter2!";

fn secret() -> SecretKey {
    SecretKey::from_bytes([42; 16])
}

struct Device {
    _dir: tempfile::TempDir,
    db: PathBuf,
    sequence: PathBuf,
    store: Store,
    u: Unlocked,
}

fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.vpdb");
    let sequence = dir.path().join("sequence");
    (dir, db, sequence)
}

impl Device {
    fn new() -> Device {
        let (dir, db, sequence) = paths();
        let (mut store, mut u) = Store::create(&db, &sequence, PASSWORD, &secret(), CHEAP).unwrap();
        store.create_vault(&mut u, "V1", b"Private").unwrap();
        store
            .put_item(&mut u, "V1", "A", b"overview", b"a1", &[])
            .unwrap();
        Device {
            _dir: dir,
            db,
            sequence,
            store,
            u,
        }
    }

    fn join(folder: &Folder) -> Device {
        let (dir, db, sequence) = paths();
        let (store, u, _) = vp_sync::join(folder, &db, &sequence, PASSWORD, &secret()).unwrap();
        Device {
            _dir: dir,
            db,
            sequence,
            store,
            u,
        }
    }

    fn round(&mut self, folder: &Folder) -> vp_sync::Report {
        vp_sync::round(&mut self.store, &mut self.u, folder).unwrap()
    }

    fn set(&mut self, item: &str, value: &str) {
        let heads = self.u.heads("V1", item);
        self.store
            .put_item(
                &mut self.u,
                "V1",
                item,
                b"overview",
                value.as_bytes(),
                &heads[..heads.len().min(1)],
            )
            .unwrap();
    }

    fn get(&self, item: &str) -> Vec<String> {
        let mut values: Vec<String> = self
            .u
            .heads("V1", item)
            .iter()
            .map(|r| {
                String::from_utf8(self.store.details(&self.u, "V1", item, r).unwrap().to_vec())
                    .unwrap()
            })
            .collect();
        values.sort();
        values
    }
}

fn files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn set_up_join_and_edit_on_either_device() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let names = files(folder.root());
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names
            .iter()
            .any(|n| n.contains("/accounts/") && n.ends_with(".vpa"))
    );
    assert!(
        names
            .iter()
            .any(|n| n.contains("/snapshots/") && n.ends_with("0000000000000000.vps"))
    );

    let mut b = Device::join(&folder);
    assert_eq!(b.get("A"), vec!["a1"]);

    a.set("A", "a2");
    a.set("B", "b1");
    assert_eq!(a.round(&folder).written, 1);
    let report = b.round(&folder);
    assert_eq!(report.applied, 2);
    assert_eq!(report.devices.len(), 1);
    assert!(report.devices[0].heard.is_some());
    assert_eq!(b.get("A"), vec!["a2"]);

    b.set("B", "b2");
    b.round(&folder);
    assert_eq!(a.round(&folder).applied, 1);
    assert_eq!(a.get("B"), vec!["b2"]);
    // Nothing new: nothing written, nothing applied.
    let quiet = a.round(&folder);
    assert_eq!((quiet.written, quiet.applied), (0, 0));

    // A third device joins from the first snapshot and replays both logs.
    let c = Device::join(&folder);
    assert_eq!(c.get("A"), vec!["a2"]);
    assert_eq!(c.get("B"), vec!["b2"]);
}

#[test]
fn offline_edits_on_both_devices_become_a_conflict_on_both() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let mut b = Device::join(&folder);
    a.set("A", "from a");
    b.set("A", "from b");
    a.round(&folder);
    b.round(&folder);
    a.round(&folder);
    assert_eq!(a.get("A"), vec!["from a", "from b"]);
    assert_eq!(b.get("A"), vec!["from a", "from b"]);
}

#[test]
fn a_write_interrupted_before_it_was_confirmed_is_finished_not_renumbered() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    a.set("A", "a2");
    // Committed to the outbox, then the process died before writing it.
    let pending = a.store.commit_change(&mut a.u).unwrap().unwrap();
    assert_eq!(a.store.outbox(&a.u).unwrap().len(), 1);
    let report = a.round(&folder);
    assert_eq!(report.written, 1);
    assert!(!report.new_device_id);
    assert!(a.store.outbox(&a.u).unwrap().is_empty());
    // Written under its first number, with its first bytes.
    let account = vp_store::hex(&a.u.position().account_id);
    let path = format!(
        "{account}/devices/{}/{:016x}.vpc",
        vp_store::hex(&pending.device),
        pending.seq
    );
    assert_eq!(folder.read(&path).unwrap(), Some(pending.bytes.clone()));
    // Written but not confirmed: the next round confirms it without a new ID.
    a.set("A", "a3");
    let next = a.store.commit_change(&mut a.u).unwrap().unwrap();
    let path = format!(
        "{account}/devices/{}/{:016x}.vpc",
        vp_store::hex(&next.device),
        next.seq
    );
    assert_eq!(folder.create(&path, &next.bytes).unwrap(), Created::Written);
    let report = a.round(&folder);
    assert!(!report.new_device_id);
    assert!(a.store.outbox(&a.u).unwrap().is_empty());
}

#[test]
fn a_restored_backup_takes_a_new_id_and_nothing_is_lost() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let mut b = Device::join(&folder);

    // The same disk on a second machine.
    let (dir, db, sequence) = paths();
    std::fs::copy(&a.db, &db).unwrap();
    std::fs::copy(&a.sequence, &sequence).unwrap();
    let store = Store::open(&db, &sequence).unwrap();
    let u = store.unlock(PASSWORD, &secret()).unwrap();
    let mut copy = Device {
        _dir: dir,
        db,
        sequence,
        store,
        u,
    };

    a.set("A", "original");
    a.round(&folder);
    copy.set("B", "copy");
    let report = copy.round(&folder);
    assert!(report.new_device_id);
    assert_ne!(copy.u.position().device, a.u.position().device);
    assert_eq!(copy.get("A"), vec!["original"]);

    b.round(&folder);
    assert_eq!(b.get("A"), vec!["original"]);
    assert_eq!(b.get("B"), vec!["copy"]);
    assert_eq!(a.round(&folder).applied, 1);
    assert_eq!(a.get("B"), vec!["copy"]);
    assert!(b.round(&folder).devices.iter().all(|d| !d.forked));
}

#[test]
fn half_copied_or_foreign_files_are_retried_not_applied() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let mut b = Device::join(&folder);
    a.set("A", "a2");
    a.round(&folder);
    let account = vp_store::hex(&a.u.position().account_id);
    let path = folder.root().join(format!(
        "{account}/devices/{}/{:016x}.vpc",
        vp_store::hex(&a.u.position().device),
        1
    ));
    let whole = std::fs::read(&path).unwrap();
    std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();
    let report = b.round(&folder);
    assert_eq!(report.applied, 0);
    assert!(report.devices[0].refused.is_some());
    assert_eq!(b.get("A"), vec!["a1"]);
    // The sync service finishes copying it.
    std::fs::write(&path, &whole).unwrap();
    let report = b.round(&folder);
    assert_eq!(report.applied, 1);
    assert!(report.devices[0].refused.is_none());
}

#[test]
fn joining_an_empty_folder_or_with_the_wrong_password_leaves_nothing() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let (_dir, db, sequence) = paths();
    let error = vp_sync::join(&folder, &db, &sequence, PASSWORD, &secret())
        .err()
        .unwrap();
    assert!(error.0.contains("no VisiPass sync data"), "{}", error.0);
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let error = vp_sync::join(&folder, &db, &sequence, "wrong!", &secret())
        .err()
        .unwrap();
    assert_eq!(error.0, "Wrong master password or Secret Key");
    assert!(!db.exists());
}
