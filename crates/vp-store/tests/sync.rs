//! §11.1 between two stores, with the storage played by plain byte vectors
//! that the tests may lose, reorder, replay or tamper with.

use std::path::PathBuf;
use vp_crypto::{KdfParams, SecretKey};
use vp_store::sync::{Applied, Sealed};
use vp_store::{Rev, Store, Unlocked};

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

impl Device {
    fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.vpdb");
        let sequence = dir.path().join("sequence");
        (dir, db, sequence)
    }

    /// A device with vault V1 holding item A, sync set up: (device, snapshot, record).
    fn first() -> (Device, Sealed, Vec<u8>) {
        let (dir, db, sequence) = Self::paths();
        let (mut store, mut u) = Store::create(&db, &sequence, PASSWORD, &secret(), CHEAP).unwrap();
        store.create_vault(&mut u, "V1", b"Private").unwrap();
        store
            .put_item(&mut u, "V1", "A", b"overview a1", b"secret a1", &[])
            .unwrap();
        let snapshot = store.snapshot(&mut u).unwrap();
        let record = store.account_record(&u).unwrap();
        (
            Device {
                _dir: dir,
                db,
                sequence,
                store,
                u,
            },
            snapshot,
            record,
        )
    }

    fn join(snapshot: &Sealed, record: &[u8]) -> Device {
        let (dir, db, sequence) = Self::paths();
        let (mut store, mut u) =
            Store::join(&db, &sequence, &[record.to_vec()], PASSWORD, &secret()).unwrap();
        store
            .apply_snapshot(&mut u, snapshot.device, snapshot.seq, &snapshot.bytes)
            .unwrap();
        Device {
            _dir: dir,
            db,
            sequence,
            store,
            u,
        }
    }

    fn edit(&mut self, item: &str, text: &str) -> Rev {
        let heads = self.u.heads("V1", item);
        let ov = format!("overview {text}");
        let det = format!("secret {text}");
        self.store
            .put_item(
                &mut self.u,
                "V1",
                item,
                ov.as_bytes(),
                det.as_bytes(),
                &heads[..heads.len().min(1)],
            )
            .unwrap()
    }

    fn send(&mut self) -> Sealed {
        self.store.commit_change(&mut self.u).unwrap().unwrap()
    }

    fn apply(&mut self, file: &Sealed) -> Applied {
        self.store
            .apply_change(&mut self.u, file.device, file.seq, &file.bytes)
            .unwrap()
    }

    fn details(&self, item: &str) -> Vec<Vec<u8>> {
        self.u
            .heads("V1", item)
            .iter()
            .map(|r| self.store.details(&self.u, "V1", item, r).unwrap().to_vec())
            .collect()
    }

    /// Reopens from disk, so every manifest is checked again.
    fn reopen(self) -> Device {
        let Device {
            _dir, db, sequence, ..
        } = self;
        let store = Store::open(&db, &sequence).unwrap();
        let u = store.unlock(PASSWORD, &secret()).unwrap();
        Device {
            _dir,
            db,
            sequence,
            store,
            u,
        }
    }
}

#[test]
fn a_joined_device_has_everything_and_follows_the_log() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    assert_eq!(b.details("A"), vec![b"secret a1".to_vec()]);
    assert_ne!(a.u.position().device, b.u.position().device);

    a.edit("A", "a2");
    a.edit("B", "b1");
    let first = a.send();
    assert_eq!(first.seq, 1);
    assert!(a.store.commit_change(&mut a.u).unwrap().is_none());
    a.edit("A", "a3");
    let second = a.send();

    assert_eq!(b.apply(&second), Applied::Gap);
    assert_eq!(b.apply(&first), Applied::Changes(2));
    assert_eq!(b.apply(&first), Applied::Already);
    assert_eq!(b.apply(&second), Applied::Changes(1));
    assert_eq!(b.details("A"), vec![b"secret a3".to_vec()]);
    assert_eq!(b.details("B"), vec![b"secret b1".to_vec()]);
    let b = b.reopen();
    assert_eq!(b.details("A"), vec![b"secret a3".to_vec()]);
    assert_eq!(b.u.position().devices[0].seq, 2);
}

#[test]
fn concurrent_edits_keep_both_versions_until_one_write_replaces_both() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    a.edit("A", "from a");
    b.edit("A", "from b");
    let (from_a, from_b) = (a.send(), b.send());
    assert_eq!(a.apply(&from_b), Applied::Changes(1));
    assert_eq!(b.apply(&from_a), Applied::Changes(1));
    for device in [&a, &b] {
        let mut both = device.details("A");
        both.sort();
        assert_eq!(
            both,
            vec![b"secret from a".to_vec(), b"secret from b".to_vec()]
        );
        assert_eq!(device.u.conflicts().len(), 1);
    }
    // Editing one side leaves the other side in place.
    let heads = a.u.heads("V1", "A");
    a.store
        .put_item(&mut a.u, "V1", "A", b"o", b"secret edited", &heads[..1])
        .unwrap();
    assert_eq!(a.u.heads("V1", "A").len(), 2);
    // Settling it names every head.
    let heads = a.u.heads("V1", "A");
    a.store
        .put_item(&mut a.u, "V1", "A", b"o", b"secret settled", &heads)
        .unwrap();
    assert!(a.u.conflicts().is_empty());
    assert_eq!(b.apply(&a.send()), Applied::Changes(2));
    assert!(b.u.conflicts().is_empty());
    assert_eq!(b.details("A"), vec![b"secret settled".to_vec()]);
    assert_eq!(a.reopen().details("A"), b.reopen().details("A"));
}

#[test]
fn tampered_forged_or_misplaced_files_are_refused() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    a.edit("A", "a2");
    let file = a.send();
    for i in [5, 40, file.bytes.len() - 1] {
        let mut bad = file.bytes.clone();
        bad[i] ^= 1;
        assert!(
            b.store
                .apply_change(&mut b.u, file.device, 1, &bad)
                .is_err()
        );
    }
    // The right bytes under another name.
    assert!(
        b.store
            .apply_change(&mut b.u, [9; 16], 1, &file.bytes)
            .is_err()
    );
    // Another account's file, under this one's names.
    let (mut other, _, _) = Device::first();
    other.edit("A", "other");
    let foreign = other.send();
    assert!(
        b.store
            .apply_change(&mut b.u, file.device, 1, &foreign.bytes)
            .is_err()
    );
    // None of that changed anything; the real file still applies.
    assert_eq!(b.apply(&file), Applied::Changes(1));
}

#[test]
fn a_device_whose_log_forks_is_stopped() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    let mut clone = Device::first_from(&a);
    a.edit("A", "a2");
    clone.edit("A", "clone");
    let (real, other) = (a.send(), clone.send());
    assert_eq!(real.seq, other.seq);
    assert_eq!(b.apply(&real), Applied::Changes(1));
    assert_eq!(b.apply(&other), Applied::Forked);
    a.edit("A", "a3");
    assert_eq!(b.apply(&a.send()), Applied::Forked);
    assert!(b.reopen().u.position().devices[0].forked);
}

impl Device {
    /// A copy of the device's disk, as a restored backup or cloned machine is.
    fn first_from(original: &Device) -> Device {
        let (dir, db, sequence) = Self::paths();
        std::fs::copy(&original.db, &db).unwrap();
        std::fs::copy(&original.sequence, &sequence).unwrap();
        let store = Store::open(&db, &sequence).unwrap();
        let u = store.unlock(PASSWORD, &secret()).unwrap();
        Device {
            _dir: dir,
            db,
            sequence,
            store,
            u,
        }
    }
}

#[test]
fn a_cloned_device_takes_a_new_id_and_both_lines_reach_the_others() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    let mut clone = Device::first_from(&a);
    a.edit("A", "a2");
    let real = a.send();
    clone.edit("B", "unsent");
    let lost = clone.send();
    assert_eq!(b.apply(&real), Applied::Changes(1));
    // The clone finds seq 1 taken by other bytes: new ID, and its own change goes out again.
    assert_ne!(lost.bytes, real.bytes);
    clone.store.new_device_id(&mut clone.u).unwrap();
    assert!(clone.store.outbox(&clone.u).unwrap().is_empty());
    let again = clone.send();
    assert_ne!(again.device, real.device);
    assert_eq!(again.seq, 1);
    assert_eq!(b.apply(&again), Applied::Changes(1));
    assert_eq!(b.details("B"), vec![b"secret unsent".to_vec()]);
    // The clone now follows the original ID as another device.
    assert_eq!(clone.apply(&real), Applied::Changes(1));
    assert_eq!(clone.details("A"), vec![b"secret a2".to_vec()]);
}

#[test]
fn joining_needs_the_password_and_secret_key_and_a_signed_record() {
    let (_a, _snapshot, record) = Device::first();
    let (_dir, db, sequence) = Device::paths();
    let error = Store::join(
        &db,
        &sequence,
        std::slice::from_ref(&record),
        "wrong!",
        &secret(),
    )
    .err()
    .unwrap();
    assert_eq!(error.0, "Wrong master password or Secret Key");
    let error = Store::join(
        &db,
        &sequence,
        std::slice::from_ref(&record),
        PASSWORD,
        &SecretKey::from_bytes([1; 16]),
    )
    .err()
    .unwrap();
    assert_eq!(error.0, "Wrong master password or Secret Key");
    assert!(!db.exists());
    // A record whose signature does not verify is not used, even with the right password.
    let mut bad = record.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(Store::join(&db, &sequence, &[bad], PASSWORD, &secret()).is_err());
    assert!(!db.exists());
}

#[test]
fn sync_files_hold_no_plaintext() {
    let (mut a, snapshot, _) = Device::first();
    a.edit("A", "a2");
    let change = a.send();
    for bytes in [&snapshot.bytes, &change.bytes] {
        // Long needles only: two bytes like the vault ID "V1" turn up in random ciphertext.
        for needle in [&b"secret"[..], b"overview", b"Private"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} found",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

#[test]
fn a_vault_made_on_two_devices_before_they_synced_merges() {
    let (mut a, snapshot, record) = Device::first();
    let mut b = Device::join(&snapshot, &record);
    a.store.create_vault(&mut a.u, "V9", b"Same").unwrap();
    b.store.create_vault(&mut b.u, "V9", b"Same").unwrap();
    a.store
        .put_item(&mut a.u, "V9", "X", b"o", b"from a", &[])
        .unwrap();
    b.store
        .put_item(&mut b.u, "V9", "Y", b"o", b"from b", &[])
        .unwrap();
    let (from_a, from_b) = (a.send(), b.send());
    assert_eq!(a.apply(&from_b), Applied::Changes(1));
    assert_eq!(b.apply(&from_a), Applied::Changes(1));
    let a = a.reopen();
    let y = a.u.heads("V9", "Y")[0];
    assert_eq!(&*a.store.details(&a.u, "V9", "Y", &y).unwrap(), b"from b");
}
