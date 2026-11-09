//! Sync through an S3-compatible bucket, against a fake server. The real thing
//! is covered by `a_real_bucket`, which needs one and is ignored by default.

#[path = "support/fake_s3.rs"]
mod fake_s3;

use fake_s3::{ACCESS_KEY, BUCKET, Fake, SECRET_KEY};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use vp_core::bucket::{BucketConfig, BucketKeys};
use vp_core::secret::Secret;
use vp_crypto::{KdfParams, SecretKey};
use vp_store::{Store, Unlocked};
use vp_sync::{Bucket, Created, Folder, Mirror, Report, Storage};

const CHEAP: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 1,
    p: 1,
};
const PASSWORD: &str = "hunter2!";

fn secret() -> SecretKey {
    SecretKey::from_bytes([42; 16])
}

fn keys(access: &str, secret: &str) -> BucketKeys {
    BucketKeys {
        access_key: Secret::new(access.into()),
        secret_key: Secret::new(secret.into()),
    }
}

fn fake(prefix: &str) -> (Arc<Fake>, Bucket) {
    let (fake, endpoint) = Fake::start();
    let location = format!("s3://{BUCKET}/{prefix}");
    let config = BucketConfig::parse(&location, Some(&endpoint), None).unwrap();
    (
        fake,
        Bucket::new(config, keys(ACCESS_KEY, SECRET_KEY)).unwrap(),
    )
}

struct Device {
    _dir: tempfile::TempDir,
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
            store,
            u,
        }
    }

    fn join(storage: &dyn Storage) -> Device {
        let (dir, db, sequence) = paths();
        let (store, u, _) = vp_sync::join(storage, &db, &sequence, PASSWORD, &secret()).unwrap();
        Device {
            _dir: dir,
            store,
            u,
        }
    }

    /// As the daemon does it: network apart from the steps that use the vault.
    fn cycle(&mut self, remote: &dyn Storage, setup: bool) -> Report {
        let mirror = Mirror::fetch(remote, &self.u.position()).unwrap();
        let mut report = if setup {
            vp_sync::setup(&mut self.store, &mut self.u, &mirror).unwrap()
        } else {
            vp_sync::round(&mut self.store, &mut self.u, &mirror).unwrap()
        };
        for _ in 0..3 {
            if !mirror.has_outgoing() {
                break;
            }
            report.written += mirror.send().unwrap();
            let next = vp_sync::round(&mut self.store, &mut self.u, &mirror).unwrap();
            report.applied += next.applied;
            report.new_device_id |= next.new_device_id;
        }
        report
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

fn storage_behaves(bucket: &Bucket) {
    assert_eq!(bucket.read("nothing/here").unwrap(), None);
    assert!(bucket.list("empty").unwrap().is_empty());
    for name in ["a", "b", "c", "d", "e"] {
        assert_eq!(
            bucket.create(&format!("dir/{name}"), b"one").unwrap(),
            Created::Written
        );
    }
    bucket.create("dir/sub/deep", b"one").unwrap();
    bucket.create("dir/.hidden", b"one").unwrap();
    assert_eq!(
        bucket.list("dir").unwrap(),
        ["a", "b", "c", "d", "e", "sub"]
    );
    assert_eq!(bucket.read("dir/a").unwrap().unwrap(), b"one");
    assert!(bucket.modified("dir/a").is_some());
    assert!(bucket.modified("dir/missing").is_none());
    assert_eq!(
        bucket.create("dir/a", b"two").unwrap(),
        Created::Exists(b"one".to_vec())
    );
    assert_eq!(bucket.read("dir/a").unwrap().unwrap(), b"one");
}

#[test]
fn a_bucket_lists_reads_and_never_replaces() {
    let (fake, bucket) = fake("some/path");
    storage_behaves(&bucket);
    let objects = fake.objects.lock().unwrap();
    assert!(
        objects
            .keys()
            .all(|k| k.starts_with("some/path/visipass-sync/")),
        "{objects:?}"
    );
}

#[test]
fn a_storage_without_conditional_writes_still_cannot_replace_a_file() {
    let (fake, bucket) = fake("");
    fake.no_conditional.store(true, Ordering::SeqCst);
    assert_eq!(bucket.create("f", b"one").unwrap(), Created::Written);
    assert_eq!(
        bucket.create("f", b"two").unwrap(),
        Created::Exists(b"one".to_vec())
    );
}

#[test]
fn refused_keys_say_so_and_never_appear_in_the_error() {
    let (fake, bucket) = fake("");
    fake.refuse.store(true, Ordering::SeqCst);
    let error = bucket.list("").unwrap_err().0;
    assert!(error.contains("refused these keys"), "{error}");
    assert!(!error.contains(SECRET_KEY) && !error.contains(ACCESS_KEY));
}

#[test]
fn nothing_listening_is_an_error_not_a_hang() {
    let config =
        BucketConfig::parse(&format!("s3://{BUCKET}"), Some("http://127.0.0.1:9"), None).unwrap();
    let bucket = Bucket::new(config, keys(ACCESS_KEY, SECRET_KEY)).unwrap();
    assert!(bucket.list("").unwrap_err().0.contains("Could not reach"));
}

#[test]
fn keys_with_spaces_are_refused_before_any_request() {
    let config =
        BucketConfig::parse(&format!("s3://{BUCKET}"), Some("http://127.0.0.1:9"), None).unwrap();
    assert!(Bucket::new(config, keys("a b", "c")).is_err());
}

#[test]
fn two_devices_stay_in_step_through_a_bucket() {
    let (_fake, bucket) = fake("");
    let mut a = Device::new();
    a.cycle(&bucket, true);

    let mut b = Device::join(&bucket);
    assert_eq!(b.get("A"), ["a1"]);

    a.set("A", "a2");
    let sent = a.cycle(&bucket, false);
    assert_eq!(sent.written, 1);
    assert_eq!(b.cycle(&bucket, false).applied, 1);
    assert_eq!(b.get("A"), ["a2"]);

    b.set("A", "a3");
    b.cycle(&bucket, false);
    a.cycle(&bucket, false);
    assert_eq!(a.get("A"), ["a3"]);

    // Nothing to do: nothing written, and the outbox is empty.
    assert_eq!(a.cycle(&bucket, false).written, 0);
    assert!(a.store.outbox(&a.u).unwrap().is_empty());
}

/// The vault's lock is held for the round, so the round must not use the network.
#[test]
fn the_round_itself_never_touches_the_network() {
    let (fake, bucket) = fake("");
    let mut a = Device::new();
    a.cycle(&bucket, true);
    let mut b = Device::join(&bucket);
    a.set("A", "a2");
    a.cycle(&bucket, false);
    b.set("B", "b1");

    let mirror = Mirror::fetch(&bucket, &b.u.position()).unwrap();
    let before = fake.count();
    let report = vp_sync::round(&mut b.store, &mut b.u, &mirror).unwrap();
    assert_eq!(fake.count(), before, "the round went to the network");
    assert_eq!(report.applied, 1);
    assert!(mirror.has_outgoing());
    assert!(
        !b.store.outbox(&b.u).unwrap().is_empty(),
        "a queued file is not confirmed until the bucket has it"
    );

    assert_eq!(mirror.send().unwrap(), 1);
    vp_sync::round(&mut b.store, &mut b.u, &mirror).unwrap();
    assert!(b.store.outbox(&b.u).unwrap().is_empty());
}

#[test]
fn a_failed_upload_keeps_the_change_for_next_time() {
    let (fake, bucket) = fake("");
    let mut a = Device::new();
    a.cycle(&bucket, true);
    let mut b = Device::join(&bucket);
    a.set("A", "a2");

    let mirror = Mirror::fetch(&bucket, &a.u.position()).unwrap();
    vp_sync::round(&mut a.store, &mut a.u, &mirror).unwrap();
    fake.refuse.store(true, Ordering::SeqCst);
    assert!(mirror.send().is_err());
    assert!(!a.store.outbox(&a.u).unwrap().is_empty());

    fake.refuse.store(false, Ordering::SeqCst);
    a.cycle(&bucket, false);
    assert!(a.store.outbox(&a.u).unwrap().is_empty());
    b.cycle(&bucket, false);
    assert_eq!(b.get("A"), ["a2"]);
}

/// Two machines with one device ID, from a restored backup. A storage that
/// ignores `If-None-Match` must still expose it.
#[test]
fn a_clone_is_caught_even_where_conditional_writes_are_ignored() {
    let (fake, bucket) = fake("");
    fake.ignore_conditional.store(true, Ordering::SeqCst);
    let mut a = Device::new();
    a.cycle(&bucket, true);
    let reader_seq = a.u.position().seq;

    // Another machine has taken the next number.
    let device = vp_store::hex(&a.u.position().device);
    let account = vp_store::hex(&a.u.position().account_id);
    let next = format!("{account}/devices/{device}/{:016x}.vpc", reader_seq + 1);
    bucket.create(&next, b"another machine's bytes").unwrap();

    a.set("A", "a2");
    let report = a.cycle(&bucket, false);
    assert!(report.new_device_id);
    assert_eq!(
        bucket.read(&next).unwrap().unwrap(),
        b"another machine's bytes"
    );
    assert_ne!(vp_store::hex(&a.u.position().device), device);
    assert!(a.store.outbox(&a.u).unwrap().is_empty());
}

#[test]
fn a_device_moves_from_a_folder_with_its_whole_history() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();
    let mut b = Device::join(&folder);
    a.set("A", "a2");
    vp_sync::round(&mut a.store, &mut a.u, &folder).unwrap();

    let (_fake, bucket) = fake("");
    assert!(vp_sync::copy_all(&folder, &bucket).unwrap() >= 3);
    a.cycle(&bucket, true);
    a.set("A", "a3");
    a.cycle(&bucket, false);

    // B had not seen a2. The log came too, so it catches up without a gap.
    assert_eq!(vp_sync::copy_all(&folder, &bucket).unwrap(), 0);
    b.cycle(&bucket, true);
    assert_eq!(b.get("A"), ["a3"]);

    let c = Device::join(&bucket);
    assert_eq!(c.get("A"), ["a3"]);
}

#[test]
fn setting_up_on_empty_storage_writes_a_snapshot_even_if_one_exists_elsewhere() {
    let shared = tempfile::tempdir().unwrap();
    let folder = Folder::new(shared.path());
    let mut a = Device::new();
    vp_sync::setup(&mut a.store, &mut a.u, &folder).unwrap();

    let (_fake, bucket) = fake("");
    a.cycle(&bucket, true);
    assert_eq!(Device::join(&bucket).get("A"), ["a1"]);
}

/// Against real storage, to check what a fake can't: signatures and
/// conditional writes. VP_TEST_S3=endpoint,bucket,access key,secret key
#[test]
#[ignore]
fn a_real_bucket() {
    let settings = std::env::var("VP_TEST_S3").expect("VP_TEST_S3");
    let parts: Vec<&str> = settings.split(',').collect();
    let run = vp_store::hex(&vp_crypto::random::<4>());
    let location = format!("s3://{}/test-{run}", parts[1]);
    let config = BucketConfig::parse(&location, Some(parts[0]), None).unwrap();
    let make = || Bucket::new(config.clone(), keys(parts[2], parts[3])).unwrap();
    storage_behaves(&make());

    let location = format!("s3://{}/vault-{run}", parts[1]);
    let config = BucketConfig::parse(&location, Some(parts[0]), None).unwrap();
    let bucket = Bucket::new(config, keys(parts[2], parts[3])).unwrap();
    let mut a = Device::new();
    a.cycle(&bucket, true);
    let mut b = Device::join(&bucket);
    a.set("A", "a2");
    a.cycle(&bucket, false);
    assert_eq!(b.cycle(&bucket, false).applied, 1);
    assert_eq!(b.get("A"), ["a2"]);
}
