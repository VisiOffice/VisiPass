use rusqlite::Connection;
use std::path::PathBuf;
use vp_crypto::{KdfParams, SecretKey};
use vp_store::{Rev, Store};

const CHEAP: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 1,
    p: 1,
};

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    sequence: PathBuf,
    secret: [u8; 16],
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            db: dir.path().join("account.vpdb"),
            sequence: dir.path().join("sequence"),
            secret: [42; 16],
            _dir: dir,
        }
    }

    fn secret(&self) -> SecretKey {
        SecretKey::from_bytes(self.secret)
    }

    /// One vault with two items; the first has been saved twice.
    fn populated(&self) {
        let (mut store, mut unlocked) =
            Store::create(&self.db, &self.sequence, "hunter2!", &self.secret(), CHEAP).unwrap();
        store
            .create_vault(&mut unlocked, "V1", b"{\"name\":\"Private\"}")
            .unwrap();
        let a1 = store
            .put_item(&mut unlocked, "V1", "A", b"overview a1", b"secret a1", &[])
            .unwrap();
        store
            .put_item(&mut unlocked, "V1", "B", b"overview b1", b"secret b1", &[])
            .unwrap();
        let a2 = store
            .put_item(
                &mut unlocked,
                "V1",
                "A",
                b"overview a2",
                b"secret a2",
                &[a1],
            )
            .unwrap();
        assert_eq!(unlocked.heads("V1", "A"), vec![a2]);
    }

    fn store(&self) -> Store {
        Store::open(&self.db, &self.sequence).unwrap()
    }

    fn sql(&self, statement: &str) {
        Connection::open(&self.db)
            .unwrap()
            .execute_batch(statement)
            .unwrap();
    }

    fn unlock_error(&self) -> String {
        match self.store().unlock("hunter2!", &self.secret()) {
            Ok(_) => panic!("unlock should have failed"),
            Err(e) => e.0,
        }
    }
}

#[test]
fn items_round_trip_through_a_reopened_store() {
    let f = Fixture::new();
    f.populated();
    let store = f.store();
    let unlocked = store.unlock("hunter2!", &f.secret()).unwrap();
    let overviews = store.overviews(&unlocked, "V1").unwrap();
    assert_eq!(overviews.len(), 2);
    assert_eq!(&*overviews[0].plaintext, b"overview a2");
    let (a, b) = (&overviews[0].rev, &overviews[1].rev);
    assert_eq!(
        &*store.details(&unlocked, "V1", "A", a).unwrap(),
        b"secret a2"
    );
    assert_eq!(
        &*store.details(&unlocked, "V1", "B", b).unwrap(),
        b"secret b1"
    );
    let vaults = store.vaults(&unlocked).unwrap();
    assert_eq!(&*vaults[0].1, b"{\"name\":\"Private\"}");
}

#[test]
fn nothing_typed_by_a_human_is_in_the_file() {
    let f = Fixture::new();
    f.populated();
    let bytes = std::fs::read(&f.db).unwrap();
    for needle in [
        &b"secret a"[..],
        b"overview a",
        b"overview b",
        b"Private",
        b"hunter2",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "{} found in the file",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn a_wrong_password_or_secret_key_does_not_unlock() {
    let f = Fixture::new();
    f.populated();
    let store = f.store();
    assert!(store.unlock("hunter3!", &f.secret()).is_err());
    let error = store
        .unlock("hunter2!", &SecretKey::from_bytes([1; 16]))
        .err()
        .unwrap();
    assert_eq!(error.0, "Wrong master password or Secret Key");
}

#[test]
fn replacing_an_item_with_its_older_version_is_detected() {
    let f = Fixture::new();
    f.populated();
    // Make A's first revision current again: a valid ciphertext, but rolled back.
    f.sql("UPDATE revision SET head = 1 - head WHERE item_id = 'A';");
    assert!(f.unlock_error().contains("integrity check"));
}

#[test]
fn swapping_ciphertexts_between_items_is_detected() {
    let f = Fixture::new();
    f.populated();
    let store = f.store();
    let unlocked = store.unlock("hunter2!", &f.secret()).unwrap();
    // While unlocked: B's row now carries A's details.
    f.sql("UPDATE revision SET details = (SELECT details FROM revision WHERE item_id = 'A' AND head = 1) WHERE item_id = 'B';");
    let b = unlocked.heads("V1", "B")[0];
    assert!(
        store
            .details(&unlocked, "V1", "B", &b)
            .unwrap_err()
            .0
            .contains("integrity check")
    );
    assert!(f.unlock_error().contains("integrity check"));
}

#[test]
fn deleting_a_row_is_detected() {
    let f = Fixture::new();
    f.populated();
    f.sql("DELETE FROM revision WHERE item_id = 'B';");
    assert!(f.unlock_error().contains("integrity check"));

    let g = Fixture::new();
    g.populated();
    g.sql("DELETE FROM revision WHERE head = 0;");
    assert!(g.unlock_error().contains("integrity check"));
}

#[test]
fn rolling_back_the_whole_file_is_detected() {
    let f = Fixture::new();
    let (mut store, mut unlocked) =
        Store::create(&f.db, &f.sequence, "hunter2!", &f.secret(), CHEAP).unwrap();
    store.create_vault(&mut unlocked, "V1", b"attrs").unwrap();
    drop(store);
    let backup = std::fs::read(&f.db).unwrap();
    let mut store = f.store();
    store
        .put_item(&mut unlocked, "V1", "A", b"o", b"d", &[])
        .unwrap();
    drop(store);
    std::fs::write(&f.db, backup).unwrap();
    assert!(f.unlock_error().contains("went backwards"));
}

#[test]
fn tampering_with_the_password_parameters_is_refused() {
    let f = Fixture::new();
    f.populated();
    f.sql("UPDATE account SET m_kib = 99999999;");
    assert!(f.unlock_error().contains("out of bounds"));
    let g = Fixture::new();
    g.populated();
    g.sql("UPDATE account SET t = 2;");
    assert!(g.unlock_error().contains("Wrong master password"));
}

#[test]
fn a_kept_account_key_reopens_the_vault_with_the_same_checks() {
    let f = Fixture::new();
    f.populated();
    let store = f.store();
    let key = store
        .unlock("hunter2!", &f.secret())
        .unwrap()
        .into_account_key();
    let unlocked = store.unlock_with_key(key).unwrap();
    assert_eq!(unlocked.vault_ids(), vec!["V1".to_string()]);
    let key = unlocked.into_account_key();

    f.sql("DELETE FROM revision WHERE item_id = 'B'");
    match f.store().unlock_with_key(key) {
        Ok(_) => panic!("a deleted row must still be caught"),
        Err(e) => assert!(e.0.contains("integrity check"), "{}", e.0),
    }
}

#[test]
fn an_account_key_from_another_vault_is_refused() {
    let (a, b) = (Fixture::new(), Fixture::new());
    a.populated();
    b.populated();
    let key = a
        .store()
        .unlock("hunter2!", &a.secret())
        .unwrap()
        .into_account_key();
    assert!(b.store().unlock_with_key(key).is_err());
}

#[test]
fn a_write_must_name_the_current_revision_it_replaces() {
    let f = Fixture::new();
    f.populated();
    let mut store = f.store();
    let mut unlocked = store.unlock("hunter2!", &f.secret()).unwrap();
    let stale = Rev {
        device: unlocked.position().device,
        n: 1,
    };
    let error = store
        .put_item(&mut unlocked, "V1", "A", b"o", b"d", &[stale])
        .unwrap_err();
    assert!(error.0.contains("changed since it was read"), "{}", error.0);
    let error = store
        .put_item(&mut unlocked, "V1", "A", b"o", b"d", &[])
        .unwrap_err();
    assert!(error.0.contains("already exists"), "{}", error.0);
    // Nothing half-done is left behind: it still opens.
    drop(store);
    f.store().unlock("hunter2!", &f.secret()).unwrap();
}

/// A schema-1 file made by VisiPass 0.10.3: vault V1 with A (saved twice) and
/// B, and an empty vault V2. Password hunter2!, Secret Key all 42s.
#[test]
fn a_schema_1_vault_is_checked_backed_up_and_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.vpdb");
    let sequence = dir.path().join("sequence");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.vpdb");
    std::fs::copy(fixture, &db).unwrap();
    let secret = SecretKey::from_bytes([42; 16]);

    // Tampering is still caught in the old format, before anything changes.
    Connection::open(&db)
        .unwrap()
        .execute_batch("UPDATE item SET item_version = 1 WHERE item_id = 'A';")
        .unwrap();
    let error = Store::open(&db, &sequence)
        .unwrap()
        .unlock("hunter2!", &secret)
        .err()
        .unwrap();
    assert!(error.0.contains("integrity check"), "{}", error.0);
    std::fs::copy(fixture, &db).unwrap();

    let store = Store::open(&db, &sequence).unwrap();
    let unlocked = store.unlock("hunter2!", &secret).unwrap();
    assert_eq!(
        unlocked.vault_ids(),
        vec!["V1".to_string(), "V2".to_string()]
    );
    let overviews = store.overviews(&unlocked, "V1").unwrap();
    assert_eq!(overviews.len(), 2);
    assert_eq!(&*overviews[0].plaintext, b"overview a2");
    assert_eq!(overviews[0].rev.n, 2);
    let a = overviews[0].rev;
    assert_eq!(
        &*store.details(&unlocked, "V1", "A", &a).unwrap(),
        b"secret a2"
    );
    let a1 = Rev {
        device: a.device,
        n: 1,
    };
    assert_eq!(
        &*store.details(&unlocked, "V1", "A", &a1).unwrap(),
        b"secret a1"
    );
    drop((store, unlocked));

    let mut backup = db.as_os_str().to_owned();
    backup.push(".schema1-backup");
    let original = Connection::open(std::path::PathBuf::from(backup)).unwrap();
    let rows: i64 = original
        .query_row("SELECT count(*) FROM history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);

    // Migrated once; it opens as schema 2 from now on, with every check.
    let mut store = Store::open(&db, &sequence).unwrap();
    let mut unlocked = store.unlock("hunter2!", &secret).unwrap();
    store
        .put_item(&mut unlocked, "V1", "A", b"overview a3", b"secret a3", &[a])
        .unwrap();
    drop(store);
    Connection::open(&db)
        .unwrap()
        .execute_batch("DELETE FROM revision WHERE item_id = 'A' AND rev_n = 1;")
        .unwrap();
    let error = Store::open(&db, &sequence)
        .unwrap()
        .unlock("hunter2!", &secret)
        .err()
        .unwrap();
    assert!(error.0.contains("integrity check"), "{}", error.0);
}
