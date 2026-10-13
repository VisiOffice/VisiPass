use rusqlite::Connection;
use std::path::PathBuf;
use vp_crypto::{KdfParams, SecretKey};
use vp_store::Store;

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
        store
            .put_item(&mut unlocked, "V1", "A", b"overview a1", b"secret a1")
            .unwrap();
        store
            .put_item(&mut unlocked, "V1", "B", b"overview b1", b"secret b1")
            .unwrap();
        assert_eq!(
            store
                .put_item(&mut unlocked, "V1", "A", b"overview a2", b"secret a2")
                .unwrap(),
            2
        );
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
    assert_eq!(overviews[0].version, 2);
    assert_eq!(&*store.details(&unlocked, "V1", "A").unwrap(), b"secret a2");
    assert_eq!(&*store.details(&unlocked, "V1", "B").unwrap(), b"secret b1");
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
    // Put A's version-1 details back as current: a valid ciphertext, but rolled back.
    f.sql(
        "UPDATE item SET item_version = 1, details = (SELECT details FROM history WHERE item_id = 'A' AND item_version = 1) WHERE item_id = 'A';",
    );
    assert!(f.unlock_error().contains("integrity check"));
}

#[test]
fn swapping_ciphertexts_between_items_is_detected() {
    let f = Fixture::new();
    f.populated();
    let store = f.store();
    let unlocked = store.unlock("hunter2!", &f.secret()).unwrap();
    // While unlocked: B's row now carries A's details.
    f.sql("UPDATE item SET details = (SELECT details FROM item WHERE item_id = 'A') WHERE item_id = 'B';");
    assert!(
        store
            .details(&unlocked, "V1", "B")
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
    f.sql("DELETE FROM item WHERE item_id = 'B';");
    assert!(f.unlock_error().contains("integrity check"));

    let g = Fixture::new();
    g.populated();
    g.sql("DELETE FROM history;");
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
        .put_item(&mut unlocked, "V1", "A", b"o", b"d")
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

    f.sql("DELETE FROM item WHERE item_id = 'B'");
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
