use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use vp_core::Failure;
use vp_core::backend::Backend;
use vp_core::model::{Destination, Field, Item, PasswordRequest, Scope, UrlEntry, VaultRef};
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;
use vp_crypto::KdfParams;
use vp_native::{NativeBackend, Paths, Presence, Unlock};

const CHEAP: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 1,
    p: 1,
};
const PASSWORD: &str = "correct horse battery";
const SENTINEL: &str = "sentinel-secret-9f3a";

/// Answers the unlock prompt from a script, and counts how often it was asked.
#[derive(Clone)]
struct Scripted {
    answers: Arc<Vec<Option<&'static str>>>,
    asked: Arc<AtomicUsize>,
    presence: Arc<Mutex<Vec<Presence>>>,
    checked: Arc<AtomicUsize>,
}

impl Scripted {
    fn new(answers: Vec<Option<&'static str>>) -> Self {
        Self {
            answers: Arc::new(answers),
            asked: Arc::new(AtomicUsize::new(0)),
            presence: Arc::new(Mutex::new(Vec::new())),
            checked: Arc::new(AtomicUsize::new(0)),
        }
    }
    /// The presence checks' answers, in order.
    fn presence(self, answers: Vec<Presence>) -> Self {
        *self.presence.lock().unwrap() = answers.into_iter().rev().collect();
        self
    }
    fn checked(&self) -> usize {
        self.checked.load(Ordering::SeqCst)
    }
    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Unlock for Scripted {
    async fn password(
        &self,
        _retry: bool,
        _purpose: Option<&str>,
    ) -> Result<Option<Secret>, Failure> {
        let n = self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .get(n)
            .copied()
            .flatten()
            .map(|p| Secret::new(p.into())))
    }

    async fn confirm_presence(&self) -> Presence {
        self.checked.fetch_add(1, Ordering::SeqCst);
        self.presence
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(Presence::Unavailable)
    }
}

fn paths(dir: &tempfile::TempDir) -> Paths {
    Paths {
        vault: dir.path().join("data/vault.vpdb"),
        secret_key: dir.path().join("data/secret-key"),
        sequence: dir.path().join("state/sequence"),
        settings: dir.path().join("state/vault-settings.json"),
    }
}

fn field(id: &str, kind: &str, purpose: Option<&str>, value: &str) -> Field {
    Field {
        id: id.into(),
        label: Some(id.into()),
        kind: kind.into(),
        purpose: purpose.map(String::from),
        section: None,
        value: Some(Secret::new(value.into())),
        reference: None,
    }
}

fn login(id: &str, title: &str, vault: &VaultRef, password: &str) -> Item {
    Item {
        id: id.into(),
        title: title.into(),
        category: "LOGIN".into(),
        vault: vault.clone(),
        tags: vec![],
        urls: vec![UrlEntry {
            href: "https://example.com".into(),
            label: None,
            primary: true,
        }],
        favorite: false,
        created_at: None,
        updated_at: None,
        sections: vec![],
        fields: vec![
            field("username", "STRING", Some("USERNAME"), "robert"),
            field("password", "CONCEALED", Some("PASSWORD"), password),
        ],
    }
}

fn private() -> VaultRef {
    VaultRef {
        id: "ces2xceuothnen6nav4z67rwjq".into(),
        name: "Private".into(),
    }
}

async fn created(dir: &tempfile::TempDir) -> NativeBackend<Scripted> {
    let backend = NativeBackend::with_params(paths(dir), Scripted::new(vec![]), CHEAP);
    let shown = backend.init(Secret::new(PASSWORD.into())).await.unwrap();
    assert!(shown.starts_with("VP1-"));
    let item = login(
        "o2kmam7av67ewmcgxllw2t7dda",
        "Example",
        &private(),
        SENTINEL,
    );
    assert_eq!(
        backend.import(&private(), vec![item]).await.unwrap(),
        (1, 0)
    );
    backend
}

#[tokio::test]
async fn imported_items_keep_their_ids_so_op_references_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let refs = [
        "op://ces2xceuothnen6nav4z67rwjq/o2kmam7av67ewmcgxllw2t7dda/password",
        "op://Private/Example/password",
        "op://private/Example/username",
    ]
    .map(|r| SecretRef::parse(r).unwrap());
    let values = backend.resolve(&refs).await.unwrap();
    assert_eq!(values[0].expose(), SENTINEL);
    assert_eq!(values[1].expose(), SENTINEL);
    assert_eq!(values[2].expose(), "robert");
    assert!(
        backend
            .resolve(&[SecretRef::parse("op://Private/Nope/password").unwrap()])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn listing_and_details_never_carry_values() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let listed = backend.list(&Scope::default()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].summary.additional_information.as_deref(),
        Some("robert")
    );
    let details = backend.details(&listed, &Scope::default()).await.unwrap();
    let json = serde_json::to_string(&details).unwrap();
    assert!(!json.contains(SENTINEL));
    assert!(json.contains("op://ces2xceuothnen6nav4z67rwjq/o2kmam7av67ewmcgxllw2t7dda/password"));
}

#[tokio::test]
async fn a_new_process_asks_for_the_password_once_and_retries_a_wrong_one() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock = Scripted::new(vec![Some("wrong password!"), Some(PASSWORD)]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);
    assert!(!backend.is_unlocked());
    assert_eq!(backend.list(&Scope::default()).await.unwrap().len(), 1);
    assert_eq!(unlock.asked(), 2);
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!(unlock.asked(), 2, "stays unlocked");
    backend.lock();
    let failed = backend.list(&Scope::default()).await.unwrap_err();
    assert!(failed.0.contains("cancelled"), "{}", failed.0);
}

#[tokio::test]
async fn three_wrong_passwords_keep_it_locked() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock = Scripted::new(vec![
        Some("a wrong one"),
        Some("another one"),
        Some("third wrong"),
        Some(PASSWORD),
    ]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);
    let error = backend.list(&Scope::default()).await.unwrap_err();
    assert!(error.0.contains("Wrong master password"));
    assert_eq!(unlock.asked(), 3);
}

#[tokio::test]
async fn saves_are_verified_and_keep_history() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let mut item = backend.item("Example", "Private").await.unwrap();
    item.fields[1].value = Some(Secret::new("new password".into()));
    let saved = backend.save_item(&item).await.unwrap();
    assert_eq!(
        saved.fields[1].value.as_ref().unwrap().expose(),
        "new password"
    );

    let mut fresh = login("", "Fresh", &private(), "pw");
    fresh.id.clear();
    let created = backend.save_item(&fresh).await.unwrap();
    assert_eq!(created.id.len(), 26);
    assert!(created.created_at.is_some());
    assert_eq!(backend.list(&Scope::default()).await.unwrap().len(), 2);
}

#[tokio::test]
async fn api_credentials_get_a_reference_and_titles_stay_unique() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let destination = Destination {
        title: "Stripe Test Key".into(),
        vault: "Private".into(),
        account: None,
        url: None,
        notes: None,
    };
    let receipt = backend
        .create_api_credential(&destination, Secret::new(SENTINEL.into()))
        .await
        .unwrap();
    assert!(receipt.verified);
    let value = backend
        .resolve(&[SecretRef::parse(&receipt.reference).unwrap()])
        .await
        .unwrap();
    assert_eq!(value[0].expose(), SENTINEL);
    assert!(
        backend
            .create_api_credential(&destination, Secret::new("x".into()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn password_compare_and_apply() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let mut request = PasswordRequest {
        item: "Example".into(),
        vault: "Private".into(),
        account: None,
        apply: false,
        repair_imported_fields: false,
    };
    let compared = backend
        .password(&request, Secret::new(SENTINEL.into()))
        .await
        .unwrap();
    assert_eq!(compared.matches, Some(true));
    request.apply = true;
    let applied = backend
        .password(&request, Secret::new("rotated!".into()))
        .await
        .unwrap();
    assert_eq!(
        (applied.changed, applied.verified),
        (Some(true), Some(true))
    );
    let value = backend
        .resolve(&[SecretRef::parse("op://Private/Example/password").unwrap()])
        .await
        .unwrap();
    assert_eq!(value[0].expose(), "rotated!");
}

#[tokio::test]
async fn archiving_hides_and_importing_twice_skips() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    let again = login(
        "o2kmam7av67ewmcgxllw2t7dda",
        "Example",
        &private(),
        "different",
    );
    assert_eq!(
        backend.import(&private(), vec![again]).await.unwrap(),
        (0, 1)
    );
    let value = backend
        .resolve(&[SecretRef::parse("op://Private/Example/password").unwrap()])
        .await
        .unwrap();
    assert_eq!(value[0].expose(), SENTINEL, "an import never overwrites");
    backend.archive("Example", "Private").await.unwrap();
    assert!(backend.list(&Scope::default()).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_vault_file_holds_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    drop(backend);
    let bytes = std::fs::read(paths(&dir).vault).unwrap();
    for needle in [SENTINEL, "Example", "robert", "Private", "example.com"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} is in the vault file"
        );
    }
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(paths(&dir).secret_key)
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn init_refuses_an_existing_vault_and_short_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let backend = created(&dir).await;
    assert!(backend.init(Secret::new(PASSWORD.into())).await.is_err());
    let other = tempfile::tempdir().unwrap();
    let fresh = NativeBackend::with_params(paths(&other), Scripted::new(vec![]), CHEAP);
    assert!(fresh.init(Secret::new("short".into())).await.is_err());
    let nothing = fresh.list(&Scope::default()).await.unwrap_err();
    assert!(nothing.0.contains("vp init"));
}

const HOURS_8: Duration = Duration::from_secs(8 * 3600);

#[tokio::test]
async fn without_quick_unlock_every_lock_needs_the_master_password() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock =
        Scripted::new(vec![Some(PASSWORD), Some(PASSWORD)]).presence(vec![Presence::Confirmed]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);
    backend.list(&Scope::default()).await.unwrap();
    backend.lock();
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!((unlock.asked(), unlock.checked()), (2, 0));
    assert_eq!(backend.quick_unlock(), None);
}

#[tokio::test]
async fn quick_unlock_keeps_the_account_key_through_a_lock_but_not_a_full_one() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock = Scripted::new(vec![Some(PASSWORD), Some(PASSWORD)])
        .presence(vec![Presence::Confirmed, Presence::Confirmed]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);

    backend.set_quick_unlock(Some(HOURS_8)).await.unwrap();
    assert_eq!(unlock.asked(), 1, "turning it on takes the master password");
    let status = backend.quick_unlock().unwrap();
    assert_eq!(status.window, HOURS_8);
    assert!(status.remaining.unwrap() > Duration::from_secs(7 * 3600));

    backend.lock();
    assert!(!backend.is_unlocked());
    assert_eq!(backend.list(&Scope::default()).await.unwrap().len(), 1);
    assert_eq!(
        (unlock.asked(), unlock.checked()),
        (1, 1),
        "presence, not password"
    );

    backend.lock_fully();
    assert_eq!(backend.quick_unlock().unwrap().remaining, None);
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!(
        (unlock.asked(), unlock.checked()),
        (2, 1),
        "a full lock ends the window"
    );
}

#[tokio::test]
async fn a_dismissed_check_cancels_and_an_unavailable_one_asks_for_the_password() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock = Scripted::new(vec![Some(PASSWORD), Some(PASSWORD)]).presence(vec![
        Presence::Dismissed,
        Presence::Confirmed,
        Presence::Unavailable,
    ]);
    let backend = NativeBackend::with_quiet_after_cancel(
        paths(&dir),
        unlock.clone(),
        CHEAP,
        Duration::from_millis(200),
    );
    backend.set_quick_unlock(Some(HOURS_8)).await.unwrap();
    backend.lock();

    let error = backend.list(&Scope::default()).await.unwrap_err();
    assert!(error.0.contains("cancelled"), "{}", error.0);
    let quiet = backend.list(&Scope::default()).await.unwrap_err();
    assert!(quiet.0.contains("just cancelled"), "{}", quiet.0);
    assert_eq!(
        unlock.checked(),
        1,
        "no second prompt straight after a cancel"
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!(
        (unlock.asked(), unlock.checked()),
        (1, 2),
        "dismissing kept the key"
    );

    backend.lock();
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!((unlock.asked(), unlock.checked()), (2, 3));
}

#[tokio::test]
async fn the_setting_survives_a_restart_and_turns_off() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let backend =
        NativeBackend::with_params(paths(&dir), Scripted::new(vec![Some(PASSWORD)]), CHEAP);
    assert!(
        backend
            .set_quick_unlock(Some(Duration::from_secs(25 * 3600)))
            .await
            .is_err()
    );
    backend.set_quick_unlock(Some(HOURS_8)).await.unwrap();
    drop(backend);

    let unlock = Scripted::new(vec![Some(PASSWORD)]).presence(vec![Presence::Confirmed]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);
    let status = backend.quick_unlock().unwrap();
    assert_eq!((status.window, status.remaining), (HOURS_8, None));
    backend.list(&Scope::default()).await.unwrap();
    assert_eq!(
        (unlock.asked(), unlock.checked()),
        (1, 0),
        "a restarted daemon has no key to keep, so the window starts with the password"
    );

    backend.set_quick_unlock(None).await.unwrap();
    drop(backend);
    let backend = NativeBackend::with_params(paths(&dir), Scripted::new(vec![]), CHEAP);
    assert_eq!(backend.quick_unlock(), None);
}

#[tokio::test]
async fn a_cancelled_password_leaves_quick_unlock_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let backend = NativeBackend::with_params(paths(&dir), Scripted::new(vec![None]), CHEAP);
    assert!(backend.set_quick_unlock(Some(HOURS_8)).await.is_err());
    assert_eq!(backend.quick_unlock(), None);
    assert!(!paths(&dir).settings.exists());
}

#[tokio::test]
async fn requests_waiting_on_a_cancelled_unlock_do_not_each_prompt() {
    let dir = tempfile::tempdir().unwrap();
    drop(created(&dir).await);
    let unlock = Scripted::new(vec![None, Some(PASSWORD)]);
    let backend = NativeBackend::with_params(paths(&dir), unlock.clone(), CHEAP);
    let waiting: Vec<_> = (0..5)
        .map(|_| {
            let backend = backend.clone();
            tokio::spawn(async move { backend.list(&Scope::default()).await })
        })
        .collect();
    for request in waiting {
        assert!(request.await.unwrap().is_err());
    }
    assert_eq!(unlock.asked(), 1, "one prompt, not five");
}
