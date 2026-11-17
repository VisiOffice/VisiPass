//! Phone approvals end to end: a software phone (standing in for the Secure
//! Enclave keys) pairs and answers over HTTP on the loopback listener, while
//! a scripted desktop approver answers, fails or never answers.

use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use p256::ecdsa::signature::Signer;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_core::Failure;
use vp_core::ipc::{PasteMode, PasteSpec};
use vp_core::secret::Secret;
use vp_daemon::approval::{Approver, Prompt};
use vp_daemon::grants::Decision;
use vp_daemon::phones::{BoxFuture, PairingStore, Phones, WithPhones};
use vp_phone::*;
use zeroize::Zeroizing;

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

// ---- The vault and the desktop -------------------------------------------------

#[derive(Clone, Default)]
struct Vault {
    phones: Arc<Mutex<BTreeMap<PairingId, Vec<u8>>>>,
    locked: Arc<Mutex<bool>>,
    /// The phones, for unlocking as the native vault does.
    unlocking: Arc<std::sync::OnceLock<Arc<Phones>>>,
    /// The key a phone gave back.
    unlocked_with: Arc<Mutex<Option<[u8; 32]>>>,
}

impl PairingStore for Vault {
    fn phones(&self) -> Result<Option<vp_daemon::phones::PhoneRecords>, Failure> {
        if *self.locked.lock().unwrap() {
            return Ok(None);
        }
        Ok(Some(
            self.phones
                .lock()
                .unwrap()
                .iter()
                .map(|(id, r)| (*id, Zeroizing::new(r.clone())))
                .collect(),
        ))
    }

    fn set_phone(&self, id: &PairingId, record: Option<&[u8]>) -> Result<bool, Failure> {
        let mut phones = self.phones.lock().unwrap();
        Ok(match record {
            Some(r) => phones.insert(*id, r.to_vec()).is_some(),
            None => phones.remove(id).is_some(),
        })
    }

    fn relay_secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        (!*self.locked.lock().unwrap()).then(|| Zeroizing::new([0x11; 32]))
    }

    fn confirm_password(&self, password: Secret) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if password.expose() == "hunter2!" {
                Ok(())
            } else {
                Err(Failure::new("Wrong master password"))
            }
        })
    }

    /// The phones only; nobody types the master password here.
    fn unlock(&self) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if !*self.locked.lock().unwrap() {
                return Ok(());
            }
            let phones = self.unlocking.get().unwrap().clone();
            match phones.phone_unlock(None).await {
                vp_native::PhoneUnlock::Key(key) => {
                    *self.unlocked_with.lock().unwrap() = Some(*key);
                    *self.locked.lock().unwrap() = false;
                    Ok(())
                }
                vp_native::PhoneUnlock::Denied => Err(Failure::new("denied on the phone")),
                vp_native::PhoneUnlock::NoAnswer => Err(Failure::new("nobody answered")),
            }
        })
    }
}

#[derive(Clone)]
enum Desk {
    /// Nobody at the computer.
    Never,
    /// Answers after a while.
    After(Duration, Decision),
    /// No desktop to ask at all.
    Fails,
}

#[derive(Clone)]
struct Desktop {
    mode: Desk,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Desktop {
    fn new(mode: Desk) -> Self {
        Self {
            mode,
            asked: Arc::default(),
        }
    }

    async fn wait(&self) -> Result<Decision, Failure> {
        match &self.mode {
            Desk::Never => std::future::pending().await,
            Desk::After(after, decision) => {
                tokio::time::sleep(*after).await;
                Ok(*decision)
            }
            Desk::Fails => Err(Failure::new("no desktop session")),
        }
    }
}

impl Approver for Desktop {
    fn method(&self) -> &'static str {
        "test"
    }

    async fn ask(&self, prompt: &Prompt) -> Result<Decision, Failure> {
        self.asked.lock().unwrap().push(prompt.action.clone());
        self.wait().await
    }

    async fn paste(&self, prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        self.asked.lock().unwrap().push(prompt.action.clone());
        self.wait()
            .await
            .map(|d| (d != Decision::Deny).then(|| Secret::new("from the desktop".into())))
    }
}

// ---- The phone --------------------------------------------------------------

struct SoftPhone {
    sign: p256::ecdsa::SigningKey,
    kem: <Kem as hpke::Kem>::PrivateKey,
    n_p: [u8; 32],
    name: String,
}

impl SoftPhone {
    fn new(name: &str) -> Self {
        Self {
            sign: p256::ecdsa::SigningKey::from_slice(&vp_crypto::random::<32>()).unwrap(),
            kem: Kem::derive_keypair(&vp_crypto::random::<32>()).0,
            n_p: vp_crypto::random(),
            name: name.into(),
        }
    }

    fn sign_p(&self) -> PublicKey {
        self.sign
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn kem_p(&self) -> PublicKey {
        Kem::sk_to_pk(&self.kem)
            .to_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = self.sign.sign(message);
        signature.to_bytes().into()
    }

    fn commit(&self, invite: &Invite) -> Commit {
        Commit::new(
            invite,
            commitment(&invite.pairing_id, &self.sign_p(), &self.kem_p(), &self.n_p),
        )
    }

    fn body(&self) -> Phone {
        Phone {
            name: self.name.clone(),
            sign_p: self.sign_p(),
            kem_p: self.kem_p(),
            n_p: self.n_p,
            push_token: vec![],
        }
    }

    fn reveal(&self, invite: &Invite) -> Reveal {
        let body = self.body().encode();
        Reveal {
            pairing_id: invite.pairing_id,
            sealed: Reveal::seal(invite, &body).unwrap(),
            signature: self.sign(&Phone::signed_bytes(&invite.pairing_id, &body)),
        }
    }

    /// Scans, commits and reveals; returns the code it shows.
    async fn pair(&self, port: u16, invite: &Invite) -> String {
        let (status, nonce) = http(
            port,
            "POST",
            "/v1/pair/commit",
            &self.commit(invite).encode(),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&nonce));
        let nonce = Nonce::decode(&nonce).unwrap();
        let (status, _) = http(
            port,
            "POST",
            "/v1/pair/reveal",
            &self.reveal(invite).encode(),
        )
        .await;
        assert_eq!(status, 200);
        pairing_code(&invite.pairing_id, &invite.kem_d, &self.body(), &nonce.n_d)
    }

    /// Fetches what is waiting, and opens it as CryptoKit would.
    async fn pending(&self, port: u16, invite: &Invite) -> Vec<(Request, Vec<u8>)> {
        let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
        let (status, body) = http(port, "GET", &path, &[]).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        decode_pending(&body)
            .unwrap()
            .iter()
            .map(|sealed| {
                let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.sealed.enc).unwrap();
                let sender = <Kem as hpke::Kem>::PublicKey::from_bytes(&invite.kem_d).unwrap();
                let body = hpke::single_shot_open::<Aead, Kdf, Kem>(
                    &OpModeR::Auth(sender),
                    &self.kem,
                    &enc,
                    &Request::info(&sealed.pairing_id),
                    &sealed.sealed.ciphertext,
                    &[],
                )
                .unwrap();
                (Request::decode(&body).unwrap(), body)
            })
            .collect()
    }

    fn answer(
        &self,
        invite: &Invite,
        request: &Request,
        body: &[u8],
        choice: Choice,
        value: Option<&[u8]>,
    ) -> Vec<u8> {
        let hash = Request::hash(body);
        let answer = Answer {
            request_id: request.request_id,
            request_hash: hash,
            choice,
            value: value
                .map(|v| Answer::seal_value(&invite.kem_d, &invite.pairing_id, &hash, v).unwrap()),
        }
        .encode();
        SignedAnswer {
            pairing_id: invite.pairing_id,
            signature: self.sign(&Answer::signed_bytes(&invite.pairing_id, &answer)),
            answer,
        }
        .encode()
    }
}

async fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: phone.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    raw_reply(stream).await
}

async fn raw_reply(mut stream: tokio::net::TcpStream) -> (u16, Vec<u8>) {
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let split = reply.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&reply[..split]).to_string();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, reply[split + 4..].to_vec())
}

// ---- Fixtures ------------------------------------------------------------------

struct Setup {
    vault: Vault,
    phones: Arc<Phones>,
    port: u16,
}

async fn setup() -> Setup {
    let vault = Vault::default();
    let phones = Phones::new(vault.clone(), 0);
    let _ = vault.unlocking.set(phones.clone());
    let port = phones.listen().await.unwrap();
    Setup {
        vault,
        phones,
        port,
    }
}

/// A phone paired through the real flow.
async fn paired(s: &Setup, name: &str) -> (SoftPhone, Invite) {
    let invite = s
        .phones
        .open_window("https://desk.tail1234.ts.net".into(), "desk".into());
    let phone = SoftPhone::new(name);
    let shown = phone.pair(s.port, &invite).await;
    let (revealed, code) = s.phones.revealed(&invite.pairing_id).await.unwrap();
    assert_eq!(code, shown);
    s.phones.keep(&invite.pairing_id, &revealed).unwrap();
    (phone, invite)
}

fn prompt() -> Prompt {
    Prompt {
        who: "Claude Code".into(),
        action: "inject 1 secret into a command".into(),
        details: vec![("Project".into(), "~/Code/visipass".into())],
        secrets: vec!["vp://Dev/Stripe/secret key".into()],
        purpose: Some("Run the billing tests".into()),
        timeout_secs: 120,
        every_time: false,
        paste: None,
    }
}

fn paste_prompt(mode: PasteMode) -> Prompt {
    Prompt {
        paste: Some(PasteSpec {
            title: "Stripe".into(),
            vault: "Dev".into(),
            mode,
        }),
        ..prompt()
    }
}

/// Waits for the question to reach the phone.
async fn question(s: &Setup, phone: &SoftPhone, invite: &Invite) -> (Request, Vec<u8>) {
    for _ in 0..100 {
        if let Some(found) = phone.pending(s.port, invite).await.pop() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the phone was never asked");
}

// ---- Pairing ----------------------------------------------------------------------

#[tokio::test]
async fn pairing_records_the_phone_sealed_in_the_vault() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "Robert's iPhone").await;
    let pairings = s.phones.pairings().unwrap().unwrap();
    assert_eq!(pairings.len(), 1);
    assert_eq!(pairings[0].name, "Robert's iPhone");
    assert_eq!(pairings[0].sign_p, phone.sign_p());
    assert_eq!(pairings[0].kem_d.public(), invite.kem_d);
    // Paired, nothing waiting: the app can tell.
    assert!(phone.pending(s.port, &invite).await.is_empty());
    // The window is closed: the code works once.
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/commit",
        &phone.commit(&invite).encode(),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_second_device_with_the_code_cancels_pairing_on_both_screens() {
    let s = setup().await;
    let invite = s
        .phones
        .open_window("https://desk.tail1234.ts.net".into(), "desk".into());
    let phone = SoftPhone::new("mine");
    let agent = SoftPhone::new("the agent's");
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/commit",
        &phone.commit(&invite).encode(),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = http(
        s.port,
        "POST",
        "/v1/pair/commit",
        &agent.commit(&invite).encode(),
    )
    .await;
    assert_eq!(status, 409);
    assert!(String::from_utf8_lossy(&body).contains("Another device"));
    // The first phone is told the same.
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/reveal",
        &phone.reveal(&invite).encode(),
    )
    .await;
    assert_eq!(status, 409);
    let error = s.phones.revealed(&invite.pairing_id).await.unwrap_err();
    assert!(error.to_string().contains("Another device"));
    assert!(s.phones.pairings().unwrap().unwrap().is_empty());
}

#[tokio::test]
async fn a_commit_without_the_codes_secret_changes_nothing() {
    let s = setup().await;
    let invite = s
        .phones
        .open_window("https://desk.tail1234.ts.net".into(), "desk".into());
    let mut guess = invite.clone();
    guess.secret = Zeroizing::new([7; 32]);
    let stranger = SoftPhone::new("stranger");
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/commit",
        &stranger.commit(&guess).encode(),
    )
    .await;
    assert_eq!(status, 403);
    // The person's phone still pairs.
    let phone = SoftPhone::new("mine");
    let shown = phone.pair(s.port, &invite).await;
    let (_, code) = s.phones.revealed(&invite.pairing_id).await.unwrap();
    assert_eq!(shown, code);
}

#[tokio::test]
async fn a_reveal_of_other_keys_than_committed_is_refused() {
    let s = setup().await;
    let invite = s
        .phones
        .open_window("https://desk.tail1234.ts.net".into(), "desk".into());
    let phone = SoftPhone::new("mine");
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/commit",
        &phone.commit(&invite).encode(),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/pair/reveal",
        &SoftPhone::new("other").reveal(&invite).encode(),
    )
    .await;
    assert_eq!(status, 403);
}

// ---- Asking -------------------------------------------------------------------------

#[tokio::test]
async fn the_phone_answers_when_nobody_is_at_the_computer() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "Robert's iPhone").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.ask(&prompt()).await }
    });
    let (request, body) = question(&s, &phone, &invite).await;
    assert_eq!(request.prompt.who, "Claude Code");
    assert_eq!(
        request.choices,
        vec![Choice::Deny, Choice::Once, Choice::Task, Choice::Hours]
    );
    let answer = phone.answer(&invite, &request, &body, Choice::Task, None);
    let (status, _) = http(s.port, "POST", "/v1/answer", &answer).await;
    assert_eq!(status, 200);
    assert_eq!(asking.await.unwrap().unwrap(), Decision::Task);
    assert_eq!(approver.answered_by().as_deref(), Some("Robert's iPhone"));
    assert_eq!(approver.answered_by(), None);
    // Answered: gone from the phone, and a second answer is refused.
    assert!(phone.pending(s.port, &invite).await.is_empty());
    let (status, _) = http(s.port, "POST", "/v1/answer", &answer).await;
    assert_eq!(status, 410);
}

#[tokio::test]
async fn the_computer_answering_first_withdraws_the_phones_question() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let approver = WithPhones {
        desktop: Desktop::new(Desk::After(Duration::from_millis(300), Decision::Once)),
        phones: s.phones.clone(),
    };
    let asked = prompt();
    let (decision, (request, body)) =
        tokio::join!(approver.ask(&asked), question(&s, &phone, &invite));
    assert_eq!(decision.unwrap(), Decision::Once);
    assert_eq!(approver.answered_by(), None);
    assert!(phone.pending(s.port, &invite).await.is_empty());
    let late = phone.answer(&invite, &request, &body, Choice::Hours, None);
    let (status, _) = http(s.port, "POST", "/v1/answer", &late).await;
    assert_eq!(status, 410);
}

#[tokio::test]
async fn with_no_desktop_the_phone_still_decides() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Fails),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.ask(&prompt()).await }
    });
    let (request, body) = question(&s, &phone, &invite).await;
    // Give the desktop's failure time to land before the phone answers.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let answer = phone.answer(&invite, &request, &body, Choice::Deny, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &answer).await.0, 200);
    assert_eq!(asking.await.unwrap().unwrap(), Decision::Deny);
}

#[tokio::test]
async fn forged_or_mismatched_answers_count_as_no_answer() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.ask(&prompt()).await }
    });
    let (request, body) = question(&s, &phone, &invite).await;

    // Signed by another key: an agent on the computer, a node on the tailnet.
    let forger = SoftPhone::new("forger");
    let forged = forger.answer(&invite, &request, &body, Choice::Hours, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &forged).await.0, 403);
    // The phone's key, over other bytes than were sent.
    let mut edited = request.clone();
    edited.choices.push(Choice::Hours);
    let wrong = phone.answer(&invite, &request, &edited.encode(), Choice::Once, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &wrong).await.0, 422);
    // Garbage.
    assert_eq!(
        http(s.port, "POST", "/v1/answer", b"\x83\x01\x02\x03")
            .await
            .0,
        400
    );

    // None of that answered or denied: the real answer still wins.
    assert!(!asking.is_finished());
    let real = phone.answer(&invite, &request, &body, Choice::Once, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &real).await.0, 200);
    assert_eq!(asking.await.unwrap().unwrap(), Decision::Once);
}

#[tokio::test]
async fn every_paired_phone_is_asked_and_the_first_answer_wins() {
    let s = setup().await;
    let (first, first_invite) = paired(&s, "first").await;
    let (second, second_invite) = paired(&s, "second").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.ask(&prompt()).await }
    });
    let (r1, b1) = question(&s, &first, &first_invite).await;
    let (r2, b2) = question(&s, &second, &second_invite).await;
    assert_ne!(r1.request_id, r2.request_id);
    // One phone's answer is not good for the other's request.
    let crossed = first.answer(&first_invite, &r2, &b2, Choice::Once, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &crossed).await.0, 410);

    let answer = second.answer(&second_invite, &r2, &b2, Choice::Deny, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &answer).await.0, 200);
    assert_eq!(asking.await.unwrap().unwrap(), Decision::Deny);
    assert_eq!(approver.answered_by().as_deref(), Some("second"));
    let late = first.answer(&first_invite, &r1, &b1, Choice::Once, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &late).await.0, 410);
}

#[tokio::test]
async fn every_time_prompts_offer_only_once_and_never_always() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move {
            approver
                .ask(&Prompt {
                    every_time: true,
                    ..prompt()
                })
                .await
        }
    });
    let (request, body) = question(&s, &phone, &invite).await;
    assert_eq!(request.choices, vec![Choice::Deny, Choice::Once]);
    let task = phone.answer(&invite, &request, &body, Choice::Task, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &task).await.0, 422);
    let once = phone.answer(&invite, &request, &body, Choice::Once, None);
    assert_eq!(http(s.port, "POST", "/v1/answer", &once).await.0, 200);
    assert_eq!(asking.await.unwrap().unwrap(), Decision::Once);
}

#[tokio::test]
async fn a_new_secret_can_be_pasted_on_the_phone() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let approver = Arc::new(WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    });
    let asking = tokio::spawn({
        let approver = approver.clone();
        async move { approver.paste(&paste_prompt(PasteMode::Secret)).await }
    });
    let (request, body) = question(&s, &phone, &invite).await;
    assert_eq!(request.kind, Kind::Paste);
    assert_eq!(request.prompt.paste, Some(("Stripe".into(), "Dev".into())));
    let answer = phone.answer(
        &invite,
        &request,
        &body,
        Choice::Once,
        Some(b"sk_live_SENTINEL"),
    );
    assert_eq!(http(s.port, "POST", "/v1/answer", &answer).await.0, 200);
    let pasted = asking.await.unwrap().unwrap().unwrap();
    assert_eq!(pasted.expose(), "sk_live_SENTINEL");
}

#[tokio::test]
async fn phones_are_never_asked_to_unlock_or_to_pair() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let desktop = Desktop::new(Desk::After(Duration::from_millis(200), Decision::Once));
    let approver = WithPhones {
        desktop: desktop.clone(),
        phones: s.phones.clone(),
    };
    let unlock = PasteMode::Unlock {
        retry: false,
        purpose: None,
    };
    let unlock = paste_prompt(unlock);
    let (_, seen) = tokio::join!(approver.paste(&unlock), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        phone.pending(s.port, &invite).await
    });
    assert!(seen.is_empty());
    let asked = prompt();
    let (_, seen) = tokio::join!(approver.ask_at_computer(&asked), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        phone.pending(s.port, &invite).await
    });
    assert!(seen.is_empty());
    assert_eq!(desktop.asked.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_locked_vault_asks_no_phone() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    *s.vault.locked.lock().unwrap() = true;
    let approver = WithPhones {
        desktop: Desktop::new(Desk::After(Duration::from_millis(100), Decision::Deny)),
        phones: s.phones.clone(),
    };
    assert_eq!(approver.ask(&prompt()).await.unwrap(), Decision::Deny);
    let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
    let (status, body) = http(s.port, "GET", &path, &[]).await;
    assert_eq!(status, 423);
    assert!(String::from_utf8_lossy(&body).contains("unlock at the computer"));
    drop(phone);
}

#[tokio::test]
async fn a_removed_phone_is_no_longer_asked() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "Robert's iPhone").await;
    assert!(s.phones.remove("nobody").is_err());
    assert_eq!(
        s.phones.remove("robert's iphone").unwrap(),
        "Robert's iPhone"
    );
    assert!(s.vault.phones.lock().unwrap().is_empty());
    let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
    assert_eq!(http(s.port, "GET", &path, &[]).await.0, 404);
    drop(phone);
}

// ---- The listener -------------------------------------------------------------------

#[tokio::test]
async fn the_listener_takes_only_its_four_routes_and_bounded_bodies() {
    let s = setup().await;
    assert_eq!(http(s.port, "GET", "/", &[]).await.0, 404);
    assert_eq!(http(s.port, "GET", "/v1/pending/zz", &[]).await.0, 404);
    assert_eq!(http(s.port, "PUT", "/v1/answer", &[]).await.0, 404);
    // An unknown phone.
    let path = format!("/v1/pending/{}", "ab".repeat(16));
    assert_eq!(http(s.port, "GET", &path, &[]).await.0, 404);

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", s.port))
        .await
        .unwrap();
    stream
        .write_all(b"POST /v1/answer HTTP/1.1\r\nContent-Length: 999999\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(raw_reply(stream).await.0, 413);

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", s.port))
        .await
        .unwrap();
    stream
        .write_all(b"POST /v1/answer HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(raw_reply(stream).await.0, 411);

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", s.port))
        .await
        .unwrap();
    let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(20_000));
    stream.write_all(huge.as_bytes()).await.unwrap();
    assert_eq!(raw_reply(stream).await.0, 431);
}

#[tokio::test]
async fn a_phone_polling_too_fast_is_slowed() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
    let mut statuses = Vec::new();
    for _ in 0..125 {
        statuses.push(http(s.port, "GET", &path, &[]).await.0);
    }
    assert!(statuses[..120].iter().all(|s| *s == 200));
    assert_eq!(statuses[124], 429);
    drop(phone);
}

// ---- The relay ------------------------------------------------------------------

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// visipassd's connection as the relay sees it: the path and bearer it
/// connected with, and the socket.
struct Connected {
    path: String,
    bearer: String,
    socket: Socket,
    pushes: Vec<String>,
    next: u64,
}

impl Connected {
    /// A phone's request passed down; visipassd's reply. Pushes that arrive
    /// meanwhile are kept.
    async fn ask(&mut self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        self.next += 1;
        let down = serde_json::json!({
            "id": self.next, "method": method, "path": path, "body": STANDARD.encode(body),
        });
        self.socket
            .send(Message::Text(down.to_string().into()))
            .await
            .unwrap();
        loop {
            let up = self.frame().await;
            if let Some(push) = up["push"].as_str() {
                self.pushes.push(push.into());
                continue;
            }
            assert_eq!(up["id"], self.next);
            return (
                up["status"].as_u64().unwrap() as u16,
                STANDARD.decode(up["body"].as_str().unwrap()).unwrap(),
            );
        }
    }

    async fn frame(&mut self) -> serde_json::Value {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("visipassd said nothing")
                .unwrap()
                .unwrap();
            if let Message::Text(text) = message
                && text.as_str() != "ping"
            {
                return serde_json::from_str(text.as_str()).unwrap();
            }
        }
    }
}

/// A relay on loopback; each connection visipassd makes arrives on the channel.
#[allow(clippy::result_large_err)] // tungstenite's handshake callback type
async fn fake_relay() -> (String, tokio::sync::mpsc::UnboundedReceiver<Connected>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = Arc::new(Mutex::new((String::new(), String::new())));
            let record = seen.clone();
            let socket = tokio_tungstenite::accept_hdr_async(
                stream,
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      response| {
                    *record.lock().unwrap() = (
                        request.uri().path().to_string(),
                        request
                            .headers()
                            .get("authorization")
                            .map(|v| v.to_str().unwrap().to_string())
                            .unwrap_or_default(),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            let (path, bearer) = seen.lock().unwrap().clone();
            let _ = sender.send(Connected {
                path,
                bearer,
                socket,
                pushes: vec![],
                next: 0,
            });
        }
    });
    (url, receiver)
}

impl SoftPhone {
    fn push_token(&self, invite: &Invite, token: &[u8]) -> Vec<u8> {
        let kem_p = DaemonKey::from_bytes(&self.kem.to_bytes()).unwrap();
        PushToken::seal(&kem_p, &invite.kem_d, &invite.pairing_id, token)
            .unwrap()
            .encode()
    }
}

#[tokio::test]
async fn a_phone_pairs_and_answers_through_the_relay() {
    let (relay, mut connections) = fake_relay().await;
    let vault = Vault::default();
    let phones = Phones::with_relay(vault.clone(), 0, relay.clone());
    tokio::spawn(phones.clone().keep_tunnel());

    // No phone and no pairing: no tunnel.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), connections.recv())
            .await
            .is_err()
    );

    let endpoint = phones.relay_endpoint().unwrap();
    let tunnel = vp_daemon::phones::tunnel_id(&[0x11; 32]);
    assert_eq!(endpoint, format!("{relay}/t/{tunnel}"));
    let invite = phones.open_window(endpoint, "desk".into());
    let mut relay = connections.recv().await.unwrap();
    // It proves the secret the tunnel's id is the hash of.
    assert_eq!(relay.path, format!("/t/{tunnel}/connect"));
    assert_eq!(relay.bearer, format!("Bearer {}", "11".repeat(32)));
    assert!(phones.wait_for_tunnel(Duration::from_secs(1)).await);

    // Pairing, through the tunnel.
    let phone = SoftPhone::new("iPhone");
    let (status, nonce) = relay
        .ask("POST", "/v1/pair/commit", &phone.commit(&invite).encode())
        .await;
    assert_eq!(status, 200);
    let nonce = Nonce::decode(&nonce).unwrap();
    let (status, _) = relay
        .ask("POST", "/v1/pair/reveal", &phone.reveal(&invite).encode())
        .await;
    assert_eq!(status, 200);
    let (revealed, code) = phones.revealed(&invite.pairing_id).await.unwrap();
    assert_eq!(
        code,
        pairing_code(&invite.pairing_id, &invite.kem_d, &phone.body(), &nonce.n_d)
    );
    phones.keep(&invite.pairing_id, &revealed).unwrap();

    // The phone's device token, kept in the sealed record.
    let token = [0x5a; 32];
    let (status, _) = relay
        .ask("POST", "/v1/push", &phone.push_token(&invite, &token))
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        phones.pairings().unwrap().unwrap()[0].push_token,
        token.to_vec()
    );

    // A request: the relay is asked to notify that token, and nothing else.
    let desktop = Desktop::new(Desk::Never);
    let approver = WithPhones {
        desktop,
        phones: phones.clone(),
    };
    let asking = tokio::spawn(async move {
        let decision = approver.ask(&prompt()).await;
        (decision, approver.answered_by())
    });
    let push = relay.frame().await;
    assert_eq!(push, serde_json::json!({ "push": "5a".repeat(32) }));

    let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
    let (status, body) = relay.ask("GET", &path, &[]).await;
    assert_eq!(status, 200);
    let sealed = decode_pending(&body).unwrap().pop().unwrap();
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.sealed.enc).unwrap();
    let sender = <Kem as hpke::Kem>::PublicKey::from_bytes(&invite.kem_d).unwrap();
    let body = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Auth(sender),
        &phone.kem,
        &enc,
        &Request::info(&sealed.pairing_id),
        &sealed.sealed.ciphertext,
        &[],
    )
    .unwrap();
    let request = Request::decode(&body).unwrap();
    let answer = phone.answer(&invite, &request, &body, Choice::Once, None);
    assert_eq!(relay.ask("POST", "/v1/answer", &answer).await.0, 200);
    let (decision, by) = asking.await.unwrap();
    assert_eq!(decision.unwrap(), Decision::Once);
    assert_eq!(by.as_deref(), Some("iPhone"));

    // The relay is held to the same routes as the loopback port.
    assert_eq!(relay.ask("GET", "/", &[]).await.0, 404);
    assert_eq!(relay.ask("DELETE", "/v1/answer", &[]).await.0, 404);
}

#[tokio::test]
async fn only_the_paired_phone_sets_its_push_token() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let stranger = SoftPhone::new("stranger");
    let (status, _) = http(
        s.port,
        "POST",
        "/v1/push",
        &stranger.push_token(&invite, &[1; 32]),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        s.phones.pairings().unwrap().unwrap()[0]
            .push_token
            .is_empty()
    );

    assert_eq!(
        http(
            s.port,
            "POST",
            "/v1/push",
            &phone.push_token(&invite, &[2; 32])
        )
        .await
        .0,
        200
    );
    assert_eq!(
        s.phones.pairings().unwrap().unwrap()[0].push_token,
        vec![2; 32]
    );
    // Not paired here.
    let other = Invite::new(
        "https://desk.tail1234.ts.net".into(),
        "desk".into(),
        invite.kem_d,
    );
    assert_eq!(
        http(
            s.port,
            "POST",
            "/v1/push",
            &phone.push_token(&other, &[3; 32])
        )
        .await
        .0,
        404
    );
    assert_eq!(http(s.port, "POST", "/v1/push", b"junk").await.0, 400);
}

// ---- Unlocking from the phone ------------------------------------------------------

impl SoftPhone {
    /// Fetches an unlock request and opens it as the app would: `Held` from
    /// this pairing's daemon first, then the request from the `kem_L` it names.
    async fn pending_unlock(&self, port: u16, invite: &Invite) -> Option<(Request, Vec<u8>, Held)> {
        let path = format!("/v1/pending/{}", vp_daemon::phones::hex(&invite.pairing_id));
        let (status, body) = http(port, "GET", &path, &[]).await;
        if status != 200 {
            return None;
        }
        let sealed = decode_pending(&body).unwrap().pop()?;
        let kem = DaemonKey::from_bytes(&self.kem.to_bytes()).unwrap();
        let held = Held::open(
            sealed.held.as_ref().unwrap(),
            &kem,
            &invite.kem_d,
            &invite.pairing_id,
        )
        .unwrap();
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.sealed.enc).unwrap();
        let sender = <Kem as hpke::Kem>::PublicKey::from_bytes(&held.kem_l).unwrap();
        let body = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Auth(sender),
            &self.kem,
            &enc,
            &Request::info(&sealed.pairing_id),
            &sealed.sealed.ciphertext,
            &[],
        )
        .unwrap();
        Some((Request::decode(&body).unwrap(), body, held))
    }

    fn answer_unlock(
        &self,
        invite: &Invite,
        request: &Request,
        body: &[u8],
        choice: Choice,
        held: &Held,
    ) -> Vec<u8> {
        let hash = Request::hash(body);
        let answer = Answer {
            request_id: request.request_id,
            request_hash: hash,
            choice,
            value: (choice != Choice::Deny).then(|| {
                Answer::seal_key(&held.kem_l, &invite.pairing_id, &hash, &held.key).unwrap()
            }),
        }
        .encode();
        SignedAnswer {
            pairing_id: invite.pairing_id,
            signature: self.sign(&Answer::signed_bytes(&invite.pairing_id, &answer)),
            answer,
        }
        .encode()
    }
}

/// Locks the vault as the native vault does with phone unlock on: `K` to the
/// phones, then the records are out of reach. Returns `K`.
fn lock_with_handoff(s: &Setup, until: u64) -> [u8; 32] {
    let key = vp_crypto::random::<32>();
    let records = s.vault.phones().unwrap().unwrap();
    let handed = s.phones.hand_off(vp_native::Handoff {
        key: &key,
        lock_id: [3; 16],
        until,
        phones: &records,
        relay_secret: Zeroizing::new([0x11; 32]),
    });
    assert!(handed);
    *s.vault.locked.lock().unwrap() = true;
    key
}

async fn unlock_question(
    s: &Setup,
    phone: &SoftPhone,
    invite: &Invite,
) -> (Request, Vec<u8>, Held) {
    for _ in 0..100 {
        if let Some(found) = phone.pending_unlock(s.port, invite).await {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the phone was never asked to unlock");
}

#[tokio::test]
async fn one_answer_on_the_phone_unlocks_and_approves() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "Robert's iPhone").await;
    let key = lock_with_handoff(&s, vp_daemon::phones::now() + 3600);
    let approver = WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    };
    let asked = prompt();
    let (decision, ()) = tokio::join!(approver.ask(&asked), async {
        let (request, body, held) = unlock_question(&s, &phone, &invite).await;
        assert_eq!(request.kind, Kind::Unlock);
        assert_eq!(request.prompt.action, "inject 1 secret into a command");
        assert_eq!(*held.key, key);
        let reply = http(
            s.port,
            "POST",
            "/v1/answer",
            &phone.answer_unlock(&invite, &request, &body, Choice::Task, &held),
        )
        .await;
        assert_eq!(reply.0, 200, "{}", String::from_utf8_lossy(&reply.1));
    });
    assert_eq!(decision.unwrap(), Decision::Task);
    assert_eq!(*s.vault.unlocked_with.lock().unwrap(), Some(key));
    assert!(!*s.vault.locked.lock().unwrap());
    assert_eq!(approver.answered_by().as_deref(), Some("Robert's iPhone"));
}

#[tokio::test]
async fn denying_on_the_phone_keeps_the_vault_locked() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    lock_with_handoff(&s, vp_daemon::phones::now() + 3600);
    let approver = WithPhones {
        desktop: Desktop::new(Desk::Never),
        phones: s.phones.clone(),
    };
    let asked = prompt();
    let (decision, ()) = tokio::join!(approver.ask(&asked), async {
        let (request, body, held) = unlock_question(&s, &phone, &invite).await;
        let reply = http(
            s.port,
            "POST",
            "/v1/answer",
            &phone.answer_unlock(&invite, &request, &body, Choice::Deny, &held),
        )
        .await;
        assert_eq!(reply.0, 200);
    });
    assert_eq!(decision.unwrap(), Decision::Deny);
    assert!(*s.vault.locked.lock().unwrap());
    assert!(s.vault.unlocked_with.lock().unwrap().is_none());
}

#[tokio::test]
async fn an_unlock_answer_without_the_key_or_from_another_phone_counts_as_none() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    lock_with_handoff(&s, vp_daemon::phones::now() + 3600);
    let unlocking = tokio::spawn({
        let phones = s.phones.clone();
        async move { phones.phone_unlock(Some("unlock your vault".into())).await }
    });
    let (request, body, held) = unlock_question(&s, &phone, &invite).await;
    assert_eq!(request.choices, vec![Choice::Deny, Choice::Once]);

    // "Once" with no key.
    let hash = Request::hash(&body);
    let keyless = Answer {
        request_id: request.request_id,
        request_hash: hash,
        choice: Choice::Once,
        value: None,
    }
    .encode();
    let keyless = SignedAnswer {
        pairing_id: invite.pairing_id,
        signature: phone.sign(&Answer::signed_bytes(&invite.pairing_id, &keyless)),
        answer: keyless,
    };
    assert_eq!(
        http(s.port, "POST", "/v1/answer", &keyless.encode())
            .await
            .0,
        422
    );
    // Signed by another phone.
    let impostor = SoftPhone::new("impostor");
    let forged = impostor.answer_unlock(&invite, &request, &body, Choice::Once, &held);
    assert_eq!(http(s.port, "POST", "/v1/answer", &forged).await.0, 403);

    let good = phone.answer_unlock(&invite, &request, &body, Choice::Once, &held);
    assert_eq!(http(s.port, "POST", "/v1/answer", &good).await.0, 200);
    assert!(matches!(
        unlocking.await.unwrap(),
        vp_native::PhoneUnlock::Key(key) if *key == *held.key
    ));
}

#[tokio::test]
async fn after_its_days_the_phone_is_not_asked_to_unlock() {
    let s = setup().await;
    let (phone, invite) = paired(&s, "phone").await;
    let past = vp_daemon::phones::now() - 1;
    let key = vp_crypto::random::<32>();
    let records = s.vault.phones().unwrap().unwrap();
    s.phones.hand_off(vp_native::Handoff {
        key: &key,
        lock_id: [3; 16],
        until: past,
        phones: &records,
        relay_secret: Zeroizing::new([0x11; 32]),
    });
    *s.vault.locked.lock().unwrap() = true;
    let desktop = Desktop::new(Desk::After(Duration::from_millis(100), Decision::Deny));
    let approver = WithPhones {
        desktop: desktop.clone(),
        phones: s.phones.clone(),
    };
    assert_eq!(approver.ask(&prompt()).await.unwrap(), Decision::Deny);
    assert_eq!(desktop.asked.lock().unwrap().len(), 1, "only the desktop");
    assert!(phone.pending_unlock(s.port, &invite).await.is_none());
    assert!(matches!(
        s.phones.phone_unlock(None).await,
        vp_native::PhoneUnlock::NoAnswer
    ));
}
