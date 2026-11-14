//! Phone approvals: a phone the person paired gets the same question as the
//! desktop window, and the first valid answer wins (see `vp-phone` for the
//! messages and their checks).
//!
//! Nothing a caller sets chooses where approvals are asked: visipassd asks
//! every paired phone and the desktop every time. Pairing is refused to
//! agents, confirmed with the master password and a code compared on both
//! screens, and recorded sealed in the vault, so nothing an agent can write
//! adds a phone. Phones are asked only while the vault is unlocked, and never
//! about unlocking it, the master password or anything else typed only at the
//! computer.
//!
//! The phone reaches visipassd through `tailscale serve`, which forwards HTTPS
//! to a loopback port. Every process on this computer can reach that port too,
//! so everything on it is untrusted input: four routes, bounded bodies, rate
//! limits, and every message sealed or signed above HTTP.

use crate::approval::{Approver, Prompt, STANDING_HOURS};
use crate::grants::Decision;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use vp_core::Failure;
use vp_core::ipc::PasteMode;
use vp_core::secret::Secret;
use vp_phone::{
    Choice, Commit, DaemonKey, Invite, Kind, Nonce, PairingId, Phone, Request, RequestId, Reveal,
    SealedRequest, SignedAnswer,
};
use zeroize::Zeroizing;

/// Where visipassd listens for `tailscale serve`, on loopback only.
pub const PORT: u16 = 7473;

/// Requests a phone may make to `pending` and `answer` in a minute.
const PER_MINUTE: u32 = 120;
/// Messages a pairing window takes, valid or not, before it closes.
const PAIRING_ATTEMPTS: u32 = 12;
/// Connections served at once.
const CONNECTIONS: usize = 16;
/// A request's head (request line and headers).
const MAX_HEAD: usize = 8 * 1024;
/// How long a connection may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Paired phones' records, opened: `(pairing_id, record)`.
pub type PhoneRecords = Vec<(PairingId, Zeroizing<Vec<u8>>)>;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where pairing records are kept: sealed in the native vault.
pub trait PairingStore: Send + Sync + 'static {
    /// Every pairing's record; `None` while the vault is locked.
    fn phones(&self) -> Result<Option<PhoneRecords>, Failure>;
    /// Seals `record` in the vault, or with `None` removes the pairing.
    fn set_phone(&self, pairing_id: &PairingId, record: Option<&[u8]>) -> Result<bool, Failure>;
    /// Checks the master password, opening the vault if it is locked.
    fn confirm_password(&self, password: Secret) -> BoxFuture<'_, Result<(), Failure>>;
}

impl<U: vp_native::Unlock> PairingStore for vp_native::NativeBackend<U> {
    fn phones(&self) -> Result<Option<PhoneRecords>, Failure> {
        vp_native::NativeBackend::phones(self)
    }

    fn set_phone(&self, pairing_id: &PairingId, record: Option<&[u8]>) -> Result<bool, Failure> {
        vp_native::NativeBackend::set_phone(self, pairing_id, record)
    }

    fn confirm_password(&self, password: Secret) -> BoxFuture<'_, Result<(), Failure>> {
        Box::pin(vp_native::NativeBackend::confirm_password(self, password))
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The page with the pairing QR code: self-contained, shown from memory like
/// the Emergency Kit, never printed or written to a file.
pub fn pairing_page(invite: &Invite, port: u16) -> Result<Zeroizing<String>, Failure> {
    let uri = invite.uri();
    let svg = Zeroizing::new(
        qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
            .map_err(|_| Failure::new("Could not make the pairing code"))?
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(320, 320)
            .quiet_zone(true)
            .build(),
    );
    let svg = svg.as_str();
    let endpoint = escape(&invite.endpoint);
    Ok(Zeroizing::new(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Pair a phone with VisiPass</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; }}
  .code {{ background: #fff; padding: 12px; border-radius: 12px; width: fit-content; margin: 1.5rem 0; }}
  .code svg {{ display: block; width: 320px; height: 320px; }}
  code {{ font-size: 0.9em; }}
  small {{ color: GrayText; }}
</style></head><body>
<h1>Pair a phone</h1>
<p>In the VisiPass app on your phone, choose <b>Pair with a computer</b> and scan this code. It works once, for five minutes.</p>
<div class="code">{svg}</div>
<p>Then check that the six digits on your phone match the ones VisiPass shows on this computer.</p>
<p><small>Your phone reaches this computer at <code>{endpoint}</code>, through Tailscale. Tailscale must be running on the phone, and this computer must forward HTTPS to VisiPass:<br>
<code>tailscale serve --bg http://127.0.0.1:{port}</code></small></p>
<p><small>Close this page when you are done; it is deleted from memory in ten minutes.</small></p>
</body></html>"#
    )))
}

/// This computer's Tailscale name, as `https://name.tailnet.ts.net`, from the
/// `tailscale` program in the system directories (never PATH, which the caller
/// sets). A wrong answer would only point the phone somewhere that cannot open
/// its messages, but the person sees it on the pairing page all the same.
pub async fn tailscale_endpoint() -> Option<String> {
    let program = crate::approval::trusted_program("tailscale").or_else(|| {
        let app = std::path::PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale");
        (cfg!(target_os = "macos") && app.is_file()).then_some(app)
    })?;
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(program)
            .args(["status", "--json"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let name = status["Self"]["DNSName"].as_str()?.trim_end_matches('.');
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    valid.then(|| format!("https://{}", name.to_ascii_lowercase()))
}

/// What a phone answered, once every check has passed.
pub struct PhoneAnswer {
    pub choice: Choice,
    /// A pasted secret, for a paste request answered with anything but Deny.
    pub value: Option<Secret>,
    /// The phone's name, for the access log.
    pub phone: String,
}

/// One question to every paired phone; the first valid answer goes here.
struct Ask {
    answer: Mutex<Option<oneshot::Sender<PhoneAnswer>>>,
}

/// A request one phone may fetch and answer.
struct Pending {
    pairing: Arc<vp_phone::Pairing>,
    request: Request,
    body: Vec<u8>,
    sealed: SealedRequest,
    ask: Arc<Ask>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
    /// Waiting for the phone's commitment.
    Open,
    /// The commitment came, and `n_D` went back.
    Committed,
    /// The phone revealed keys matching its commitment.
    Revealed,
    /// Over, with the reason to give the person and the phone.
    Cancelled(&'static str),
}

/// A pairing in progress, from the QR code to the person's confirmation.
struct Window {
    invite: Invite,
    key: DaemonKey,
    opened: Instant,
    stage: Stage,
    commit: Option<Commit>,
    n_d: [u8; 32],
    phone: Option<Phone>,
    attempts: u32,
}

const SECOND_COMMIT: &str =
    "Another device tried to pair with this code. Pairing cancelled; start again";

#[derive(Default)]
struct State {
    window: Option<Window>,
    pending: HashMap<RequestId, Pending>,
    /// Per pairing: the minute's start and the requests in it.
    rates: HashMap<PairingId, (Instant, u32)>,
    /// Who answered the last approval, while it is read back.
    answered_by: Option<String>,
}

pub struct Phones {
    store: Box<dyn PairingStore>,
    port: u16,
    state: Mutex<State>,
    /// Woken when a pairing window changes stage.
    changed: Notify,
    /// The port, once listening.
    listening: tokio::sync::Mutex<Option<u16>>,
}

/// An HTTP response: status and body.
type Reply = (u16, Vec<u8>);

fn refuse(status: u16, message: &str) -> Reply {
    (status, message.as_bytes().to_vec())
}

impl Phones {
    /// `port` 0 picks a free one (tests).
    pub fn new(store: impl PairingStore, port: u16) -> Arc<Self> {
        Arc::new(Self {
            store: Box::new(store),
            port,
            state: Mutex::default(),
            changed: Notify::new(),
            listening: tokio::sync::Mutex::new(None),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The paired phones, decoded; `None` while the vault is locked.
    pub fn pairings(&self) -> Result<Option<Vec<vp_phone::Pairing>>, Failure> {
        let Some(records) = self.store.phones()? else {
            return Ok(None);
        };
        records
            .iter()
            .map(|(id, record)| {
                vp_phone::Pairing::decode(record)
                    .ok()
                    .filter(|p| p.pairing_id == *id)
                    .ok_or_else(|| Failure::new("A phone's pairing record does not read"))
            })
            .collect::<Result<_, _>>()
            .map(Some)
    }

    pub async fn confirm_password(&self, password: Secret) -> Result<(), Failure> {
        self.store.confirm_password(password).await
    }

    /// Unpairs the phone named `phone` (or with that pairing ID), and withdraws
    /// anything waiting for it. Returns its name.
    pub fn remove(&self, phone: &str) -> Result<String, Failure> {
        let pairings = self
            .pairings()?
            .ok_or_else(|| Failure::new("VisiPass is locked; unlock it to remove a phone"))?;
        let mut matching = pairings.iter().filter(|p| {
            hex(&p.pairing_id) == phone.to_ascii_lowercase() || p.name.eq_ignore_ascii_case(phone)
        });
        let pairing = match (matching.next(), matching.next()) {
            (Some(pairing), None) => pairing,
            (Some(_), Some(_)) => {
                return Err(Failure::new(format!(
                    "More than one phone is named {phone}; remove it by its ID from `vp phone list`"
                )));
            }
            (None, _) => {
                return Err(Failure::new(format!(
                    "No phone named {phone} is paired. See `vp phone list`"
                )));
            }
        };
        self.store.set_phone(&pairing.pairing_id, None)?;
        self.state()
            .pending
            .retain(|_, p| p.pairing.pairing_id != pairing.pairing_id);
        Ok(pairing.name.clone())
    }

    /// Starts the loopback listener, once. Returns its port.
    pub async fn listen(self: &Arc<Self>) -> Result<u16, Failure> {
        let mut listening = self.listening.lock().await;
        if let Some(port) = *listening {
            return Ok(port);
        }
        let listener = TcpListener::bind(("127.0.0.1", self.port))
            .await
            .map_err(|_| {
                Failure::new(format!(
                    "Could not listen for phones on 127.0.0.1:{}: is something else using that port?",
                    self.port
                ))
            })?;
        let port = listener
            .local_addr()
            .map_err(|_| Failure::new("Could not listen for phones"))?
            .port();
        tokio::spawn(self.clone().serve(listener));
        *listening = Some(port);
        Ok(port)
    }

    async fn serve(self: Arc<Self>, listener: TcpListener) {
        let slots = Arc::new(tokio::sync::Semaphore::new(CONNECTIONS));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            // Over the limit, a connection is closed unanswered.
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let phones = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                phones.connection(stream).await;
            });
        }
    }

    async fn connection(&self, mut stream: TcpStream) {
        let reply = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok((method, path, body))) => self.route(&method, &path, &body),
            Ok(Err(reply)) => reply,
            Err(_) => refuse(408, "Too slow"),
        };
        if write_reply(&mut stream, reply).await.is_ok() {
            // Read what the client still sends before closing, a little and
            // briefly: closing with unread input resets the connection, and the
            // client may never see the reply.
            let mut rest = [0u8; 4096];
            let mut left = 4 * vp_phone::MAX_MESSAGE;
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while let Ok(n @ 1..) = stream.read(&mut rest).await {
                    left = left.saturating_sub(n);
                    if left == 0 {
                        break;
                    }
                }
            })
            .await;
        }
    }

    fn route(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        match (method, path) {
            ("POST", "/v1/pair/commit") => self.commit(body),
            ("POST", "/v1/pair/reveal") => self.reveal(body),
            ("POST", "/v1/answer") => self.answer(body),
            ("GET", path) => match path.strip_prefix("/v1/pending/").and_then(unhex::<16>) {
                Some(pairing_id) => self.pending(&pairing_id),
                None => refuse(404, "Not found"),
            },
            _ => refuse(404, "Not found"),
        }
    }

    /// Counts a request against a pairing's minute; false once over.
    fn within_rate(&self, pairing_id: &PairingId) -> bool {
        let mut state = self.state();
        // Pairing IDs come from the request, so anything on this computer can
        // make up new ones: keep only the last minute's.
        if state.rates.len() >= 1024 {
            state
                .rates
                .retain(|_, (start, _)| start.elapsed() < Duration::from_secs(60));
        }
        let entry = state
            .rates
            .entry(*pairing_id)
            .or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        entry.1 += 1;
        entry.1 <= PER_MINUTE
    }

    // ---- Pairing ------------------------------------------------------------

    /// Opens a pairing window for a phone that will reach this computer at
    /// `endpoint`. Returns the QR code's contents. One window at a time.
    pub fn open_window(&self, endpoint: String) -> Invite {
        let key = DaemonKey::generate();
        let invite = Invite::new(endpoint, key.public());
        self.state().window = Some(Window {
            invite: invite.clone(),
            key,
            opened: Instant::now(),
            stage: Stage::Open,
            commit: None,
            n_d: vp_crypto::random(),
            phone: None,
            attempts: 0,
        });
        invite
    }

    pub fn close_window(&self) {
        self.state().window = None;
        self.changed.notify_waiters();
    }

    /// Waits for the phone to reveal its keys. Returns the phone and the code
    /// both screens show, or why pairing ended.
    pub async fn revealed(&self, pairing_id: &PairingId) -> Result<(Phone, String), Failure> {
        let deadline = Instant::now() + Duration::from_secs(vp_phone::PAIRING_SECS);
        loop {
            let changed = self.changed.notified();
            {
                let state = self.state();
                let window = state
                    .window
                    .as_ref()
                    .filter(|w| w.invite.pairing_id == *pairing_id)
                    .ok_or_else(|| Failure::new("Pairing was cancelled"))?;
                match (&window.stage, &window.phone) {
                    (Stage::Revealed, Some(phone)) => {
                        let code = vp_phone::pairing_code(
                            pairing_id,
                            &window.key.public(),
                            phone,
                            &window.n_d,
                        );
                        return Ok((phone.clone(), code));
                    }
                    (Stage::Cancelled(reason), _) => return Err(Failure::new(*reason)),
                    _ => {}
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || tokio::time::timeout(left, changed).await.is_err() {
                return Err(Failure::new(
                    "No phone paired within 5 minutes. Run `vp phone pair` again when the app is ready to scan",
                ));
            }
        }
    }

    /// Records the pairing the person confirmed, sealed in the vault.
    pub fn keep(&self, pairing_id: &PairingId, phone: &Phone) -> Result<(), Failure> {
        let key = {
            let state = self.state();
            let window = state
                .window
                .as_ref()
                .filter(|w| w.invite.pairing_id == *pairing_id && w.stage == Stage::Revealed)
                .ok_or_else(|| Failure::new("Pairing was cancelled"))?;
            window.key.clone()
        };
        let record = vp_phone::Pairing {
            pairing_id: *pairing_id,
            // Shown later in `vp phone list` and the access log.
            name: vp_core::ipc::clean_text(&phone.name, false, 64),
            sign_p: phone.sign_p,
            kem_p: phone.kem_p,
            kem_d: key,
            push_token: phone.push_token.clone(),
            created: now(),
        };
        self.store.set_phone(pairing_id, Some(&record.encode()))?;
        self.close_window();
        Ok(())
    }

    /// The window a pairing message is for, if it is open, counting the attempt.
    fn window_for<'a>(
        state: &'a mut State,
        pairing_id: &PairingId,
    ) -> Result<&'a mut Window, Reply> {
        let window = state
            .window
            .as_mut()
            .filter(|w| w.invite.pairing_id == *pairing_id)
            .ok_or_else(|| refuse(404, "No pairing is open with that code"))?;
        if window.opened.elapsed() >= Duration::from_secs(vp_phone::PAIRING_SECS) {
            return Err(refuse(410, "The pairing code has expired; start again"));
        }
        window.attempts += 1;
        if window.attempts > PAIRING_ATTEMPTS {
            window.stage =
                Stage::Cancelled("Too many pairing attempts. Pairing cancelled; start again");
        }
        if let Stage::Cancelled(reason) = window.stage {
            return Err(refuse(409, reason));
        }
        Ok(window)
    }

    fn commit(&self, body: &[u8]) -> Reply {
        let Ok(commit) = Commit::decode(body) else {
            return refuse(400, "Not a pairing commit");
        };
        let reply = {
            let mut state = self.state();
            let window = match Self::window_for(&mut state, &commit.pairing_id) {
                Ok(window) => window,
                Err(reply) => return reply,
            };
            if commit.check(&window.invite).is_err() {
                return refuse(403, "The pairing code does not match");
            }
            if window.stage != Stage::Open {
                // Someone else holds the code too: say so on both screens
                // rather than let either finish.
                window.stage = Stage::Cancelled(SECOND_COMMIT);
                refuse(409, SECOND_COMMIT)
            } else {
                window.stage = Stage::Committed;
                window.commit = Some(commit.clone());
                let nonce = Nonce {
                    pairing_id: commit.pairing_id,
                    n_d: window.n_d,
                };
                (200, nonce.encode())
            }
        };
        self.changed.notify_waiters();
        reply
    }

    fn reveal(&self, body: &[u8]) -> Reply {
        let Ok(reveal) = Reveal::decode(body) else {
            return refuse(400, "Not a pairing reveal");
        };
        let reply = {
            let mut state = self.state();
            let window = match Self::window_for(&mut state, &reveal.pairing_id) {
                Ok(window) => window,
                Err(reply) => return reply,
            };
            let (Stage::Committed, Some(commit)) = (&window.stage, &window.commit) else {
                return refuse(409, "Send the commitment first");
            };
            match reveal.open(&window.key, &window.invite, commit) {
                Ok(phone) => {
                    window.phone = Some(phone);
                    window.stage = Stage::Revealed;
                    (200, Vec::new())
                }
                Err(_) => return refuse(403, "The phone's keys do not match its commitment"),
            }
        };
        self.changed.notify_waiters();
        reply
    }

    // ---- Asking -------------------------------------------------------------

    /// Seals `prompt` to every paired phone. `None` when there is nobody to ask:
    /// no phones, the vault locked, or the listener down.
    fn post(self: &Arc<Self>, prompt: &Prompt, kind: Kind) -> Option<Posted> {
        let pairings = match self.pairings() {
            Ok(Some(pairings)) if !pairings.is_empty() => pairings,
            _ => return None,
        };
        let shown = prompt.cleaned();
        let paste = shown
            .paste
            .as_ref()
            .map(|p| (p.title.clone(), p.vault.clone()));
        let phone_prompt = vp_phone::Prompt {
            who: shown.who,
            action: shown.action,
            details: shown.details,
            secrets: shown.secrets,
            purpose: shown.purpose,
            paste,
        };
        // "Always" is offered only at the computer.
        let choices = if shown.every_time || kind == Kind::Paste {
            vec![Choice::Deny, Choice::Once]
        } else {
            vec![Choice::Deny, Choice::Once, Choice::Task, Choice::Hours]
        };
        let (sender, receiver) = oneshot::channel();
        let ask = Arc::new(Ask {
            answer: Mutex::new(Some(sender)),
        });
        let issued = now();
        let mut ids = Vec::new();
        let mut state = self.state();
        for pairing in pairings {
            let request = Request::new(
                pairing.pairing_id,
                kind,
                phone_prompt.clone(),
                choices.clone(),
                issued,
            );
            let body = request.encode();
            let Ok(sealed) =
                SealedRequest::seal(&pairing.kem_d, &pairing.kem_p, &pairing.pairing_id, &body)
            else {
                continue;
            };
            ids.push(request.request_id);
            state.pending.insert(
                request.request_id,
                Pending {
                    pairing: Arc::new(pairing),
                    request,
                    body,
                    sealed,
                    ask: ask.clone(),
                },
            );
        }
        drop(state);
        (!ids.is_empty()).then(|| Posted {
            phones: self.clone(),
            ids,
            receiver: Some(receiver),
        })
    }

    fn withdraw(&self, ids: &[RequestId]) {
        let mut state = self.state();
        for id in ids {
            state.pending.remove(id);
        }
    }

    fn pending(&self, pairing_id: &PairingId) -> Reply {
        if !self.within_rate(pairing_id) {
            return refuse(429, "Too many requests");
        }
        let now = now();
        let requests: Vec<SealedRequest> = self
            .state()
            .pending
            .values()
            .filter(|p| p.pairing.pairing_id == *pairing_id && now < p.request.expires_at)
            .map(|p| p.sealed.clone())
            .collect();
        if requests.is_empty() {
            // Nothing waiting: say whether this phone is paired at all, so the
            // app knows when pairing has been confirmed or removed.
            match self.store.phones() {
                Ok(Some(phones)) if phones.iter().any(|(id, _)| id == pairing_id) => {}
                Ok(Some(_)) => return refuse(404, "This phone is not paired"),
                Ok(None) => return refuse(423, "VisiPass is locked; unlock at the computer"),
                Err(_) => return refuse(500, "VisiPass could not read its phones"),
            }
        }
        (200, vp_phone::encode_pending(&requests))
    }

    fn answer(&self, body: &[u8]) -> Reply {
        let Ok(signed) = SignedAnswer::decode(body) else {
            return refuse(400, "Not an answer");
        };
        if !self.within_rate(&signed.pairing_id) {
            return refuse(429, "Too many requests");
        }
        // The pairing's keys, from a request still waiting for it: with none,
        // there is nothing it could answer.
        let pairing = self
            .state()
            .pending
            .values()
            .find(|p| p.pairing.pairing_id == signed.pairing_id)
            .map(|p| p.pairing.clone());
        let Some(pairing) = pairing else {
            return refuse(410, "Nothing is waiting for an answer");
        };
        // 1. The signature, before anything in the answer is looked at.
        let Ok(answer) = signed.verify(&pairing.sign_p) else {
            return refuse(403, "The answer's signature does not verify");
        };
        // 2–4. The request, its bytes, expiry and choices; then the first
        // valid answer takes the request from every phone.
        let ask = {
            let state = self.state();
            let Some(pending) = state
                .pending
                .get(&answer.request_id)
                .filter(|p| p.pairing.pairing_id == signed.pairing_id)
            else {
                return refuse(410, "That request is no longer waiting");
            };
            if answer
                .check(&pending.request, &pending.body, now())
                .is_err()
            {
                return refuse(422, "The answer does not fit the request");
            }
            pending.ask.clone()
        };
        let value = match answer.open_value(&pairing.kem_d, &pairing.pairing_id) {
            Ok(None) => None,
            Ok(Some(v)) => match String::from_utf8(v.to_vec()) {
                Ok(text) => Some(Secret::new(text)),
                Err(e) => {
                    drop(Zeroizing::new(e.into_bytes()));
                    return refuse(422, "The pasted value is not text");
                }
            },
            Err(_) => return refuse(422, "The pasted value does not open"),
        };
        let Some(sender) = ask.answer.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return refuse(410, "That request was already answered");
        };
        self.state()
            .pending
            .retain(|_, p| !Arc::ptr_eq(&p.ask, &ask));
        let _ = sender.send(PhoneAnswer {
            choice: answer.choice,
            value,
            phone: pairing.name.clone(),
        });
        (200, Vec::new())
    }
}

/// Requests posted to the phones; withdrawn when dropped, whoever answered.
struct Posted {
    phones: Arc<Phones>,
    ids: Vec<RequestId>,
    receiver: Option<oneshot::Receiver<PhoneAnswer>>,
}

impl Posted {
    /// The first valid answer from any phone; `None` if none comes in time.
    async fn answer(&mut self) -> Option<PhoneAnswer> {
        let receiver = self.receiver.take()?;
        let answer = tokio::time::timeout(Duration::from_secs(vp_phone::ANSWER_SECS), receiver)
            .await
            .ok()?
            .ok()?;
        self.phones.state().answered_by = Some(answer.phone.clone());
        Some(answer)
    }
}

impl Drop for Posted {
    fn drop(&mut self) {
        self.phones.withdraw(&self.ids);
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>), Reply> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > MAX_HEAD {
            return Err(refuse(431, "Headers too large"));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| refuse(400, "Bad request"))?;
        if n == 0 {
            return Err(refuse(400, "Bad request"));
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let mut body = buffer.split_off(head_end + 4);
    buffer.truncate(head_end);
    let head = std::str::from_utf8(&buffer).map_err(|_| refuse(400, "Bad request"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(path), Some(version), None) =
        (first.next(), first.next(), first.next(), first.next())
    else {
        return Err(refuse(400, "Bad request"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(refuse(505, "HTTP/1.1 only"));
    }
    let mut length = 0usize;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| refuse(400, "Bad request"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().map_err(|_| refuse(400, "Bad request"))?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(refuse(411, "Send a Content-Length"));
        }
    }
    if length > vp_phone::MAX_MESSAGE {
        return Err(refuse(413, "Too large"));
    }
    while body.len() < length {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| refuse(400, "Bad request"))?;
        if n == 0 {
            return Err(refuse(400, "Bad request"));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if body.len() != length {
        return Err(refuse(400, "Bad request"));
    }
    Ok((method.to_string(), path.to_string(), body))
}

async fn write_reply(stream: &mut TcpStream, (status, body): Reply) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        423 => "Locked",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let kind = if status == 200 {
        "application/cbor"
    } else {
        "text/plain; charset=utf-8"
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

/// The desktop approver, with every paired phone asked alongside it.
pub struct WithPhones<A> {
    pub desktop: A,
    pub phones: Arc<Phones>,
}

fn decision(choice: Choice) -> Decision {
    match choice {
        Choice::Deny => Decision::Deny,
        Choice::Once => Decision::Once,
        Choice::Task => Decision::Task,
        Choice::Hours => Decision::Hours(STANDING_HOURS),
    }
}

impl<A: Approver> Approver for WithPhones<A> {
    fn method(&self) -> &'static str {
        self.desktop.method()
    }

    async fn ask(&self, prompt: &Prompt) -> Result<Decision, Failure> {
        self.phones.state().answered_by = None;
        let Some(mut posted) = self.phones.post(prompt, Kind::Approve) else {
            return self.desktop.ask(prompt).await;
        };
        let desktop = self.desktop.ask(prompt);
        let phone = posted.answer();
        tokio::pin!(desktop, phone);
        let mut failed = None;
        loop {
            tokio::select! {
                // Answering at the computer closes the phones' question; the
                // phones' answer drops the window, which closes it.
                result = &mut desktop, if failed.is_none() => match result {
                    Ok(decision) => return Ok(decision),
                    // No desktop to ask (an SSH-only machine): the phones still can.
                    Err(e) => failed = Some(e),
                },
                answer = &mut phone => return match (answer, failed) {
                    (Some(answer), _) => Ok(decision(answer.choice)),
                    (None, Some(e)) => Err(e),
                    (None, None) => Ok(Decision::Deny),
                },
            }
        }
    }

    async fn ask_at_computer(&self, prompt: &Prompt) -> Result<Decision, Failure> {
        self.desktop.ask(prompt).await
    }

    async fn paste(&self, prompt: &Prompt) -> Result<Option<Secret>, Failure> {
        // Only a new secret an agent asked for: the master password, keys and
        // anything else are typed at the computer.
        let secret = prompt
            .paste
            .as_ref()
            .is_some_and(|p| matches!(p.mode, PasteMode::Secret));
        self.phones.state().answered_by = None;
        let Some(mut posted) = secret
            .then(|| self.phones.post(prompt, Kind::Paste))
            .flatten()
        else {
            return self.desktop.paste(prompt).await;
        };
        let desktop = self.desktop.paste(prompt);
        let phone = posted.answer();
        tokio::pin!(desktop, phone);
        let mut failed = None;
        loop {
            tokio::select! {
                result = &mut desktop, if failed.is_none() => match result {
                    Ok(value) => return Ok(value),
                    Err(e) => failed = Some(e),
                },
                answer = &mut phone => return match (answer, failed) {
                    (Some(answer), _) => Ok(answer.value.filter(|_| answer.choice != Choice::Deny)),
                    (None, Some(e)) => Err(e),
                    (None, None) => Ok(None),
                },
            }
        }
    }

    async fn confirm_presence(&self) -> vp_native::Presence {
        self.desktop.confirm_presence().await
    }

    async fn show_page(&self, html: &str) -> Result<(), Failure> {
        self.desktop.show_page(html).await
    }

    fn answered_by(&self) -> Option<String> {
        self.phones.state().answered_by.take()
    }
}
