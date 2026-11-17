//! The tunnel to the VisiPass relay (crypto §11.4). visipassd holds one
//! WebSocket to `RELAY/t/<tunnel_id>/connect`, proving it holds the secret the
//! id is the hash of; the relay passes each phone request down it and the
//! reply back. Requests from the tunnel go through the same routes, limits and
//! checks as the loopback port's: the relay is trusted with nothing.
//!
//! The tunnel is open only while the unlocked vault has a phone or a pairing
//! window is open. Through it visipassd also asks the relay to send the fixed
//! notification to a phone's device token, which it keeps in the sealed
//! pairing record; the relay stores none.

use super::{Phones, hex, now, refuse};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use vp_core::Failure;
use zeroize::Zeroizing;

pub const RELAY: &str = "https://relay.visipass.app";

/// How often visipassd pings the relay, and checks the tunnel is still wanted.
const PING: Duration = Duration::from_secs(30);
/// Silence after which the connection is taken for dead.
const SILENT: Duration = Duration::from_secs(95);
/// How often to check whether the tunnel is wanted, while it is closed.
const IDLE: Duration = Duration::from_secs(15);

/// `SHA-256(tunnel_secret)[..16]`, hex: the tunnel's public id.
pub fn tunnel_id(secret: &[u8; 32]) -> String {
    hex(&Sha256::digest(secret)[..16])
}

/// A phone's request, passed down by the relay.
#[derive(Deserialize)]
struct Down {
    id: u64,
    method: String,
    path: String,
    body: String,
}

/// visipassd's reply to a request.
#[derive(Serialize)]
struct Up {
    id: u64,
    status: u16,
    body: String,
}

impl Phones {
    /// Where a phone reaches this computer through the relay; `None` while
    /// the vault is locked.
    pub fn relay_endpoint(&self) -> Option<String> {
        let secret = self.store.relay_secret()?;
        Some(format!("{}/t/{}", self.relay, tunnel_id(&secret)))
    }

    /// Whether the tunnel is open now.
    pub fn tunnel_open(&self) -> bool {
        self.sender().is_some()
    }

    /// Waits up to `limit` for the tunnel to open.
    pub async fn wait_for_tunnel(&self, limit: Duration) -> bool {
        let start = Instant::now();
        while !self.tunnel_open() {
            if start.elapsed() >= limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        true
    }

    fn sender(&self) -> Option<tokio::sync::mpsc::UnboundedSender<String>> {
        self.tunnel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn wants_tunnel(&self) -> bool {
        let locked = {
            let state = self.state();
            state.window.is_some() || state.locked.as_ref().is_some_and(|l| now() < l.until)
        };
        locked || matches!(self.pairings(), Ok(Some(p)) if !p.is_empty())
    }

    /// The tunnel's secret: from the open vault, or kept with a lock the
    /// phones can open.
    fn tunnel_secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.store.relay_secret().or_else(|| {
            self.state()
                .locked
                .as_ref()
                .filter(|l| now() < l.until)
                .map(|l| l.relay_secret.clone())
        })
    }

    /// Keeps the tunnel open while it is wanted, reconnecting with backoff.
    /// Runs for visipassd's life.
    pub async fn keep_tunnel(self: Arc<Self>) {
        let mut failures = 0u32;
        loop {
            let secret = if self.wants_tunnel() {
                self.tunnel_secret()
            } else {
                None
            };
            let wait = match secret {
                Some(secret) => {
                    let started = Instant::now();
                    match self.tunnel(&secret).await {
                        Ok(()) => failures = 0,
                        // A connection that lasted was not the problem.
                        Err(_) if started.elapsed() > SILENT => failures = 0,
                        Err(e) => {
                            failures += 1;
                            if failures == 3 {
                                eprintln!("visipassd: phone relay: {e}");
                            }
                        }
                    }
                    Duration::from_secs(1 << failures.min(6))
                }
                None => IDLE,
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.tunnel_wanted.notified() => {}
            }
        }
    }

    /// One connection, until it drops or is no longer wanted.
    async fn tunnel(self: &Arc<Self>, secret: &[u8; 32]) -> Result<(), Failure> {
        let base = self
            .relay
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let mut request = format!("{base}/t/{}/connect", tunnel_id(secret))
            .into_client_request()
            .map_err(|_| Failure::new("Not a relay address"))?;
        let bearer = Zeroizing::new(format!("Bearer {}", hex(secret)));
        let mut bearer = HeaderValue::from_str(&bearer).expect("hex is a header value");
        bearer.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, bearer);
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .map_err(|_| Failure::new("The relay did not answer"))?
        .map_err(|e| Failure::new(format!("Could not reach the relay: {e}")))?;

        let (mut sink, mut stream) = socket.split();
        let (sender, mut outgoing) = tokio::sync::mpsc::unbounded_channel();
        *self.tunnel.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
        let result = async {
            let mut ping = tokio::time::interval(PING);
            ping.tick().await;
            let mut heard = Instant::now();
            loop {
                tokio::select! {
                    message = stream.next() => {
                        heard = Instant::now();
                        match message {
                            Some(Ok(Message::Text(text))) => {
                                if let Some(reply) = self.answer_relay(text.as_str()) {
                                    sink.send(Message::Text(reply.into())).await?;
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => return Ok(()),
                            Some(Ok(_)) => {}
                            Some(Err(e)) => return Err(e),
                        }
                    }
                    Some(frame) = outgoing.recv() => sink.send(Message::Text(frame.into())).await?,
                    _ = ping.tick() => {
                        if !self.wants_tunnel() || heard.elapsed() > SILENT {
                            let _ = sink.close().await;
                            return Ok(());
                        }
                        sink.send(Message::Text("ping".into())).await?;
                    }
                }
            }
        }
        .await;
        *self.tunnel.lock().unwrap_or_else(|e| e.into_inner()) = None;
        result.map_err(|e| Failure::new(format!("The relay connection failed: {e}")))
    }

    /// Answers one request from the relay, as the loopback port would.
    fn answer_relay(&self, text: &str) -> Option<String> {
        let down: Down = serde_json::from_str(text).ok()?;
        let (status, body) = match STANDARD.decode(&down.body) {
            Ok(body) if body.len() <= vp_phone::MAX_MESSAGE => {
                self.route(&down.method, &down.path, &body)
            }
            _ => refuse(413, "Too large"),
        };
        serde_json::to_string(&Up {
            id: down.id,
            status,
            body: STANDARD.encode(body),
        })
        .ok()
    }

    /// Asks the relay to send the fixed notification to each device token.
    /// Without an open tunnel nothing is sent; the phone sees the request the
    /// next time its app looks.
    pub(super) fn notify(&self, tokens: &[Vec<u8>]) {
        if let Some(sender) = self.sender() {
            for token in tokens {
                let _ = sender.send(serde_json::json!({ "push": hex(token) }).to_string());
            }
        }
    }
}
