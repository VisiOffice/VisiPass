//! Phone approvals: the messages between visipassd and a phone the person
//! paired, and how each is sealed, signed and checked. Pure functions over
//! bytes: no I/O, no storage, no clock (callers pass the time).
//!
//! Both ends use this crate: visipassd directly, the iOS app through its Rust
//! core. The phone's two keys live in its Secure Enclave, so the phone signs
//! (`sign_P`) and opens requests (`kem_P`) in its own code; this crate gives it
//! the exact bytes to sign and the HPKE `info` to open with, and does the rest.
//!
//! Every message is a deterministic CBOR array under its own label
//! (`vp_crypto::ad`), read back with the bounded decoder that refuses any
//! other encoding. The transport is not trusted: everything that matters is
//! sealed or signed above it.
//!
//! HPKE (RFC 9180) is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! ChaCha20-Poly1305. Public keys are uncompressed SEC1 points (65 bytes,
//! CryptoKit's `x963Representation`); signatures are ECDSA P-256 over SHA-256,
//! as raw `r ‖ s` (64 bytes, CryptoKit's `rawRepresentation`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, PskBundle, Serializable};
use p256::ecdsa::signature::Verifier;
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use vp_crypto::{Error, Part, Result, Value, ad, decode, hash};
use zeroize::Zeroizing;

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

/// The most any message may be, before it is decoded (the endpoint's limit).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// How long a phone has to answer.
pub const ANSWER_SECS: u64 = 120;
/// How long a pairing window stays open.
pub const PAIRING_SECS: u64 = 300;

/// An uncompressed P-256 public key.
pub type PublicKey = [u8; 65];
pub type PairingId = [u8; 16];
pub type RequestId = [u8; 16];

const URI_SCHEME: &str = "visipass-pair:";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Decodes `bytes` as `label` with exactly `N` parts.
fn parts<const N: usize>(label: &str, bytes: &[u8]) -> Result<[Value; N]> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Error("message too large"));
    }
    decode(label, bytes)?
        .try_into()
        .map_err(|_| Error("wrong number of fields"))
}

fn kem_public(bytes: &PublicKey) -> Result<<Kem as hpke::Kem>::PublicKey> {
    <Kem as hpke::Kem>::PublicKey::from_bytes(bytes).map_err(|_| Error("not a P-256 public key"))
}

fn verifying_key(bytes: &PublicKey) -> Result<p256::ecdsa::VerifyingKey> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error("not a P-256 public key"))
}

/// Checks an ECDSA P-256 signature (raw `r ‖ s`) over `message`.
fn verify(key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> Result<()> {
    const BAD: Error = Error("the signature does not verify");
    let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|_| BAD)?;
    // CryptoKit does not promise a low s; (r, s) and (r, n - s) are the same
    // signature, and answers are told apart by request_id, not by signature.
    let signature = signature.normalize_s().unwrap_or(signature);
    verifying_key(key)?
        .verify(message, &signature)
        .map_err(|_| BAD)
}

fn rng() -> rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

/// HPKE ciphertext: the encapsulated key and the sealed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub enc: PublicKey,
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    fn part(&self) -> Part<'_> {
        Part::List(vec![Part::Bytes(&self.enc), Part::Bytes(&self.ciphertext)])
    }

    fn from_value(value: &Value) -> Result<Self> {
        let [enc, ciphertext] = value.list()? else {
            return Err(Error("wrong number of fields"));
        };
        Ok(Self {
            enc: enc.fixed()?,
            ciphertext: ciphertext.bytes()?.to_vec(),
        })
    }

    fn seal(mode: &OpModeS<Kem>, to: &PublicKey, info: &[u8], plaintext: &[u8]) -> Result<Self> {
        let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
            mode,
            &kem_public(to)?,
            info,
            plaintext,
            &[],
            &mut rng(),
        )
        .map_err(|_| Error("could not seal"))?;
        Ok(Self {
            enc: enc.to_bytes().as_slice().try_into().expect("65 bytes"),
            ciphertext,
        })
    }

    fn open(
        &self,
        mode: &OpModeR<Kem>,
        key: &DaemonKey,
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        const REFUSED: Error = Error("could not open");
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&self.enc).map_err(|_| REFUSED)?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(mode, &key.0, &enc, info, &self.ciphertext, &[])
            .map(Zeroizing::new)
            .map_err(|_| REFUSED)
    }
}

// ---- Keys ---------------------------------------------------------------

/// visipassd's `kem_D` for one pairing. Its 32 bytes are kept only inside the
/// sealed pairing record.
#[derive(Clone)]
pub struct DaemonKey(<Kem as hpke::Kem>::PrivateKey);

impl DaemonKey {
    pub fn generate() -> Self {
        Self(Kem::gen_keypair(&mut rng()).0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        <Kem as hpke::Kem>::PrivateKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error("not a P-256 private key"))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().into())
    }

    pub fn public(&self) -> PublicKey {
        Kem::sk_to_pk(&self.0)
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("65 bytes")
    }

    fn pair(
        &self,
    ) -> (
        <Kem as hpke::Kem>::PrivateKey,
        <Kem as hpke::Kem>::PublicKey,
    ) {
        (self.0.clone(), Kem::sk_to_pk(&self.0))
    }
}

impl std::fmt::Debug for DaemonKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DaemonKey(..)")
    }
}

// ---- Pairing --------------------------------------------------------------

/// What the QR code in the VisiPass window carries, and nowhere else.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// `https://host.tailnet.ts.net`, where the phone reaches visipassd.
    pub endpoint: String,
    pub pairing_id: PairingId,
    pub kem_d: PublicKey,
    /// One-time, valid for the pairing window; the HPKE PSK for the reveal
    /// (at least 32 bytes, RFC 9180 §5.1.2) and the key of the commit's MAC.
    pub secret: Zeroizing<[u8; 32]>,
}

const INVITE: &str = "VisiPass phone pair invite";

impl Invite {
    pub fn new(endpoint: String, kem_d: PublicKey) -> Self {
        Self {
            endpoint,
            pairing_id: vp_crypto::random(),
            kem_d,
            secret: Zeroizing::new(vp_crypto::random()),
        }
    }

    /// `visipass-pair:` and the invite, base64url.
    pub fn uri(&self) -> Zeroizing<String> {
        let bytes = Zeroizing::new(ad(
            INVITE,
            &[
                Part::Text(&self.endpoint),
                Part::Bytes(&self.pairing_id),
                Part::Bytes(&self.kem_d),
                Part::Bytes(self.secret.as_ref()),
            ],
        ));
        Zeroizing::new(format!("{URI_SCHEME}{}", URL_SAFE_NO_PAD.encode(&bytes)))
    }

    pub fn parse(uri: &str) -> Result<Self> {
        const NOT: Error = Error("not a VisiPass pairing code");
        let encoded = uri.trim().strip_prefix(URI_SCHEME).ok_or(NOT)?;
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| NOT)?);
        let [endpoint, pairing_id, kem_d, secret] = parts(INVITE, &bytes)?;
        let endpoint = endpoint.text()?;
        if !endpoint.starts_with("https://") || endpoint.len() > 256 {
            return Err(Error("the pairing endpoint is not an https address"));
        }
        let kem_d = kem_d.fixed()?;
        kem_public(&kem_d)?;
        Ok(Self {
            endpoint: endpoint.into(),
            pairing_id: pairing_id.fixed()?,
            kem_d,
            secret: Zeroizing::new(secret.fixed()?),
        })
    }

    fn reveal_info(&self) -> Vec<u8> {
        ad("VisiPass phone pair", &[Part::Bytes(&self.pairing_id)])
    }
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("endpoint", &self.endpoint)
            .field("pairing_id", &self.pairing_id)
            .finish_non_exhaustive()
    }
}

/// `H(AD("VisiPass phone pair commit", pairing_id, sign_P, kem_P, n_P))`: the
/// phone's keys, fixed before it sees the computer's `n_D`.
pub fn commitment(
    pairing_id: &PairingId,
    sign_p: &PublicKey,
    kem_p: &PublicKey,
    n_p: &[u8; 32],
) -> [u8; 32] {
    hash(
        "VisiPass phone pair commit",
        &[
            Part::Bytes(pairing_id),
            Part::Bytes(sign_p),
            Part::Bytes(kem_p),
            Part::Bytes(n_p),
        ],
    )
}

/// Step 3: the phone's commitment, with a MAC under the invite's secret so
/// only someone who read the QR code can send one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub pairing_id: PairingId,
    pub commitment: [u8; 32],
    pub mac: [u8; 32],
}

const COMMIT: &str = "VisiPass phone pair commit message";

fn commit_mac(secret: &[u8; 32], pairing_id: &PairingId, commitment: &[u8; 32]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&ad(
        "VisiPass phone pair commit mac",
        &[Part::Bytes(pairing_id), Part::Bytes(commitment)],
    ));
    mac
}

impl Commit {
    pub fn new(invite: &Invite, commitment: [u8; 32]) -> Self {
        let mac = commit_mac(&invite.secret, &invite.pairing_id, &commitment);
        Self {
            pairing_id: invite.pairing_id,
            commitment,
            mac: mac.finalize().into_bytes().into(),
        }
    }

    /// Whether this commit was made by someone holding `invite`'s secret.
    pub fn check(&self, invite: &Invite) -> Result<()> {
        if self.pairing_id != invite.pairing_id {
            return Err(Error("another pairing"));
        }
        commit_mac(&invite.secret, &self.pairing_id, &self.commitment)
            .verify_slice(&self.mac)
            .map_err(|_| Error("the pairing code does not match"))
    }

    pub fn encode(&self) -> Vec<u8> {
        ad(
            COMMIT,
            &[
                Part::Bytes(&self.pairing_id),
                Part::Bytes(&self.commitment),
                Part::Bytes(&self.mac),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [pairing_id, commitment, mac] = parts(COMMIT, bytes)?;
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            commitment: commitment.fixed()?,
            mac: mac.fixed()?,
        })
    }
}

/// Step 4: the computer's random input, sent only after the commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    pub pairing_id: PairingId,
    pub n_d: [u8; 32],
}

const NONCE: &str = "VisiPass phone pair nonce";

impl Nonce {
    pub fn encode(&self) -> Vec<u8> {
        ad(
            NONCE,
            &[Part::Bytes(&self.pairing_id), Part::Bytes(&self.n_d)],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [pairing_id, n_d] = parts(NONCE, bytes)?;
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            n_d: n_d.fixed()?,
        })
    }
}

/// What the phone reveals in step 5, sealed to `kem_D`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phone {
    /// The phone's name, as the person will see it in `vp phone list`.
    pub name: String,
    pub sign_p: PublicKey,
    pub kem_p: PublicKey,
    pub n_p: [u8; 32],
    /// From the push relay; empty when notifications are off.
    pub push_token: Vec<u8>,
}

const PHONE: &str = "VisiPass phone pair reveal body";

impl Phone {
    pub fn encode(&self) -> Vec<u8> {
        ad(
            PHONE,
            &[
                Part::Text(&self.name),
                Part::Bytes(&self.sign_p),
                Part::Bytes(&self.kem_p),
                Part::Bytes(&self.n_p),
                Part::Bytes(&self.push_token),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [name, sign_p, kem_p, n_p, push_token] = parts(PHONE, bytes)?;
        let phone = Self {
            name: name.text()?.into(),
            sign_p: sign_p.fixed()?,
            kem_p: kem_p.fixed()?,
            n_p: n_p.fixed()?,
            push_token: push_token.bytes()?.to_vec(),
        };
        if phone.name.trim().is_empty() || phone.name.chars().count() > 64 {
            return Err(Error("the phone's name is empty or too long"));
        }
        verifying_key(&phone.sign_p)?;
        kem_public(&phone.kem_p)?;
        Ok(phone)
    }

    /// What `sign_P` signs to reveal: the body it sealed, by hash.
    pub fn signed_bytes(pairing_id: &PairingId, body: &[u8]) -> Vec<u8> {
        ad(
            "VisiPass phone pair reveal",
            &[Part::Bytes(pairing_id), Part::Bytes(&sha256(body))],
        )
    }
}

/// Step 5 on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub pairing_id: PairingId,
    pub sealed: Sealed,
    pub signature: [u8; 64],
}

const REVEAL: &str = "VisiPass phone pair reveal message";

impl Reveal {
    /// The phone seals its encoded [`Phone`] to the invite's `kem_D`, with the
    /// invite's secret as the PSK. It then signs [`Phone::signed_bytes`].
    pub fn seal(invite: &Invite, body: &[u8]) -> Result<Sealed> {
        let psk = PskBundle::new(invite.secret.as_ref(), &invite.pairing_id)
            .map_err(|_| Error("could not seal"))?;
        Sealed::seal(
            &OpModeS::Psk(psk),
            &invite.kem_d,
            &invite.reveal_info(),
            body,
        )
    }

    /// visipassd's side: opens the reveal, checks `sign_P`'s signature over it,
    /// and that it is what the phone committed to.
    pub fn open(&self, key: &DaemonKey, invite: &Invite, commit: &Commit) -> Result<Phone> {
        if self.pairing_id != invite.pairing_id || commit.pairing_id != invite.pairing_id {
            return Err(Error("another pairing"));
        }
        let psk = PskBundle::new(invite.secret.as_ref(), &invite.pairing_id)
            .map_err(|_| Error("could not open"))?;
        let body = self
            .sealed
            .open(&OpModeR::Psk(psk), key, &invite.reveal_info())?;
        let phone = Phone::decode(&body)?;
        verify(
            &phone.sign_p,
            &Phone::signed_bytes(&self.pairing_id, &body),
            &self.signature,
        )?;
        if commitment(&self.pairing_id, &phone.sign_p, &phone.kem_p, &phone.n_p)
            != commit.commitment
        {
            return Err(Error("the phone revealed other keys than it committed to"));
        }
        Ok(phone)
    }

    pub fn encode(&self) -> Vec<u8> {
        ad(
            REVEAL,
            &[
                Part::Bytes(&self.pairing_id),
                self.sealed.part(),
                Part::Bytes(&self.signature),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [pairing_id, sealed, signature] = parts(REVEAL, bytes)?;
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            sealed: Sealed::from_value(&sealed)?,
            signature: signature.fixed()?,
        })
    }
}

/// Step 6: the six digits both screens show. Anyone who read the QR code and
/// committed first gets digits it could not choose, which do not match the
/// person's phone.
pub fn pairing_code(
    pairing_id: &PairingId,
    kem_d: &PublicKey,
    phone: &Phone,
    n_d: &[u8; 32],
) -> String {
    let h = hash(
        "VisiPass phone pair code",
        &[
            Part::Bytes(pairing_id),
            Part::Bytes(kem_d),
            Part::Bytes(&phone.sign_p),
            Part::Bytes(&phone.kem_p),
            Part::Bytes(&phone.n_p),
            Part::Bytes(n_d),
        ],
    );
    // 32 bits reduced to six digits: the bias is under one in four thousand.
    let n = u32::from_be_bytes(h[..4].try_into().expect("four bytes")) % 1_000_000;
    format!("{n:06}")
}

// ---- Requests -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Approve or deny an agent's request.
    Approve,
    /// Paste a new secret an agent asked for.
    Paste,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Approve => "approve",
            Kind::Paste => "paste",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "approve" => Ok(Kind::Approve),
            "paste" => Ok(Kind::Paste),
            _ => Err(Error("unknown kind of request")),
        }
    }
}

/// What the phone may answer. There is no "always": standing grants are made
/// only at the computer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Deny,
    Once,
    Task,
    Hours,
}

impl Choice {
    pub fn as_str(self) -> &'static str {
        match self {
            Choice::Deny => "deny",
            Choice::Once => "once",
            Choice::Task => "task",
            Choice::Hours => "hours",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "deny" => Ok(Choice::Deny),
            "once" => Ok(Choice::Once),
            "task" => Ok(Choice::Task),
            "hours" => Ok(Choice::Hours),
            _ => Err(Error("unknown choice")),
        }
    }
}

/// The approval prompt as the desktop shows it, already cleaned by
/// visipassd (Invariant 12).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prompt {
    pub who: String,
    pub action: String,
    pub details: Vec<(String, String)>,
    pub secrets: Vec<String>,
    pub purpose: Option<String>,
    /// For a paste request: the item's title and vault.
    pub paste: Option<(String, String)>,
}

impl Prompt {
    fn part(&self) -> Part<'_> {
        Part::List(vec![
            Part::Text(&self.who),
            Part::Text(&self.action),
            Part::List(
                self.details
                    .iter()
                    .map(|(label, value)| Part::List(vec![Part::Text(label), Part::Text(value)]))
                    .collect(),
            ),
            Part::List(self.secrets.iter().map(|s| Part::Text(s)).collect()),
            Part::List(self.purpose.iter().map(|p| Part::Text(p)).collect()),
            Part::List(
                self.paste
                    .iter()
                    .flat_map(|(title, vault)| [Part::Text(title), Part::Text(vault)])
                    .collect(),
            ),
        ])
    }

    fn from_value(value: &Value) -> Result<Self> {
        let [who, action, details, secrets, purpose, paste] = value.list()? else {
            return Err(Error("wrong number of fields"));
        };
        let texts = |value: &Value| -> Result<Vec<String>> {
            value
                .list()?
                .iter()
                .map(|v| Ok(v.text()?.to_string()))
                .collect()
        };
        let details = details
            .list()?
            .iter()
            .map(|pair| match pair.list()? {
                [label, value] => Ok((label.text()?.into(), value.text()?.into())),
                _ => Err(Error("wrong number of fields")),
            })
            .collect::<Result<_>>()?;
        let mut purpose = texts(purpose)?;
        let paste = match texts(paste)?.as_mut_slice() {
            [] => None,
            [title, vault] => Some((std::mem::take(title), std::mem::take(vault))),
            _ => return Err(Error("wrong number of fields")),
        };
        if purpose.len() > 1 {
            return Err(Error("wrong number of fields"));
        }
        Ok(Self {
            who: who.text()?.into(),
            action: action.text()?.into(),
            details,
            secrets: texts(secrets)?,
            purpose: purpose.pop(),
            paste,
        })
    }
}

/// One question for one phone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: RequestId,
    pub pairing_id: PairingId,
    pub kind: Kind,
    pub prompt: Prompt,
    pub choices: Vec<Choice>,
    /// Seconds since the Unix epoch, by visipassd's clock.
    pub issued_at: u64,
    pub expires_at: u64,
}

const REQUEST: &str = "VisiPass phone request body";

impl Request {
    pub fn new(
        pairing_id: PairingId,
        kind: Kind,
        prompt: Prompt,
        choices: Vec<Choice>,
        now: u64,
    ) -> Self {
        Self {
            request_id: vp_crypto::random(),
            pairing_id,
            kind,
            prompt,
            choices,
            issued_at: now,
            expires_at: now + ANSWER_SECS,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        ad(
            REQUEST,
            &[
                Part::Bytes(&self.request_id),
                Part::Bytes(&self.pairing_id),
                Part::Text(self.kind.as_str()),
                self.prompt.part(),
                Part::List(
                    self.choices
                        .iter()
                        .map(|c| Part::Text(c.as_str()))
                        .collect(),
                ),
                Part::Uint(self.issued_at),
                Part::Uint(self.expires_at),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [
            request_id,
            pairing_id,
            kind,
            prompt,
            choices,
            issued_at,
            expires_at,
        ] = parts(REQUEST, bytes)?;
        Ok(Self {
            request_id: request_id.fixed()?,
            pairing_id: pairing_id.fixed()?,
            kind: Kind::parse(kind.text()?)?,
            prompt: Prompt::from_value(&prompt)?,
            choices: choices
                .list()?
                .iter()
                .map(|c| Choice::parse(c.text()?))
                .collect::<Result<_>>()?,
            issued_at: issued_at.uint()?,
            expires_at: expires_at.uint()?,
        })
    }

    /// The HPKE `info` a request to this pairing is sealed with.
    pub fn info(pairing_id: &PairingId) -> Vec<u8> {
        ad("VisiPass phone request", &[Part::Bytes(pairing_id)])
    }

    /// `request_hash`: what an answer names, so it answers exactly these bytes.
    pub fn hash(body: &[u8]) -> [u8; 32] {
        sha256(body)
    }
}

/// A request sealed to one phone, as `GET /v1/pending` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRequest {
    pub pairing_id: PairingId,
    pub sealed: Sealed,
}

impl SealedRequest {
    /// HPKE Auth mode from `kem_D` to `kem_P`: only this pairing's visipassd
    /// can make a request the phone opens.
    pub fn seal(
        key: &DaemonKey,
        kem_p: &PublicKey,
        pairing_id: &PairingId,
        body: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            pairing_id: *pairing_id,
            sealed: Sealed::seal(
                &OpModeS::Auth(key.pair()),
                kem_p,
                &Request::info(pairing_id),
                body,
            )?,
        })
    }

    fn part(&self) -> Part<'_> {
        Part::List(vec![Part::Bytes(&self.pairing_id), self.sealed.part()])
    }

    fn from_value(value: &Value) -> Result<Self> {
        let [pairing_id, sealed] = value.list()? else {
            return Err(Error("wrong number of fields"));
        };
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            sealed: Sealed::from_value(sealed)?,
        })
    }
}

const PENDING: &str = "VisiPass phone pending";

/// The answer to `GET /v1/pending/<pairing_id>`.
pub fn encode_pending(requests: &[SealedRequest]) -> Vec<u8> {
    ad(
        PENDING,
        &[Part::List(
            requests.iter().map(SealedRequest::part).collect(),
        )],
    )
}

pub fn decode_pending(bytes: &[u8]) -> Result<Vec<SealedRequest>> {
    let [requests] = parts(PENDING, bytes)?;
    requests
        .list()?
        .iter()
        .map(SealedRequest::from_value)
        .collect()
}

// ---- Answers --------------------------------------------------------------

/// The phone's answer to one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub request_id: RequestId,
    pub request_hash: [u8; 32],
    pub choice: Choice,
    /// A pasted secret, sealed to `kem_D` ([`Answer::seal_value`]).
    pub value: Option<Sealed>,
}

const ANSWER: &str = "VisiPass phone answer body";

fn paste_info(pairing_id: &PairingId, request_hash: &[u8; 32]) -> Vec<u8> {
    ad(
        "VisiPass phone paste",
        &[Part::Bytes(pairing_id), Part::Bytes(request_hash)],
    )
}

impl Answer {
    pub fn encode(&self) -> Vec<u8> {
        ad(
            ANSWER,
            &[
                Part::Bytes(&self.request_id),
                Part::Bytes(&self.request_hash),
                Part::Text(self.choice.as_str()),
                Part::List(self.value.iter().map(Sealed::part).collect()),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [request_id, request_hash, choice, value] = parts(ANSWER, bytes)?;
        let value = match value.list()? {
            [] => None,
            [sealed] => Some(Sealed::from_value(sealed)?),
            _ => return Err(Error("wrong number of fields")),
        };
        Ok(Self {
            request_id: request_id.fixed()?,
            request_hash: request_hash.fixed()?,
            choice: Choice::parse(choice.text()?)?,
            value,
        })
    }

    /// The phone seals a pasted secret to `kem_D` (HPKE Base), bound to the
    /// request it answers.
    pub fn seal_value(
        kem_d: &PublicKey,
        pairing_id: &PairingId,
        request_hash: &[u8; 32],
        value: &[u8],
    ) -> Result<Sealed> {
        Sealed::seal(
            &OpModeS::Base,
            kem_d,
            &paste_info(pairing_id, request_hash),
            value,
        )
    }

    /// What `sign_P` signs: the encoded answer, by hash, for this pairing.
    pub fn signed_bytes(pairing_id: &PairingId, answer: &[u8]) -> Vec<u8> {
        ad(
            "VisiPass phone answer",
            &[Part::Bytes(pairing_id), Part::Bytes(&sha256(answer))],
        )
    }

    /// Checks 2 to 4 of "Answering": this answers exactly `sent`, which
    /// visipassd sent as `sent_body` to this pairing; it has not expired; the
    /// choice was offered; a value comes with a paste, and only with one. That
    /// nothing has answered yet is visipassd's to know.
    pub fn check(&self, sent: &Request, sent_body: &[u8], now: u64) -> Result<()> {
        if self.request_id != sent.request_id || self.request_hash != Request::hash(sent_body) {
            return Err(Error("the answer is to another request"));
        }
        if now >= sent.expires_at {
            return Err(Error("the request has expired"));
        }
        if !sent.choices.contains(&self.choice) {
            return Err(Error("that choice was not offered"));
        }
        let wants_value = sent.kind == Kind::Paste && self.choice != Choice::Deny;
        if wants_value != self.value.is_some() {
            return Err(Error("a pasted value is missing or unexpected"));
        }
        Ok(())
    }

    /// visipassd opens a pasted value, after [`Answer::check`].
    pub fn open_value(
        &self,
        key: &DaemonKey,
        pairing_id: &PairingId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.value
            .as_ref()
            .map(|sealed| {
                sealed.open(
                    &OpModeR::Base,
                    key,
                    &paste_info(pairing_id, &self.request_hash),
                )
            })
            .transpose()
    }
}

/// `POST /v1/answer`: an encoded [`Answer`] and `sign_P`'s signature over
/// [`Answer::signed_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAnswer {
    pub pairing_id: PairingId,
    pub answer: Vec<u8>,
    pub signature: [u8; 64],
}

const SIGNED_ANSWER: &str = "VisiPass phone answer message";

impl SignedAnswer {
    pub fn encode(&self) -> Vec<u8> {
        ad(
            SIGNED_ANSWER,
            &[
                Part::Bytes(&self.pairing_id),
                Part::Bytes(&self.answer),
                Part::Bytes(&self.signature),
            ],
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [pairing_id, answer, signature] = parts(SIGNED_ANSWER, bytes)?;
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            answer: answer.bytes()?.to_vec(),
            signature: signature.fixed()?,
        })
    }

    /// Check 1, before anything in the answer is looked at: the signature
    /// verifies under the pairing's `sign_P`. Only then is the answer decoded.
    pub fn verify(&self, sign_p: &PublicKey) -> Result<Answer> {
        verify(
            sign_p,
            &Answer::signed_bytes(&self.pairing_id, &self.answer),
            &self.signature,
        )?;
        Answer::decode(&self.answer)
    }
}

// ---- Pairing records -----------------------------------------------------

/// What visipassd keeps about a paired phone, sealed in the vault (the vault
/// seals it; this is the plaintext).
#[derive(Clone, Debug)]
pub struct Pairing {
    pub pairing_id: PairingId,
    pub name: String,
    pub sign_p: PublicKey,
    pub kem_p: PublicKey,
    pub kem_d: DaemonKey,
    pub push_token: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub created: u64,
}

const PAIRING: &str = "VisiPass phone pairing record";

impl Pairing {
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let kem_d = self.kem_d.to_bytes();
        Zeroizing::new(ad(
            PAIRING,
            &[
                Part::Bytes(&self.pairing_id),
                Part::Text(&self.name),
                Part::Bytes(&self.sign_p),
                Part::Bytes(&self.kem_p),
                Part::Bytes(kem_d.as_ref()),
                Part::Bytes(&self.push_token),
                Part::Uint(self.created),
            ],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [pairing_id, name, sign_p, kem_p, kem_d, push_token, created] = parts(PAIRING, bytes)?;
        Ok(Self {
            pairing_id: pairing_id.fixed()?,
            name: name.text()?.into(),
            sign_p: sign_p.fixed()?,
            kem_p: kem_p.fixed()?,
            kem_d: DaemonKey::from_bytes(kem_d.bytes()?)?,
            push_token: push_token.bytes()?.to_vec(),
            created: created.uint()?,
        })
    }
}
