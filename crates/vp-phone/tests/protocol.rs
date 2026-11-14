//! The phone-approvals protocol end to end, with a software phone standing in
//! for the Secure Enclave keys.

use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use p256::ecdsa::signature::Signer;
use vp_phone::*;

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

const NOW: u64 = 1_800_000_000;

struct SoftPhone {
    sign: p256::ecdsa::SigningKey,
    kem: <Kem as hpke::Kem>::PrivateKey,
    n_p: [u8; 32],
}

impl SoftPhone {
    fn new() -> Self {
        Self {
            sign: p256::ecdsa::SigningKey::from_slice(&vp_crypto::random::<32>()).unwrap(),
            kem: Kem::derive_keypair(&vp_crypto::random::<32>()).0,
            n_p: vp_crypto::random(),
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

    fn body(&self) -> Phone {
        Phone {
            name: "Robert's iPhone".into(),
            sign_p: self.sign_p(),
            kem_p: self.kem_p(),
            n_p: self.n_p,
            push_token: vec![],
        }
    }

    fn commit(&self, invite: &Invite) -> Commit {
        Commit::new(
            invite,
            commitment(&invite.pairing_id, &self.sign_p(), &self.kem_p(), &self.n_p),
        )
    }

    fn reveal(&self, invite: &Invite, phone: &Phone) -> Reveal {
        let body = phone.encode();
        Reveal {
            pairing_id: invite.pairing_id,
            sealed: Reveal::seal(invite, &body).unwrap(),
            signature: self.sign(&Phone::signed_bytes(&invite.pairing_id, &body)),
        }
    }

    /// What the app does with CryptoKit: open with `kem_P`, from `kem_D` only.
    fn open(&self, request: &SealedRequest, kem_d: &PublicKey) -> Result<Vec<u8>, hpke::HpkeError> {
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&request.sealed.enc)?;
        let sender = <Kem as hpke::Kem>::PublicKey::from_bytes(kem_d)?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Auth(sender),
            &self.kem,
            &enc,
            &Request::info(&request.pairing_id),
            &request.sealed.ciphertext,
            &[],
        )
    }

    fn answer(&self, pairing_id: &PairingId, answer: &Answer) -> SignedAnswer {
        let bytes = answer.encode();
        SignedAnswer {
            pairing_id: *pairing_id,
            signature: self.sign(&Answer::signed_bytes(pairing_id, &bytes)),
            answer: bytes,
        }
    }
}

struct Paired {
    daemon: DaemonKey,
    invite: Invite,
    phone: SoftPhone,
}

fn paired() -> Paired {
    let daemon = DaemonKey::generate();
    let invite = Invite::new("https://desk.tail1234.ts.net".into(), daemon.public());
    let phone = SoftPhone::new();
    let commit = phone.commit(&invite);
    phone
        .reveal(&invite, &phone.body())
        .open(&daemon, &invite, &commit)
        .unwrap();
    Paired {
        daemon,
        invite,
        phone,
    }
}

fn prompt() -> Prompt {
    Prompt {
        who: "Claude Code".into(),
        action: "inject 1 secret into a command".into(),
        details: vec![("Project".into(), "~/Code/visipass".into())],
        secrets: vec!["vp://Dev/Stripe/secret key".into()],
        purpose: Some("Run the billing tests".into()),
        paste: None,
    }
}

fn approve(p: &Paired) -> (Request, Vec<u8>, SealedRequest) {
    let request = Request::new(
        p.invite.pairing_id,
        Kind::Approve,
        prompt(),
        vec![Choice::Deny, Choice::Once, Choice::Task, Choice::Hours],
        NOW,
    );
    let body = request.encode();
    let sealed =
        SealedRequest::seal(&p.daemon, &p.phone.kem_p(), &p.invite.pairing_id, &body).unwrap();
    (request, body, sealed)
}

#[test]
fn pairing_end_to_end() {
    let daemon = DaemonKey::generate();
    let invite = Invite::new("https://desk.tail1234.ts.net".into(), daemon.public());

    // The QR code, as the phone reads it.
    let scanned = Invite::parse(&invite.uri()).unwrap();
    assert!(scanned == invite);

    let phone = SoftPhone::new();
    let commit = Commit::decode(&phone.commit(&scanned).encode()).unwrap();
    commit.check(&invite).unwrap();

    let nonce = Nonce {
        pairing_id: invite.pairing_id,
        n_d: vp_crypto::random(),
    };
    let nonce = Nonce::decode(&nonce.encode()).unwrap();

    let mut body = phone.body();
    body.push_token = b"relay token".to_vec();
    let reveal = Reveal::decode(&phone.reveal(&scanned, &body).encode()).unwrap();
    let revealed = reveal.open(&daemon, &invite, &commit).unwrap();
    assert_eq!(revealed, body);

    let on_phone = pairing_code(&scanned.pairing_id, &scanned.kem_d, &body, &nonce.n_d);
    let on_computer = pairing_code(&invite.pairing_id, &daemon.public(), &revealed, &nonce.n_d);
    assert_eq!(on_phone, on_computer);
    assert_eq!(on_phone.len(), 6);
    assert!(on_phone.bytes().all(|b| b.is_ascii_digit()));
}

#[test]
fn the_invite_is_only_an_https_endpoint_and_never_printed() {
    let daemon = DaemonKey::generate();
    let invite = Invite::new("http://desk.local".into(), daemon.public());
    assert!(Invite::parse(&invite.uri()).is_err());
    assert!(Invite::parse("https://visipass.app").is_err());
    assert!(Invite::parse("visipass-pair:!!").is_err());
    let invite = Invite::new("https://desk.tail1234.ts.net".into(), daemon.public());
    assert!(!format!("{invite:?}").contains("secret"));
}

#[test]
fn a_commit_needs_the_qr_codes_secret() {
    let daemon = DaemonKey::generate();
    let invite = Invite::new("https://desk.tail1234.ts.net".into(), daemon.public());
    let mut guess = invite.clone();
    guess.secret = zeroize::Zeroizing::new([7; 32]);
    let phone = SoftPhone::new();
    assert!(phone.commit(&guess).check(&invite).is_err());

    let mut commit = phone.commit(&invite);
    commit.commitment[0] ^= 1;
    assert!(commit.check(&invite).is_err());
}

#[test]
fn a_reveal_must_match_the_commit_and_be_signed_by_its_key() {
    let daemon = DaemonKey::generate();
    let invite = Invite::new("https://desk.tail1234.ts.net".into(), daemon.public());
    let phone = SoftPhone::new();
    let commit = phone.commit(&invite);

    // Other keys than committed to: someone who saw n_D trying new keys.
    let other = SoftPhone::new();
    assert!(
        other
            .reveal(&invite, &other.body())
            .open(&daemon, &invite, &commit)
            .is_err()
    );

    // The committed body, signed by another key.
    let body = phone.body().encode();
    let forged = Reveal {
        pairing_id: invite.pairing_id,
        sealed: Reveal::seal(&invite, &body).unwrap(),
        signature: other.sign(&Phone::signed_bytes(&invite.pairing_id, &body)),
    };
    assert!(forged.open(&daemon, &invite, &commit).is_err());

    // Sealed without the QR code's secret.
    let mut guess = invite.clone();
    guess.secret = zeroize::Zeroizing::new([7; 32]);
    assert!(
        phone
            .reveal(&guess, &phone.body())
            .open(&daemon, &invite, &commit)
            .is_err()
    );

    // Sealed to another computer.
    let elsewhere = DaemonKey::generate();
    assert!(
        phone
            .reveal(&invite, &phone.body())
            .open(&elsewhere, &invite, &commit)
            .is_err()
    );

    // An empty or overlong name.
    for name in ["", "   ", &"x".repeat(65)] {
        let mut body = phone.body();
        body.name = name.into();
        assert!(
            phone
                .reveal(&invite, &body)
                .open(&daemon, &invite, &commit)
                .is_err()
        );
    }
}

#[test]
fn the_code_changes_with_every_input() {
    let daemon = DaemonKey::generate();
    let phone = SoftPhone::new();
    let (id, n_d) = ([1; 16], [2; 32]);
    let code = pairing_code(&id, &daemon.public(), &phone.body(), &n_d);
    assert_ne!(
        code,
        pairing_code(&[3; 16], &daemon.public(), &phone.body(), &n_d)
    );
    assert_ne!(
        code,
        pairing_code(&id, &DaemonKey::generate().public(), &phone.body(), &n_d)
    );
    assert_ne!(
        code,
        pairing_code(&id, &daemon.public(), &SoftPhone::new().body(), &n_d)
    );
    assert_ne!(
        code,
        pairing_code(&id, &daemon.public(), &phone.body(), &[4; 32])
    );
}

#[test]
fn the_daemon_key_survives_the_pairing_record() {
    let daemon = DaemonKey::generate();
    let again = DaemonKey::from_bytes(daemon.to_bytes().as_ref()).unwrap();
    assert_eq!(again.public(), daemon.public());
    assert_eq!(format!("{daemon:?}"), "DaemonKey(..)");
    assert!(DaemonKey::from_bytes(&[0; 32]).is_err());
}

#[test]
fn a_request_opens_on_its_phone_from_its_daemon_only() {
    let p = paired();
    let (request, body, sealed) = approve(&p);

    let pending = decode_pending(&encode_pending(std::slice::from_ref(&sealed))).unwrap();
    let opened = p.phone.open(&pending[0], &p.daemon.public()).unwrap();
    assert_eq!(opened, body);
    assert_eq!(Request::decode(&opened).unwrap(), request);

    // Sealed by anything but this pairing's visipassd: a node on the tailnet,
    // the relay, an agent on the computer.
    let impostor = DaemonKey::generate();
    let forged =
        SealedRequest::seal(&impostor, &p.phone.kem_p(), &p.invite.pairing_id, &body).unwrap();
    assert!(p.phone.open(&forged, &p.daemon.public()).is_err());

    // Moved to another pairing id.
    let mut moved = sealed.clone();
    moved.pairing_id = [9; 16];
    assert!(p.phone.open(&moved, &p.daemon.public()).is_err());

    // Not readable by another phone.
    assert!(SoftPhone::new().open(&sealed, &p.daemon.public()).is_err());
}

#[test]
fn a_prompt_round_trips() {
    let mut prompt = prompt();
    for purpose in [None, Some("why".to_string())] {
        for paste in [None, Some(("Stripe".to_string(), "Dev".to_string()))] {
            prompt.purpose = purpose.clone();
            prompt.paste = paste;
            let request = Request::new(
                [1; 16],
                Kind::Paste,
                prompt.clone(),
                vec![Choice::Deny],
                NOW,
            );
            assert_eq!(Request::decode(&request.encode()).unwrap(), request);
        }
    }
    assert_eq!(
        Request::decode(
            &Request::new([1; 16], Kind::Approve, Prompt::default(), vec![], NOW).encode()
        )
        .unwrap()
        .expires_at,
        NOW + ANSWER_SECS
    );
}

#[test]
fn an_answer_is_accepted_only_signed_and_exact() {
    let p = paired();
    let (request, body, _) = approve(&p);
    let id = p.invite.pairing_id;
    let answer = Answer {
        request_id: request.request_id,
        request_hash: Request::hash(&body),
        choice: Choice::Task,
        value: None,
    };

    let wire = SignedAnswer::decode(&p.phone.answer(&id, &answer).encode()).unwrap();
    let verified = wire.verify(&p.phone.sign_p()).unwrap();
    assert_eq!(verified, answer);
    verified.check(&request, &body, NOW + 10).unwrap();

    // Check 1: signed by sign_P, over exactly these bytes, for this pairing.
    assert!(wire.verify(&SoftPhone::new().sign_p()).is_err());
    let mut tampered = wire.clone();
    *tampered.answer.last_mut().unwrap() ^= 1;
    assert!(tampered.verify(&p.phone.sign_p()).is_err());
    let mut moved = wire.clone();
    moved.pairing_id = [9; 16];
    assert!(moved.verify(&p.phone.sign_p()).is_err());
    assert!(
        SoftPhone::new()
            .answer(&id, &answer)
            .verify(&p.phone.sign_p())
            .is_err()
    );

    // Check 2: this request, these bytes.
    let (other, other_body, _) = approve(&p);
    assert!(answer.check(&other, &other_body, NOW).is_err());
    let mut edited = body.clone();
    edited.push(0);
    assert!(answer.check(&request, &edited, NOW).is_err());

    // Check 3: not expired.
    assert!(answer.check(&request, &body, request.expires_at).is_err());

    // Check 4: a choice it was offered. "Always" does not exist here at all.
    let mut once_only = request.clone();
    once_only.choices = vec![Choice::Deny, Choice::Once];
    let once_body = once_only.encode();
    let task = Answer {
        request_hash: Request::hash(&once_body),
        ..answer.clone()
    };
    assert!(task.check(&once_only, &once_body, NOW).is_err());
    assert!(Choice::parse("always").is_err());

    // An approval carries no value.
    let with_value = Answer {
        value: Some(
            Answer::seal_value(&p.daemon.public(), &id, &answer.request_hash, b"x").unwrap(),
        ),
        ..answer.clone()
    };
    assert!(with_value.check(&request, &body, NOW).is_err());
}

#[test]
fn a_pasted_value_opens_only_for_its_request() {
    let p = paired();
    let id = p.invite.pairing_id;
    let mut prompt = prompt();
    prompt.paste = Some(("Stripe".into(), "Dev".into()));
    let request = Request::new(
        id,
        Kind::Paste,
        prompt,
        vec![Choice::Deny, Choice::Once],
        NOW,
    );
    let body = request.encode();
    let hash = Request::hash(&body);

    let answer = Answer {
        request_id: request.request_id,
        request_hash: hash,
        choice: Choice::Once,
        value: Some(
            Answer::seal_value(&p.daemon.public(), &id, &hash, b"sk_live_SENTINEL").unwrap(),
        ),
    };
    let verified = p
        .phone
        .answer(&id, &answer)
        .verify(&p.phone.sign_p())
        .unwrap();
    verified.check(&request, &body, NOW).unwrap();
    assert_eq!(
        verified
            .open_value(&p.daemon, &id)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"sk_live_SENTINEL"
    );

    // A value sealed for another request, moved into this answer.
    let moved = Answer {
        value: Some(Answer::seal_value(&p.daemon.public(), &id, &[0; 32], b"other").unwrap()),
        ..answer.clone()
    };
    assert!(moved.open_value(&p.daemon, &id).is_err());
    assert!(answer.open_value(&DaemonKey::generate(), &id).is_err());

    // Paste "once" with no value; Deny needs none.
    let empty = Answer {
        value: None,
        ..answer.clone()
    };
    assert!(empty.check(&request, &body, NOW).is_err());
    let deny = Answer {
        choice: Choice::Deny,
        value: None,
        ..answer
    };
    deny.check(&request, &body, NOW).unwrap();
    assert!(deny.open_value(&p.daemon, &id).unwrap().is_none());
}

#[test]
fn decoding_refuses_anything_but_the_exact_encoding() {
    let p = paired();
    let (_, body, sealed) = approve(&p);
    let pending = encode_pending(&[sealed]);

    for bytes in [&body[..], &pending[..]] {
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Request::decode(&trailing).is_err());
        assert!(decode_pending(&trailing).is_err());
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(Request::decode(&bytes[..cut]).is_err());
            assert!(decode_pending(&bytes[..cut]).is_err());
        }
    }
    // Each message only under its own label.
    assert!(Answer::decode(&body).is_err());
    assert!(Commit::decode(&body).is_err());
    // Over the endpoint's limit, before decoding.
    let huge = Request::new(
        [1; 16],
        Kind::Approve,
        Prompt {
            who: "x".repeat(MAX_MESSAGE),
            ..prompt()
        },
        vec![],
        NOW,
    );
    assert!(Request::decode(&huge.encode()).is_err());
}

// ---- RFC 9180 test vectors for this suite ------------------------------------

#[derive(serde::Deserialize)]
struct Vector {
    mode: u8,
    info: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "pkRm")]
    pk_r: String,
    psk: Option<String>,
    psk_id: Option<String>,
    #[serde(rename = "pkSm")]
    pk_s: Option<String>,
    enc: String,
    encryptions: Vec<Encryption>,
}

#[derive(serde::Deserialize)]
struct Encryption {
    aad: String,
    ct: String,
    pt: String,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 in all four modes
/// (RFC 9180 A.5, from the CFRG's test-vectors.json): the suite CryptoKit uses
/// on the phone, decrypted here as visipassd will.
#[test]
fn rfc9180_vectors() {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("rfc9180.json")).unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let v: Vector = serde_json::from_value(vector).unwrap();
        let (sk, pk) = Kem::derive_keypair(&hex(&v.ikm_r));
        assert_eq!(pk.to_bytes().as_slice(), hex(&v.pk_r));
        let (psk, psk_id) = (
            hex(v.psk.as_deref().unwrap_or("")),
            hex(v.psk_id.as_deref().unwrap_or("")),
        );
        let bundle = hpke::PskBundle::new(&psk, &psk_id).unwrap();
        let sender = v
            .pk_s
            .as_deref()
            .map(|s| <Kem as hpke::Kem>::PublicKey::from_bytes(&hex(s)).unwrap());
        let mode = match (v.mode, sender) {
            (0, None) => OpModeR::Base,
            (1, None) => OpModeR::Psk(bundle),
            (2, Some(s)) => OpModeR::Auth(s),
            (3, Some(s)) => OpModeR::AuthPsk(s, bundle),
            _ => panic!("unexpected vector"),
        };
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(&v.enc)).unwrap();
        let mut ctx =
            hpke::setup_receiver::<Aead, Kdf, Kem>(&mode, &sk, &enc, &hex(&v.info)).unwrap();
        for e in v.encryptions {
            assert_eq!(ctx.open(&hex(&e.ct), &hex(&e.aad)).unwrap(), hex(&e.pt));
        }
    }
}
