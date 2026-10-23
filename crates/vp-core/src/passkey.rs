//! Passkeys (WebAuthn credentials) that VisiPass creates and uses for web
//! pages: the relying-party check, the client data and authenticator data a
//! site verifies, and P-256 keys. Pure; the private key's home is the native
//! vault, and only visipassd calls [`Key::sign`].
//!
//! What a site sees: attestation "none", a fixed AAGUID, the "backup eligible"
//! and "backed up" flags (passkeys sync through the vault), user presence and
//! user verification (an unlocked VisiPass and a click on its own card), and a
//! signature counter of 0, as synced passkeys report, since copies on several
//! devices cannot keep one counter.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Failure;
use crate::model::PasskeyInfo;
use serde::{Deserialize, Serialize};

/// Identifies VisiPass as the authenticator to sites that look (fixed, random).
pub const AAGUID: [u8; 16] = [
    0x10, 0x5f, 0xa2, 0x4a, 0x9f, 0xb9, 0x40, 0x85, 0xa4, 0x36, 0xf8, 0x80, 0xb7, 0x6f, 0x5a, 0x60,
];

/// COSE algorithm ES256 (ECDSA with P-256 and SHA-256), the only one offered.
pub const ES256: i64 = -7;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, Failure> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| Failure::new("Not base64url"))
}

/// The origin a page's request comes from (`https://login.example.com`, with
/// a port only when it is not the default), and its host. Only https pages, and
/// http on localhost as browsers allow; never a URL carrying credentials.
pub fn origin_of(url: &str) -> Result<(String, String), Failure> {
    let parsed = url::Url::parse(url).map_err(|_| Failure::new("Not a web page"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Failure::new("Not a web page"));
    }
    let host = match parsed.host() {
        Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
        _ => return Err(Failure::new("Passkeys need a website with a domain name")),
    };
    let local = host == "localhost" || host.ends_with(".localhost");
    match parsed.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return Err(Failure::new("Passkeys work only on https pages")),
    }
    Ok((parsed.origin().ascii_serialization(), host))
}

/// Checks that a page on `host` may use passkeys for `rp_id`: the RP ID is the
/// host itself or a registrable parent of it (`example.com` from
/// `login.example.com`), never a public suffix (`com`, `github.io`).
pub fn check_rp_id(host: &str, rp_id: &str) -> Result<String, Failure> {
    let rp_id = rp_id.trim().trim_end_matches('.').to_ascii_lowercase();
    let refuse = || {
        Failure::new(format!(
            "This page ({host}) cannot use passkeys for \"{rp_id}\""
        ))
    };
    if rp_id.is_empty() || !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return Err(refuse());
    }
    let local = rp_id == "localhost" || rp_id.ends_with(".localhost");
    if !local && psl::domain_str(&rp_id).is_none() {
        return Err(refuse());
    }
    Ok(rp_id)
}

/// The JSON the browser would build and the site checks, with keys in the
/// order browsers use. `top_origin` only for a request from a cross-origin frame.
pub fn client_data(
    kind: Ceremony,
    challenge: &str,
    origin: &str,
    top_origin: Option<&str>,
) -> String {
    let text = |s: &str| serde_json::to_string(s).expect("strings serialise");
    let mut json = format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":{}",
        text(kind.name()),
        text(challenge),
        text(origin),
        top_origin.is_some()
    );
    if let Some(top) = top_origin {
        json.push_str(&format!(",\"topOrigin\":{}", text(top)));
    }
    json.push('}');
    json
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

impl Ceremony {
    fn name(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

/// Authenticator data: SHA-256 of the RP ID, flags, a zero counter and, when
/// creating, the attested credential (AAGUID, ID and COSE public key).
pub fn authenticator_data(rp_id: &str, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(UP | UV | BE | BS | if attested.is_some() { AT } else { 0 });
    out.extend_from_slice(&0u32.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}` in canonical CBOR.
pub fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    out.push(0xa0);
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

// The few CBOR items WebAuthn needs: small integers, text and byte strings.
fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        cbor_head(out, 0, n as u64);
    } else {
        cbor_head(out, 1, (-1 - n) as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// A passkey's P-256 private key. Zeroed when dropped.
pub struct Key(SigningKey);

impl Key {
    pub fn generate() -> Result<Self, Failure> {
        // Rejection-sample a valid scalar from the OS generator.
        for _ in 0..16 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| Failure::new("No randomness available"))?;
            if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
                return Ok(Self(key));
            }
        }
        Err(Failure::new("Could not make a passkey"))
    }

    /// The 32-byte private scalar, base64url, as the vault stores it.
    pub fn export(&self) -> Zeroizing<String> {
        Zeroizing::new(b64(&self.0.to_bytes()))
    }

    pub fn import(stored: &str) -> Result<Self, Failure> {
        let bytes = Zeroizing::new(unb64(stored)?);
        SigningKey::from_slice(&bytes)
            .map(Self)
            .map_err(|_| Failure::new("This passkey's key is damaged"))
    }

    fn point(&self) -> ([u8; 32], [u8; 32]) {
        let encoded = self.0.verifying_key().to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(encoded.x().expect("uncompressed point"));
        y.copy_from_slice(encoded.y().expect("uncompressed point"));
        (x, y)
    }

    /// The public key as a COSE_Key map (EC2, ES256, P-256), keys in canonical order.
    pub fn cose_public(&self) -> Vec<u8> {
        let (x, y) = self.point();
        let mut out = vec![0xa5];
        cbor_int(&mut out, 1); // kty
        cbor_int(&mut out, 2); // EC2
        cbor_int(&mut out, 3); // alg
        cbor_int(&mut out, ES256);
        cbor_int(&mut out, -1); // crv
        cbor_int(&mut out, 1); // P-256
        cbor_int(&mut out, -2);
        cbor_bytes(&mut out, &x);
        cbor_int(&mut out, -3);
        cbor_bytes(&mut out, &y);
        out
    }

    /// The public key as DER SubjectPublicKeyInfo, for the page's getPublicKey().
    pub fn spki(&self) -> Vec<u8> {
        // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04‖x‖y }
        const PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let (x, y) = self.point();
        let mut out = PREFIX.to_vec();
        out.push(0x04);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        out
    }

    /// Signs authenticator data and the client data's hash: the assertion
    /// signature, DER-encoded as WebAuthn wants for ES256.
    pub fn sign(&self, auth_data: &[u8], client_data: &str) -> Vec<u8> {
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let signature: Signature = self.0.sign(&message);
        signature.to_der().as_bytes().to_vec()
    }
}

/// A new credential ID: 16 random bytes, base64url.
pub fn new_credential_id() -> Result<String, Failure> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Failure::new("No randomness available"))?;
    Ok(b64(&bytes))
}

// ---- Ceremonies -----------------------------------------------------------

/// A page asking for a new passkey, after visipassd has checked its origin
/// and RP ID. Every field is public: the user handle is the site's opaque ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Creation {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_origin: Option<String>,
    pub rp_id: String,
    pub challenge: String,
    /// base64url, as the site gave it.
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    /// The vault the passkey goes into.
    pub vault: String,
    /// An existing login to add it to; otherwise a new login is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
}

/// A page asking to sign in with one passkey, after visipassd's checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_origin: Option<String>,
    pub rp_id: String,
    pub challenge: String,
    pub credential_id: String,
}

/// What the page's `navigator.credentials.create()` resolves with. All base64url.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
    pub public_key_algorithm: i64,
    /// Where the passkey was saved.
    pub item: String,
    pub vault: String,
}

/// What the page's `navigator.credentials.get()` resolves with. All base64url.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

/// A saved passkey for a site, with the login that holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Found {
    #[serde(flatten)]
    pub passkey: PasskeyInfo,
    pub item: String,
    pub vault: String,
    pub title: String,
}

/// Builds a new credential's response from its key.
pub fn register(
    key: &Key,
    credential_id: &str,
    creation: &Creation,
    item: &str,
    vault: &str,
) -> Result<Registration, Failure> {
    let id = unb64(credential_id)?;
    let cose = key.cose_public();
    let auth = authenticator_data(&creation.rp_id, Some((&id, &cose)));
    let client = client_data(
        Ceremony::Create,
        &creation.challenge,
        &creation.origin,
        creation.top_origin.as_deref(),
    );
    Ok(Registration {
        credential_id: credential_id.to_string(),
        client_data_json: b64(client.as_bytes()),
        attestation_object: b64(&attestation_object(&auth)),
        authenticator_data: b64(&auth),
        public_key: b64(&key.spki()),
        public_key_algorithm: ES256,
        item: item.to_string(),
        vault: vault.to_string(),
    })
}

/// Signs a sign-in with the passkey's key.
pub fn assert(key: &Key, request: &Request, user_handle: &str) -> Assertion {
    let auth = authenticator_data(&request.rp_id, None);
    let client = client_data(
        Ceremony::Get,
        &request.challenge,
        &request.origin,
        request.top_origin.as_deref(),
    );
    Assertion {
        credential_id: request.credential_id.clone(),
        client_data_json: b64(client.as_bytes()),
        signature: b64(&key.sign(&auth, &client)),
        authenticator_data: b64(&auth),
        user_handle: user_handle.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn rp_id_must_be_the_host_or_a_registrable_parent() {
        assert_eq!(
            check_rp_id("login.example.com", "example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            check_rp_id("example.com", "EXAMPLE.com.").unwrap(),
            "example.com"
        );
        assert!(check_rp_id("example.com", "login.example.com").is_err());
        assert!(check_rp_id("evilexample.com", "example.com").is_err());
        assert!(check_rp_id("example.com", "com").is_err());
        // A private-section public suffix: one github.io site cannot claim all of them.
        assert!(check_rp_id("me.github.io", "github.io").is_err());
        assert!(check_rp_id("example.com", "").is_err());
        assert_eq!(check_rp_id("localhost", "localhost").unwrap(), "localhost");
    }

    #[test]
    fn origins_are_https_or_local_http_with_a_domain() {
        assert_eq!(
            origin_of("https://Login.Example.com/path?q=1").unwrap(),
            (
                "https://login.example.com".into(),
                "login.example.com".into()
            )
        );
        assert_eq!(
            origin_of("https://example.com:8443/").unwrap().0,
            "https://example.com:8443"
        );
        assert_eq!(
            origin_of("http://localhost:3000/").unwrap().0,
            "http://localhost:3000"
        );
        assert!(origin_of("http://example.com/").is_err());
        assert!(origin_of("https://user:pw@example.com/").is_err());
        assert!(origin_of("https://192.168.1.1/").is_err());
        assert!(origin_of("file:///etc/passwd").is_err());
    }

    #[test]
    fn client_data_matches_what_browsers_send() {
        assert_eq!(
            client_data(Ceremony::Get, "abc", "https://example.com", None),
            r#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com","crossOrigin":false}"#
        );
        assert_eq!(
            client_data(
                Ceremony::Create,
                "a\"b",
                "https://x.example.com",
                Some("https://top.test")
            ),
            r#"{"type":"webauthn.create","challenge":"a\"b","origin":"https://x.example.com","crossOrigin":true,"topOrigin":"https://top.test"}"#
        );
    }

    #[test]
    fn a_created_passkey_verifies_as_a_site_would_check_it() {
        let key = Key::generate().unwrap();
        let credential_id = unb64(&new_credential_id().unwrap()).unwrap();
        let cose = key.cose_public();
        let auth = authenticator_data("example.com", Some((&credential_id, &cose)));
        let object = attestation_object(&auth);

        // Decode with an independent CBOR implementation.
        let parsed: serde_cbor_2::Value = serde_cbor_2::from_slice(&object).unwrap();
        let serde_cbor_2::Value::Map(map) = parsed else {
            panic!("not a map")
        };
        let get = |k: &str| map.get(&serde_cbor_2::Value::Text(k.into())).cloned();
        assert_eq!(get("fmt"), Some(serde_cbor_2::Value::Text("none".into())));
        assert_eq!(
            get("attStmt"),
            Some(serde_cbor_2::Value::Map(Default::default()))
        );
        let Some(serde_cbor_2::Value::Bytes(auth_back)) = get("authData") else {
            panic!()
        };
        assert_eq!(auth_back, auth);

        // rpIdHash, flags UP|UV|BE|BS|AT, counter 0, AAGUID, credential ID.
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth[32], 0x5d);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(
            u16::from_be_bytes([auth[53], auth[54]]) as usize,
            credential_id.len()
        );
        assert_eq!(
            &auth[55..55 + credential_id.len()],
            credential_id.as_slice()
        );

        // The COSE key decodes to the same point as the SPKI.
        let cose_back: serde_cbor_2::Value =
            serde_cbor_2::from_slice(&auth[55 + credential_id.len()..]).unwrap();
        let serde_cbor_2::Value::Map(cose_map) = cose_back else {
            panic!()
        };
        let int = |n: i128| cose_map.get(&serde_cbor_2::Value::Integer(n)).cloned();
        assert_eq!(int(1), Some(serde_cbor_2::Value::Integer(2)));
        assert_eq!(int(3), Some(serde_cbor_2::Value::Integer(-7)));
        assert_eq!(int(-1), Some(serde_cbor_2::Value::Integer(1)));
        let (Some(serde_cbor_2::Value::Bytes(x)), Some(serde_cbor_2::Value::Bytes(y))) =
            (int(-2), int(-3))
        else {
            panic!()
        };
        let spki = key.spki();
        assert_eq!(&spki[27..59], x.as_slice());
        assert_eq!(&spki[59..91], y.as_slice());

        // An assertion verifies against that public key, and not for other data.
        let client = client_data(Ceremony::Get, "Y2hhbGxlbmdl", "https://example.com", None);
        let assertion_auth = authenticator_data("example.com", None);
        assert_eq!(assertion_auth.len(), 37);
        assert_eq!(assertion_auth[32], 0x1d);
        let signature = Signature::from_der(&key.sign(&assertion_auth, &client)).unwrap();
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let verifying = VerifyingKey::from_sec1_bytes(&point).unwrap();
        let mut message = assertion_auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        verifying.verify(&message, &signature).unwrap();
        let other = client_data(Ceremony::Get, "b3RoZXI", "https://example.com", None);
        let mut wrong = assertion_auth.clone();
        wrong.extend_from_slice(&Sha256::digest(other.as_bytes()));
        assert!(verifying.verify(&wrong, &signature).is_err());

        // The stored form round-trips to the same key.
        let again = Key::import(&key.export()).unwrap();
        assert_eq!(again.spki(), key.spki());
    }
}
