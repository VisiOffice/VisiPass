//! VisiPass cryptography, as specified in `docs/crypto-design.md` (section numbers
//! below refer to it). Pure functions over bytes: no I/O, no storage.
//!
//! Every key type erases itself on drop and has no `Display`; `Debug` prints a
//! placeholder.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The format version in every associated-data string and ciphertext header.
pub const FORMAT: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Bytes from the OS CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the OS random number generator failed");
    out
}

// ---- Keys --------------------------------------------------------------

/// A 256-bit symmetric key.
pub struct Key(Zeroizing<[u8; 32]>);

impl Key {
    pub fn random() -> Self {
        Self(Zeroizing::new(random()))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error("bad key length"))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// HKDF-Expand with this key as the pseudorandom key.
    pub fn expand(&self, info: &[u8]) -> Key {
        let hkdf = Hkdf::<Sha256>::from_prk(self.expose()).expect("32 bytes is a valid PRK");
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf.expand(info, out.as_mut())
            .expect("32 bytes is a valid output length");
        Key(out)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

// ---- §2.1 Encodings ----------------------------------------------------

/// One element of a deterministic CBOR array (RFC 8949 §4.2).
pub enum Part<'a> {
    Text(&'a str),
    Uint(u64),
    Bytes(&'a [u8]),
    List(Vec<Part<'a>>),
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.extend([major | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend(n.to_be_bytes());
    }
}

fn encode_part(out: &mut Vec<u8>, part: &Part) {
    match part {
        Part::Uint(n) => head(out, 0, *n),
        Part::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Part::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Part::List(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_part(out, item);
            }
        }
    }
}

/// `AD(label, parts...)`: the CBOR array `[label, FORMAT, parts...]`.
pub fn ad(label: &str, parts: &[Part]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, 4, 2 + parts.len() as u64);
    encode_part(&mut out, &Part::Text(label));
    encode_part(&mut out, &Part::Uint(FORMAT));
    for part in parts {
        encode_part(&mut out, part);
    }
    out
}

/// A decoded element of the CBOR subset [`Part`] writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Uint(u64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
}

impl Value {
    pub fn uint(&self) -> Result<u64> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(Error("expected a number")),
        }
    }

    pub fn bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error("expected bytes")),
        }
    }

    pub fn fixed<const N: usize>(&self) -> Result<[u8; N]> {
        self.bytes()?
            .try_into()
            .map_err(|_| Error("bytes of the wrong length"))
    }

    pub fn text(&self) -> Result<&str> {
        match self {
            Value::Text(t) => Ok(t),
            _ => Err(Error("expected text")),
        }
    }

    pub fn list(&self) -> Result<&[Value]> {
        match self {
            Value::List(l) => Ok(l),
            _ => Err(Error("expected a list")),
        }
    }
}

const MALFORMED: Error = Error("malformed encoding");

fn decode_value(input: &mut &[u8], depth: usize) -> Result<Value> {
    if depth > 16 {
        return Err(MALFORMED);
    }
    let (&first, rest) = input.split_first().ok_or(MALFORMED)?;
    *input = rest;
    let (major, info) = (first >> 5, first & 31);
    let take = |input: &mut &[u8], n: usize| -> Result<u64> {
        if input.len() < n {
            return Err(MALFORMED);
        }
        let (bytes, rest) = input.split_at(n);
        *input = rest;
        Ok(bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
    };
    let n = match info {
        0..24 => info as u64,
        24 => take(input, 1)?,
        25 => take(input, 2)?,
        26 => take(input, 4)?,
        27 => take(input, 8)?,
        _ => return Err(MALFORMED),
    };
    // Deterministic encoding uses the shortest head; anything else is refused,
    // so every value has exactly one encoding.
    let mut canonical = Vec::new();
    head(&mut canonical, major, n);
    if canonical[0] != first {
        return Err(MALFORMED);
    }
    let length = |input: &&[u8]| -> Result<usize> {
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= input.len())
            .ok_or(MALFORMED)
    };
    Ok(match major {
        0 => Value::Uint(n),
        2 | 3 => {
            let len = length(input)?;
            let (bytes, rest) = input.split_at(len);
            *input = rest;
            if major == 2 {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(
                    std::str::from_utf8(bytes)
                        .map_err(|_| MALFORMED)?
                        .to_string(),
                )
            }
        }
        4 => {
            // Each element takes at least one byte.
            let count = length(input)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value(input, depth + 1)?);
            }
            Value::List(items)
        }
        _ => return Err(MALFORMED),
    })
}

/// Reads what [`ad`] wrote under `label`: the parts after the label and format
/// version. Refuses another label, another format, or trailing bytes.
pub fn decode(label: &str, bytes: &[u8]) -> Result<Vec<Value>> {
    let mut input = bytes;
    let value = decode_value(&mut input, 0)?;
    if !input.is_empty() {
        return Err(MALFORMED);
    }
    let Value::List(mut items) = value else {
        return Err(MALFORMED);
    };
    if items.len() < 2 || items[0] != Value::Text(label.into()) || items[1] != Value::Uint(FORMAT) {
        return Err(Error("unexpected label or format"));
    }
    Ok(items.split_off(2))
}

/// `SHA-256(AD(label, parts...))`.
pub fn hash(label: &str, parts: &[Part]) -> [u8; 32] {
    Sha256::digest(ad(label, parts)).into()
}

// ---- §4.1 Unlock -------------------------------------------------------

/// Argon2id parameters, stored in the clear with the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 4,
    };

    /// Refuses parameters outside the bounds before any work is done (§4.1).
    pub fn check(&self) -> Result<()> {
        let ok = (65_536..=2_097_152).contains(&self.m_kib)
            && (1..=10).contains(&self.t)
            && (1..=8).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(Error("password hashing parameters out of bounds"))
        }
    }

    pub fn part(&self) -> Part<'static> {
        Part::List(vec![
            Part::Uint(self.m_kib.into()),
            Part::Uint(self.t.into()),
            Part::Uint(self.p.into()),
        ])
    }
}

/// `pw_key = Argon2id(NFKD(password), salt, params)`.
pub fn password_key(password: &str, salt: &[u8; 16], params: &KdfParams) -> Result<Key> {
    params.check()?;
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|_| Error("password hashing parameters out of bounds"))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(normalized.as_bytes(), salt, out.as_mut())
        .map_err(|_| Error("password hashing failed"))?;
    Ok(Key(out))
}

/// `PRK = HKDF-Extract(salt = secret_key, ikm = pw_key)`; `AUK = HKDF-Expand(PRK, ...)`.
pub fn account_unlock_key(pw_key: &Key, secret_key: &SecretKey, account_id: &[u8; 16]) -> Key {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(secret_key.expose()), pw_key.expose());
    let prk = Key::from_slice(&prk).expect("SHA-256 output is 32 bytes");
    prk.expand(&ad(
        "VisiPass account unlock key",
        &[Part::Bytes(account_id)],
    ))
}

/// `HKDF-SHA-256(salt = recovery_key, ikm = account_id)` (§5.2).
pub fn recovery_wrap_key(recovery_key: &SecretKey, account_id: &[u8; 16]) -> Key {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(recovery_key.expose()), account_id);
    Key::from_slice(&prk)
        .expect("SHA-256 output is 32 bytes")
        .expand(&ad("VisiPass recovery", &[]))
}

// ---- §3 Secret Key -----------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128 random bits: the Secret Key, or a Recovery Key.
pub struct SecretKey(Zeroizing<[u8; 16]>);

impl SecretKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random()))
    }

    pub fn expose(&self) -> &[u8; 16] {
        &self.0
    }

    fn checksum(bytes: &[u8; 16]) -> u16 {
        let digest = Sha256::digest(bytes);
        u16::from_be_bytes([digest[0], digest[1]]) >> 6
    }

    /// `VP1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-CC`: 26 Crockford base32 characters
    /// (the first holds 3 bits) and a 10-bit checksum.
    pub fn display(&self) -> Zeroizing<String> {
        let n = u128::from_be_bytes(*self.0);
        let mut chars = Zeroizing::new(String::with_capacity(40));
        chars.push_str("VP1");
        for i in 0..26 {
            if i == 0 || i == 6 || (i > 6 && (i - 6) % 5 == 0) {
                chars.push('-');
            }
            let shift = 5 * (25 - i);
            chars.push(CROCKFORD[((n >> shift) & 31) as usize] as char);
        }
        let check = Self::checksum(&self.0);
        chars.push('-');
        chars.push(CROCKFORD[(check >> 5) as usize] as char);
        chars.push(CROCKFORD[(check & 31) as usize] as char);
        chars
    }

    /// Accepts the display form with any spacing, dashes or case; `I`/`L` read as 1, `O` as 0.
    pub fn parse(text: &str) -> Result<Self> {
        let cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(
            text.trim()
                .to_ascii_uppercase()
                .bytes()
                .filter(|b| !matches!(b, b'-' | b' '))
                .collect(),
        );
        let body = cleaned
            .strip_prefix(b"VP1")
            .ok_or(Error("not a VisiPass key"))?;
        if body.len() != 28 {
            return Err(Error("not a VisiPass key"));
        }
        let value = |b: u8| -> Result<u128> {
            let b = match b {
                b'I' | b'L' => b'1',
                b'O' => b'0',
                other => other,
            };
            CROCKFORD
                .iter()
                .position(|&c| c == b)
                .map(|v| v as u128)
                .ok_or(Error("not a VisiPass key"))
        };
        let mut n: u128 = 0;
        for (i, &b) in body[..26].iter().enumerate() {
            let v = value(b)?;
            if i == 0 && v > 7 {
                return Err(Error("not a VisiPass key"));
            }
            n = (n << 5) | v;
        }
        let bytes = Zeroizing::new(n.to_be_bytes());
        let check = ((value(body[26])? as u16) << 5) | value(body[27])? as u16;
        if check != Self::checksum(&bytes) {
            return Err(Error("that key has a typo: its checksum does not match"));
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

// ---- Sealing ----------------------------------------------------------

/// XChaCha20-Poly1305 with a random nonce: returns `nonce ‖ ciphertext`.
pub fn seal(key: &Key, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = random();
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("encryption of an in-memory buffer cannot fail");
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn open(key: &Key, ad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 24 + 16 {
        return Err(Error("ciphertext too short"));
    }
    let (nonce, ciphertext) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error("decryption failed: wrong key or tampered data"))
}

pub fn wrap(kek: &Key, ad: &[u8], key: &Key) -> Vec<u8> {
    seal(kek, ad, key.expose())
}

pub fn unwrap(kek: &Key, ad: &[u8], wrapped: &[u8]) -> Result<Key> {
    Key::from_slice(&open(kek, ad, wrapped)?)
}

// ---- §8.2 Padding -----------------------------------------------------

/// `u32 length ‖ data ‖ zeros`, to a multiple of 256 up to 4096, then a power of two.
pub fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let needed = 4 + data.len();
    let size = if needed <= 4096 {
        needed.div_ceil(256) * 256
    } else {
        needed.next_power_of_two()
    };
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(size, 0);
    out
}

pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let length = padded
        .get(..4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
        .ok_or(Error("padding is malformed"))?;
    padded
        .get(4..4 + length)
        .ok_or(Error("padding is malformed"))
}

// ---- Signatures -------------------------------------------------------

/// An Ed25519 signing key (the keyset's, §4.2).
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random::<32>());
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(seed.try_into().map_err(|_| Error("bad signing key"))?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (
        <[u8; 32]>::try_from(public),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else {
        return false;
    };
    key.verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: KdfParams = KdfParams {
        m_kib: 65_536,
        t: 1,
        p: 1,
    };

    #[test]
    fn decoding_reads_back_what_ad_wrote_and_nothing_else() {
        let bytes = ad(
            "l",
            &[
                Part::Uint(300),
                Part::Bytes(&[1, 2]),
                Part::List(vec![Part::Text("é"), Part::Uint(0)]),
            ],
        );
        assert_eq!(
            decode("l", &bytes).unwrap(),
            vec![
                Value::Uint(300),
                Value::Bytes(vec![1, 2]),
                Value::List(vec![Value::Text("é".into()), Value::Uint(0)]),
            ]
        );
        assert!(decode("other", &bytes).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode("l", &trailing).is_err());
        assert!(decode("l", &bytes[..bytes.len() - 1]).is_err());
        // A longer head than needed for 5 is not the deterministic encoding.
        assert!(decode("l", &[0x83, 0x61, b'l', 0x01, 0x18, 5]).is_err());
        // A list claiming more elements than there are bytes.
        assert!(decode("l", &[0x83, 0x61, b'l', 0x01, 0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn cbor_is_deterministic_and_unambiguous() {
        assert_eq!(ad("x", &[]), vec![0x82, 0x61, b'x', 0x01]);
        assert_ne!(
            ad("l", &[Part::Text("ab"), Part::Text("c")]),
            ad("l", &[Part::Text("a"), Part::Text("bc")])
        );
        let mut big = Vec::new();
        head(&mut big, 0, 500);
        assert_eq!(big, vec![0x19, 0x01, 0xf4]);
    }

    #[test]
    fn the_unlock_key_needs_both_secrets() {
        let salt = [7u8; 16];
        let account = [1u8; 16];
        let secret = SecretKey::from_bytes([9u8; 16]);
        let pw = password_key("correct horse", &salt, &CHEAP).unwrap();
        let auk = account_unlock_key(&pw, &secret, &account);
        let again = account_unlock_key(
            &password_key("correct horse", &salt, &CHEAP).unwrap(),
            &secret,
            &account,
        );
        assert_eq!(auk.expose(), again.expose());
        let other_secret = account_unlock_key(&pw, &SecretKey::from_bytes([8u8; 16]), &account);
        assert_ne!(auk.expose(), other_secret.expose());
        let other_password = account_unlock_key(
            &password_key("correct horse ", &salt, &CHEAP).unwrap(),
            &secret,
            &account,
        );
        assert_ne!(auk.expose(), other_password.expose());
    }

    #[test]
    fn passwords_are_normalised() {
        let salt = [0u8; 16];
        let composed = password_key("caf\u{e9}", &salt, &CHEAP).unwrap();
        let decomposed = password_key("cafe\u{301}", &salt, &CHEAP).unwrap();
        assert_eq!(composed.expose(), decomposed.expose());
    }

    #[test]
    fn parameters_out_of_bounds_are_refused_before_hashing() {
        for params in [
            KdfParams {
                m_kib: 1024,
                ..CHEAP
            },
            KdfParams {
                m_kib: 4 << 20,
                ..CHEAP
            },
            KdfParams { t: 0, ..CHEAP },
            KdfParams { t: 11, ..CHEAP },
            KdfParams { p: 9, ..CHEAP },
        ] {
            assert!(password_key("x", &[0; 16], &params).is_err());
        }
        KdfParams::DEFAULT.check().unwrap();
    }

    #[test]
    fn sealed_data_is_bound_to_its_key_and_associated_data() {
        let key = Key::random();
        let sealed = seal(&key, b"ad", b"hello");
        assert_eq!(&*open(&key, b"ad", &sealed).unwrap(), b"hello");
        assert!(open(&key, b"other", &sealed).is_err());
        assert!(open(&Key::random(), b"ad", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"ad", &tampered).is_err());
        assert_ne!(seal(&key, b"ad", b"hello"), sealed, "nonces are random");
    }

    #[test]
    fn padding_hides_short_lengths() {
        assert_eq!(pad(b"a").len(), 256);
        assert_eq!(pad(&[1; 200]).len(), 256);
        assert_eq!(pad(&[1; 253]).len(), 512);
        assert_eq!(pad(&[1; 5000]).len(), 8192);
        for len in [0, 1, 252, 253, 4092, 4093, 5000] {
            let data = vec![3u8; len];
            assert_eq!(unpad(&pad(&data)).unwrap(), &data[..]);
        }
        assert!(unpad(&[0, 0, 1, 0]).is_err());
    }

    #[test]
    fn secret_keys_round_trip_and_catch_typos() {
        let key = SecretKey::generate();
        let shown = key.display();
        assert!(shown.starts_with("VP1-"));
        assert_eq!(shown.len(), 4 + 6 + 4 * 6 + 3);
        let parsed = SecretKey::parse(&shown.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(parsed.expose(), key.expose());
        let mut typo = shown.to_string().into_bytes();
        let i = typo.len() - 5;
        typo[i] = if typo[i] == b'2' { b'3' } else { b'2' };
        assert!(SecretKey::parse(std::str::from_utf8(&typo).unwrap()).is_err());
        assert!(SecretKey::parse("VP1-nonsense").is_err());
    }

    #[test]
    fn signatures_verify_only_the_signed_message() {
        let key = SigningKey::generate();
        let signature = key.sign(b"manifest");
        assert!(verify(&key.public(), b"manifest", &signature));
        assert!(!verify(&key.public(), b"manifest2", &signature));
        let restored = SigningKey::from_seed(&*key.seed()).unwrap();
        assert_eq!(restored.public(), key.public());
    }

    #[test]
    fn derived_keys_differ_by_label() {
        let ak = Key::random();
        let a = ak.expand(&ad("VisiPass vault key wrap", &[]));
        let b = ak.expand(&ad("VisiPass keyset", &[]));
        assert_ne!(a.expose(), b.expose());
        assert_eq!(
            a.expose(),
            ak.expand(&ad("VisiPass vault key wrap", &[])).expose()
        );
    }
}
