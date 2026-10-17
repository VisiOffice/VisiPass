//! The native vault on disk: one SQLite file per device, every row a ciphertext,
//! every vault and the account covered by a signed manifest. Implements
//! `docs/crypto-design.md` §4–§8 and the storage side of §11.1 sync (section
//! numbers below refer to it).
//!
//! The store knows nothing about items' contents: callers hand it plaintext
//! overview and details bytes, and get them back after the checks pass.
//!
//! An item is a set of revisions. Each revision names the revisions it replaces
//! (its parents); the item's current revisions, its heads, are those no other
//! revision replaces. One head is the normal case. Two or more is a conflict
//! that sync brought in (two devices edited the item offline), and stays until
//! a write replaces all of them.

mod legacy;
pub mod sync;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vp_crypto::{
    Error as CryptoError, KdfParams, Key, Part, SecretKey, SigningKey, Value, ad, hash,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Error("The vault database could not be read or written".into())
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Error(e.0.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn tampered(what: &str) -> Error {
    Error(format!(
        "The vault file fails its integrity check ({what}). It may have been tampered with or rolled back; restore it from a backup or run `vp doctor`"
    ))
}

fn newer() -> Error {
    Error("This vault was written by a newer VisiPass; update VisiPass to open it".into())
}

/// The layout of the database file, in the account row. 1 had one version
/// counter per item; 2 has revisions with parents (§11.1).
pub const SCHEMA_VERSION: u64 = 2;

const TABLES: &str = "
CREATE TABLE IF NOT EXISTS account(
  account_id BLOB PRIMARY KEY, format_version INTEGER NOT NULL, ak_generation INTEGER NOT NULL,
  salt BLOB NOT NULL, m_kib INTEGER NOT NULL, t INTEGER NOT NULL, p INTEGER NOT NULL,
  wrapped_ak BLOB NOT NULL, keyset BLOB NOT NULL,
  sequence INTEGER NOT NULL, manifest BLOB NOT NULL, signature BLOB NOT NULL,
  device BLOB NOT NULL DEFAULT x'');
CREATE TABLE IF NOT EXISTS vault(
  vault_id TEXT PRIMARY KEY, vk_generation INTEGER NOT NULL, wrapped_vk BLOB NOT NULL,
  attrs BLOB NOT NULL, sequence INTEGER NOT NULL, manifest BLOB NOT NULL, signature BLOB NOT NULL,
  origin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS revision(
  vault_id TEXT NOT NULL, item_id TEXT NOT NULL, rev_device BLOB NOT NULL, rev_n INTEGER NOT NULL,
  parents BLOB NOT NULL, head INTEGER NOT NULL, overview BLOB, details BLOB NOT NULL,
  PRIMARY KEY(vault_id, item_id, rev_device, rev_n));
CREATE TABLE IF NOT EXISTS outbox(
  seq INTEGER PRIMARY KEY, exported INTEGER NOT NULL, prev BLOB NOT NULL, body BLOB NOT NULL);
";

// ---- Revisions ------------------------------------------------------------

/// One revision of an item: the device that wrote it and that device's counter
/// (§11.1). Unique without coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rev {
    pub device: [u8; 16],
    pub n: u64,
}

impl Rev {
    const MIN: Rev = Rev {
        device: [0; 16],
        n: 0,
    };
    const MAX: Rev = Rev {
        device: [0xff; 16],
        n: u64::MAX,
    };

    fn part(&self) -> Part<'_> {
        Part::List(vec![Part::Bytes(&self.device), Part::Uint(self.n)])
    }

    fn from_value(value: &Value) -> Result<Rev> {
        match value.list()? {
            [device, n] => Ok(Rev {
                device: device.fixed()?,
                n: n.uint()?,
            }),
            _ => Err(Error("malformed revision".into())),
        }
    }
}

/// `<32 hex digits>.<n>`, how revisions are named outside the store.
impl std::fmt::Display for Rev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", hex(&self.device), self.n)
    }
}

impl std::str::FromStr for Rev {
    type Err = Error;
    fn from_str(s: &str) -> Result<Rev> {
        let bad = || Error(format!("{s} is not a revision"));
        let (device, n) = s.split_once('.').ok_or_else(bad)?;
        Ok(Rev {
            device: unhex(device).ok_or_else(bad)?,
            n: n.parse().map_err(|_| bad())?,
        })
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn revs_part(revs: &[Rev]) -> Part<'_> {
    Part::List(revs.iter().map(Rev::part).collect())
}

fn encode_revs(revs: &[Rev]) -> Vec<u8> {
    ad("VisiPass revisions", &[revs_part(revs)])
}

fn revs_of(value: &Value) -> Result<Vec<Rev>> {
    value.list()?.iter().map(Rev::from_value).collect()
}

fn decode_revs(bytes: &[u8]) -> Result<Vec<Rev>> {
    match vp_crypto::decode("VisiPass revisions", bytes)?.as_slice() {
        [list] => revs_of(list),
        _ => Err(tampered("revision parents")),
    }
}

// ---- This device's own state ---------------------------------------------

/// What this device knows of another device's log (§11.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Peer {
    pub seq: u64,
    pub hash: [u8; 32],
    pub forked: bool,
}

/// This device's revision counter and sync position, stored in the account row
/// and covered by the account manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Local {
    /// Every device ID this device has written under; the last is current.
    pub mine: Vec<[u8; 16]>,
    pub next_rev: u64,
    /// Own revisions and vaults numbered up to this are in a change file or snapshot.
    pub exported: u64,
    /// Own log: the last change file's seq and hash.
    pub seq: u64,
    pub head: [u8; 32],
    /// Own seq at the last snapshot written.
    pub snapshot: Option<u64>,
    pub peers: BTreeMap<[u8; 16], Peer>,
}

impl Local {
    fn new(next_rev: u64) -> Self {
        Local {
            mine: vec![vp_crypto::random()],
            next_rev,
            exported: 0,
            seq: 0,
            head: [0; 32],
            snapshot: None,
            peers: BTreeMap::new(),
        }
    }

    pub fn device(&self) -> [u8; 16] {
        *self.mine.last().expect("a device always has an ID")
    }

    fn encode(&self) -> Vec<u8> {
        let snapshot: Vec<Part> = self.snapshot.iter().map(|s| Part::Uint(*s)).collect();
        let peers = self
            .peers
            .iter()
            .map(|(id, p)| {
                Part::List(vec![
                    Part::Bytes(id),
                    Part::Uint(p.seq),
                    Part::Bytes(&p.hash),
                    Part::Uint(p.forked as u64),
                ])
            })
            .collect();
        ad(
            "VisiPass device state",
            &[
                Part::List(self.mine.iter().map(|m| Part::Bytes(m)).collect()),
                Part::Uint(self.next_rev),
                Part::Uint(self.exported),
                Part::Uint(self.seq),
                Part::Bytes(&self.head),
                Part::List(snapshot),
                Part::List(peers),
            ],
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let bad = |_| tampered("device state");
        let parts = vp_crypto::decode("VisiPass device state", bytes).map_err(bad)?;
        let [mine, next_rev, exported, seq, head, snapshot, peers] = parts.as_slice() else {
            return Err(tampered("device state"));
        };
        let mine: Vec<[u8; 16]> = mine
            .list()?
            .iter()
            .map(|m| m.fixed())
            .collect::<vp_crypto::Result<_>>()?;
        if mine.is_empty() {
            return Err(tampered("device state"));
        }
        let mut peer_map = BTreeMap::new();
        for p in peers.list()? {
            let [id, seq, hash, forked] = p.list()? else {
                return Err(tampered("device state"));
            };
            peer_map.insert(
                id.fixed()?,
                Peer {
                    seq: seq.uint()?,
                    hash: hash.fixed()?,
                    forked: forked.uint()? != 0,
                },
            );
        }
        Ok(Local {
            mine,
            next_rev: next_rev.uint()?,
            exported: exported.uint()?,
            seq: seq.uint()?,
            head: head.fixed()?,
            snapshot: match snapshot.list()? {
                [] => None,
                [s] => Some(s.uint()?),
                _ => return Err(tampered("device state")),
            },
            peers: peer_map,
        })
    }
}

// ---- Keys and manifests held while unlocked ----------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct RevState {
    parents: Vec<Rev>,
    head: bool,
    /// None for history migrated from schema 1, which kept only details.
    overview: Option<[u8; 32]>,
    details: [u8; 32],
}

type Revisions = BTreeMap<(String, Rev), RevState>;

struct VaultState {
    key: Key,
    generation: u64,
    sequence: u64,
    attrs_hash: [u8; 32],
    wrapped_hash: [u8; 32],
    /// The own revision number its creation took, or 0 if it came from elsewhere.
    origin: u64,
    revisions: Revisions,
}

fn of_item<'a>(
    revisions: &'a Revisions,
    item_id: &str,
) -> impl Iterator<Item = (&'a Rev, &'a RevState)> {
    revisions
        .range((item_id.to_string(), Rev::MIN)..=(item_id.to_string(), Rev::MAX))
        .map(|((_, rev), state)| (rev, state))
}

fn heads_of(revisions: &Revisions, item_id: &str) -> Vec<Rev> {
    of_item(revisions, item_id)
        .filter(|(_, s)| s.head)
        .map(|(r, _)| *r)
        .collect()
}

/// Everything the daemon holds while the vault is unlocked (§6.1). Dropping it
/// erases the keys.
pub struct Unlocked {
    account_id: [u8; 16],
    ak_generation: u64,
    ak: Key,
    signing: SigningKey,
    sequence: u64,
    account_row_hash: [u8; 32],
    vaults: BTreeMap<String, VaultState>,
    local: Local,
}

/// The Account Key alone, kept for quick unlock (§4.3) after everything else is
/// erased. Opening the vault with it still checks every manifest.
pub struct AccountKey {
    account_id: [u8; 16],
    ak_generation: u64,
    ak: Key,
}

impl Unlocked {
    /// Keeps the Account Key and erases the rest.
    pub fn into_account_key(self) -> AccountKey {
        AccountKey {
            account_id: self.account_id,
            ak_generation: self.ak_generation,
            ak: self.ak,
        }
    }

    /// The account's random ID, for the Emergency Kit. Not secret.
    pub fn account_id(&self) -> [u8; 16] {
        self.account_id
    }

    /// The account manifest's sequence: it grows with every commit.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn vault_ids(&self) -> Vec<String> {
        self.vaults.keys().cloned().collect()
    }

    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.vaults.contains_key(vault_id)
    }

    pub fn has_item(&self, vault_id: &str, item_id: &str) -> bool {
        self.vaults
            .get(vault_id)
            .is_some_and(|v| !heads_of(&v.revisions, item_id).is_empty())
    }

    /// The item's current revisions: one normally, more after a sync conflict.
    pub fn heads(&self, vault_id: &str, item_id: &str) -> Vec<Rev> {
        self.vaults
            .get(vault_id)
            .map(|v| heads_of(&v.revisions, item_id))
            .unwrap_or_default()
    }

    fn vault(&self, vault_id: &str) -> Result<&VaultState> {
        self.vaults
            .get(vault_id)
            .ok_or_else(|| Error(format!("No vault with ID {vault_id}")))
    }

    fn derived(&self, label: &str) -> Key {
        derive(&self.ak, label, &self.account_id, self.ak_generation)
    }
}

fn derive(ak: &Key, label: &str, account_id: &[u8; 16], generation: u64) -> Key {
    ak.expand(&ad(
        label,
        &[Part::Bytes(account_id), Part::Uint(generation)],
    ))
}

/// The parts of [`Unlocked`] a failed transaction must put back.
struct Checkpoint {
    sequence: u64,
    local: Local,
    vaults: BTreeMap<String, (u64, u64, Revisions)>,
}

impl Unlocked {
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            sequence: self.sequence,
            local: self.local.clone(),
            vaults: self
                .vaults
                .iter()
                .map(|(id, v)| (id.clone(), (v.sequence, v.origin, v.revisions.clone())))
                .collect(),
        }
    }

    fn restore(&mut self, c: Checkpoint) {
        self.sequence = c.sequence;
        self.local = c.local;
        self.vaults.retain(|id, _| c.vaults.contains_key(id));
        for (id, (sequence, origin, revisions)) in c.vaults {
            if let Some(v) = self.vaults.get_mut(&id) {
                v.sequence = sequence;
                v.origin = origin;
                v.revisions = revisions;
            }
        }
    }
}

fn h(bytes: &[u8]) -> [u8; 32] {
    hash("VisiPass manifest entry", &[Part::Bytes(bytes)])
}

fn vk_commit(vault_id: &str, generation: u64, key: &Key) -> [u8; 32] {
    hash(
        "VisiPass vault key commitment",
        &[
            Part::Text(vault_id),
            Part::Uint(generation),
            Part::Bytes(key.expose()),
        ],
    )
}

fn vault_manifest(vault_id: &str, v: &VaultState) -> Vec<u8> {
    let commit = vk_commit(vault_id, v.generation, &v.key);
    let revisions = v
        .revisions
        .iter()
        .map(|((id, rev), s)| {
            Part::List(vec![
                Part::Text(id),
                rev.part(),
                revs_part(&s.parents),
                Part::Uint(s.head as u64),
                Part::Bytes(s.overview.as_ref().map_or(&[][..], |o| &o[..])),
                Part::Bytes(&s.details),
            ])
        })
        .collect();
    ad(
        "VisiPass vault manifest",
        &[
            Part::Text(vault_id),
            Part::Uint(v.generation),
            Part::Bytes(&commit),
            Part::Uint(v.sequence),
            Part::Bytes(&v.attrs_hash),
            Part::Bytes(&v.wrapped_hash),
            Part::Uint(v.origin),
            Part::List(revisions),
        ],
    )
}

fn account_manifest(u: &Unlocked) -> Vec<u8> {
    let hashes: Vec<(&String, u64, [u8; 32])> = u
        .vaults
        .iter()
        .map(|(id, v)| (id, v.sequence, h(&vault_manifest(id, v))))
        .collect();
    let vaults = hashes
        .iter()
        .map(|(id, sequence, digest)| {
            Part::List(vec![
                Part::Text(id),
                Part::Uint(*sequence),
                Part::Bytes(digest),
            ])
        })
        .collect();
    ad(
        "VisiPass account manifest",
        &[
            Part::Bytes(&u.account_id),
            Part::Uint(u.ak_generation),
            Part::Uint(u.sequence),
            Part::List(vaults),
            Part::Bytes(&u.account_row_hash),
            Part::Bytes(&h(&u.local.encode())),
        ],
    )
}

fn sign_manifest(signing: &SigningKey, manifest: &[u8]) -> [u8; 64] {
    signing.sign(&ad("VisiPass manifest", &[Part::Bytes(manifest)]))
}

fn check_manifest(signing: &SigningKey, manifest: &[u8], signature: &[u8]) -> bool {
    vp_crypto::verify(
        &signing.public(),
        &ad("VisiPass manifest", &[Part::Bytes(manifest)]),
        signature,
    )
}

fn account_row_hash(wrapped_ak: &[u8], params: &KdfParams, salt: &[u8], keyset: &[u8]) -> [u8; 32] {
    hash(
        "VisiPass account row",
        &[
            Part::Bytes(wrapped_ak),
            params.part(),
            Part::Bytes(salt),
            Part::Bytes(keyset),
        ],
    )
}

fn ak_ad(account_id: &[u8; 16], generation: u64, params: &KdfParams, salt: &[u8]) -> Vec<u8> {
    ad(
        "VisiPass account key",
        &[
            Part::Bytes(account_id),
            Part::Uint(generation),
            params.part(),
            Part::Bytes(salt),
        ],
    )
}

fn keyset_ad(account_id: &[u8; 16], generation: u64) -> Vec<u8> {
    ad(
        "VisiPass keyset",
        &[Part::Bytes(account_id), Part::Uint(generation)],
    )
}

fn vk_ad(account_id: &[u8; 16], vault_id: &str, generation: u64) -> Vec<u8> {
    ad(
        "VisiPass vault key",
        &[
            Part::Bytes(account_id),
            Part::Text(vault_id),
            Part::Uint(generation),
        ],
    )
}

fn attrs_ad(vault_id: &str, generation: u64) -> Vec<u8> {
    ad(
        "VisiPass vault attributes",
        &[Part::Text(vault_id), Part::Uint(generation)],
    )
}

/// §7.2, with the revision where schema 1 had the item's version.
fn item_ad(vault_id: &str, generation: u64, item_id: &str, part: &str, rev: &Rev) -> Vec<u8> {
    ad(
        "VisiPass item",
        &[
            Part::Text(vault_id),
            Part::Uint(generation),
            Part::Text(item_id),
            Part::Text(part),
            rev.part(),
        ],
    )
}

/// `"VP" ‖ format ‖ vk_generation ‖ nonce ‖ ciphertext` (§7.2).
fn seal_item(key: &Key, generation: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = b"VP".to_vec();
    out.push(vp_crypto::FORMAT as u8);
    out.extend((generation as u32).to_be_bytes());
    out.extend(vp_crypto::seal(key, ad, &vp_crypto::pad(plaintext)));
    out
}

fn open_item(key: &Key, generation: u64, ad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 7 || &sealed[..2] != b"VP" {
        return Err(tampered("item header"));
    }
    if sealed[2] as u64 != vp_crypto::FORMAT {
        return Err(newer());
    }
    if u32::from_be_bytes(sealed[3..7].try_into().unwrap()) as u64 != generation {
        return Err(tampered("key generation"));
    }
    let padded = vp_crypto::open(key, ad, &sealed[7..])?;
    Ok(Zeroizing::new(vp_crypto::unpad(&padded)?.to_vec()))
}

// ---- The store -----------------------------------------------------------

/// vault_id, vk_generation, wrapped_vk, attrs, sequence, manifest, signature, origin
type VaultRow = (String, u64, Vec<u8>, Vec<u8>, u64, Vec<u8>, Vec<u8>, u64);

/// vault_id, item_id, rev, parents, head, overview, details
type RevisionRow = (String, String, Rev, Vec<u8>, bool, Option<Vec<u8>>, Vec<u8>);

struct AccountRow {
    account_id: [u8; 16],
    format: u64,
    ak_generation: u64,
    salt: [u8; 16],
    params: KdfParams,
    wrapped_ak: Vec<u8>,
    keyset: Vec<u8>,
    sequence: u64,
    manifest: Vec<u8>,
    signature: Vec<u8>,
    device: Vec<u8>,
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
    sequence_file: PathBuf,
}

/// A current revision's overview as stored: its item ID, revision and plaintext.
pub struct Overview {
    pub item_id: String,
    pub rev: Rev,
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// One item write for [`Store::put_items`].
pub struct Write<'a> {
    pub item_id: &'a str,
    pub overview: &'a [u8],
    pub details: &'a [u8],
    /// The current revisions this write replaces: none for a new item, the
    /// revision that was edited otherwise, or every head to settle a conflict.
    pub replaces: &'a [Rev],
}

impl Store {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Creates a new account (§4) in a new file. Fails if the file exists.
    pub fn create(
        path: &Path,
        sequence_file: &Path,
        password: &str,
        secret_key: &SecretKey,
        params: KdfParams,
    ) -> Result<(Store, Unlocked)> {
        let account_id: [u8; 16] = vp_crypto::random();
        let salt: [u8; 16] = vp_crypto::random();
        let auk = vp_crypto::account_unlock_key(
            &vp_crypto::password_key(password, &salt, &params)?,
            secret_key,
            &account_id,
        );
        let ak = Key::random();
        let wrapped_ak = vp_crypto::wrap(&auk, &ak_ad(&account_id, 1, &params, &salt), &ak);
        let signing = SigningKey::generate();
        let keyset = vp_crypto::seal(
            &derive(&ak, "VisiPass keyset", &account_id, 1),
            &keyset_ad(&account_id, 1),
            &*signing.seed(),
        );
        Self::create_with(
            path,
            sequence_file,
            AccountRow {
                account_id,
                format: SCHEMA_VERSION,
                ak_generation: 1,
                salt,
                params,
                wrapped_ak,
                keyset,
                sequence: 1,
                manifest: Vec::new(),
                signature: Vec::new(),
                device: Vec::new(),
            },
            ak,
            signing,
        )
    }

    /// Writes a new file holding `row`'s account and no vaults.
    fn create_with(
        path: &Path,
        sequence_file: &Path,
        mut row: AccountRow,
        ak: Key,
        signing: SigningKey,
    ) -> Result<(Store, Unlocked)> {
        if path.exists() {
            return Err(Error(format!("{} already exists", path.display())));
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(TABLES)?;
        let unlocked = Unlocked {
            account_id: row.account_id,
            ak_generation: row.ak_generation,
            ak,
            signing,
            sequence: 1,
            account_row_hash: account_row_hash(
                &row.wrapped_ak,
                &row.params,
                &row.salt,
                &row.keyset,
            ),
            vaults: BTreeMap::new(),
            local: Local::new(1),
        };
        row.manifest = account_manifest(&unlocked);
        row.signature = sign_manifest(&unlocked.signing, &row.manifest).to_vec();
        conn.execute(
            "INSERT INTO account VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12)",
            params![
                &row.account_id[..],
                SCHEMA_VERSION,
                row.ak_generation,
                &row.salt[..],
                row.params.m_kib,
                row.params.t,
                row.params.p,
                row.wrapped_ak,
                row.keyset,
                row.manifest,
                row.signature,
                unlocked.local.encode(),
            ],
        )?;
        let store = Store {
            conn,
            path: path.to_path_buf(),
            sequence_file: sequence_file.to_path_buf(),
        };
        SequenceWriter(sequence_file).write(1)?;
        Ok((store, unlocked))
    }

    pub fn open(path: &Path, sequence_file: &Path) -> Result<Store> {
        if !path.is_file() {
            return Err(Error(format!("No vault at {}", path.display())));
        }
        let conn = Connection::open(path)?;
        Ok(Store {
            conn,
            path: path.to_path_buf(),
            sequence_file: sequence_file.to_path_buf(),
        })
    }

    fn recorded_sequence(&self) -> u64 {
        std::fs::read_to_string(&self.sequence_file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Unwraps every key and checks every manifest against every row (§7.4).
    /// A schema-1 file is checked as it was written, backed up beside itself,
    /// then migrated.
    pub fn unlock(&self, password: &str, secret_key: &SecretKey) -> Result<Unlocked> {
        let row = self.account_row()?;
        row.params.check()?;
        let auk = vp_crypto::account_unlock_key(
            &vp_crypto::password_key(password, &row.salt, &row.params)?,
            secret_key,
            &row.account_id,
        );
        let ak = vp_crypto::unwrap(
            &auk,
            &ak_ad(&row.account_id, row.ak_generation, &row.params, &row.salt),
            &row.wrapped_ak,
        )
        .map_err(|_| Error("Wrong master password or Secret Key".into()))?;
        self.open_with(row, ak)
    }

    /// Opens the vault with an Account Key kept from an earlier unlock (§4.3),
    /// with the same checks as [`Store::unlock`]. Fails once the Account Key has
    /// been rotated, so the master password is needed again.
    pub fn unlock_with_key(&self, key: AccountKey) -> Result<Unlocked> {
        let row = self.account_row()?;
        if row.account_id != key.account_id || row.ak_generation != key.ak_generation {
            return Err(Error(
                "The vault's keys changed; unlock it with the master password".into(),
            ));
        }
        self.open_with(row, key.ak)
    }

    fn account_row(&self) -> Result<AccountRow> {
        let format: u64 = self
            .conn
            .query_row("SELECT format_version FROM account", [], |r| r.get(0))
            .optional()?
            .ok_or_else(|| tampered("no account"))?;
        if format > SCHEMA_VERSION {
            return Err(newer());
        }
        let device = if format >= 2 { "device" } else { "x''" };
        let row = self
            .conn
            .query_row(
                &format!(
                    "SELECT account_id, ak_generation, salt, m_kib, t, p, wrapped_ak, keyset, sequence, manifest, signature, {device} FROM account"
                ),
                [],
                |r| {
                    let id: Vec<u8> = r.get(0)?;
                    let salt: Vec<u8> = r.get(2)?;
                    Ok(AccountRow {
                        account_id: id.try_into().unwrap_or([0; 16]),
                        format,
                        ak_generation: r.get(1)?,
                        salt: salt.try_into().unwrap_or([0; 16]),
                        params: KdfParams {
                            m_kib: r.get(3)?,
                            t: r.get(4)?,
                            p: r.get(5)?,
                        },
                        wrapped_ak: r.get(6)?,
                        keyset: r.get(7)?,
                        sequence: r.get(8)?,
                        manifest: r.get(9)?,
                        signature: r.get(10)?,
                        device: r.get(11)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| tampered("no account"))?;
        if row.sequence < self.recorded_sequence() {
            return Err(tampered("its sequence number went backwards"));
        }
        Ok(row)
    }

    fn open_with(&self, row: AccountRow, ak: Key) -> Result<Unlocked> {
        let seed = vp_crypto::open(
            &derive(&ak, "VisiPass keyset", &row.account_id, row.ak_generation),
            &keyset_ad(&row.account_id, row.ak_generation),
            &row.keyset,
        )
        .map_err(|_| tampered("keyset"))?;
        let signing = SigningKey::from_seed(&seed)?;
        if row.format == 1 {
            return legacy::open_and_migrate(self, row, ak, signing);
        }
        let mut unlocked = Unlocked {
            account_id: row.account_id,
            ak_generation: row.ak_generation,
            ak,
            signing,
            sequence: row.sequence,
            account_row_hash: account_row_hash(
                &row.wrapped_ak,
                &row.params,
                &row.salt,
                &row.keyset,
            ),
            vaults: BTreeMap::new(),
            local: Local::decode(&row.device)?,
        };
        let wrap_key = unlocked.derived("VisiPass vault key wrap");
        let mut statement = self.conn.prepare(
            "SELECT vault_id, vk_generation, wrapped_vk, attrs, sequence, manifest, signature, origin FROM vault",
        )?;
        let vaults: Vec<VaultRow> = statement
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut revisions: BTreeMap<String, Revisions> = BTreeMap::new();
        for (vault_id, item_id, rev, parents, head, overview, details) in self.revision_rows("")? {
            revisions.entry(vault_id).or_default().insert(
                (item_id, rev),
                RevState {
                    parents: decode_revs(&parents)?,
                    head,
                    overview: overview.as_deref().map(h),
                    details: h(&details),
                },
            );
        }
        for (vault_id, generation, wrapped_vk, attrs, sequence, stored, signature, origin) in vaults
        {
            let key = vp_crypto::unwrap(
                &wrap_key,
                &vk_ad(&row.account_id, &vault_id, generation),
                &wrapped_vk,
            )
            .map_err(|_| tampered("vault key"))?;
            let state = VaultState {
                key,
                generation,
                sequence,
                attrs_hash: h(&attrs),
                wrapped_hash: h(&wrapped_vk),
                origin,
                revisions: revisions.remove(&vault_id).unwrap_or_default(),
            };
            if vault_manifest(&vault_id, &state) != stored
                || !check_manifest(&unlocked.signing, &stored, &signature)
            {
                return Err(tampered(&format!("vault {vault_id}")));
            }
            unlocked.vaults.insert(vault_id, state);
        }
        if !revisions.is_empty() {
            return Err(tampered("revisions of an unknown vault"));
        }
        if account_manifest(&unlocked) != row.manifest
            || !check_manifest(&unlocked.signing, &row.manifest, &row.signature)
        {
            return Err(tampered("account manifest"));
        }
        Ok(unlocked)
    }

    /// Every revision row, or with `filter` only those matching that SQL condition.
    fn revision_rows(&self, filter: &str) -> Result<Vec<RevisionRow>> {
        let condition = if filter.is_empty() {
            String::new()
        } else {
            format!(" WHERE {filter}")
        };
        let mut statement = self.conn.prepare(&format!(
            "SELECT vault_id, item_id, rev_device, rev_n, parents, head, overview, details FROM revision{condition} ORDER BY vault_id, item_id, rev_device, rev_n"
        ))?;
        let rows = statement
            .query_map([], |r| {
                let device: Vec<u8> = r.get(2)?;
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    Rev {
                        device: device.try_into().unwrap_or([0; 16]),
                        n: r.get(3)?,
                    },
                    r.get(4)?,
                    r.get::<_, i64>(5)? != 0,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Creates a vault with a fresh key (§7.1). `attrs` is its encrypted name and settings.
    pub fn create_vault(
        &mut self,
        unlocked: &mut Unlocked,
        vault_id: &str,
        attrs: &[u8],
    ) -> Result<()> {
        if unlocked.vaults.contains_key(vault_id) {
            return Err(Error(format!("Vault {vault_id} already exists")));
        }
        let key = Key::random();
        let wrapped = vp_crypto::wrap(
            &unlocked.derived("VisiPass vault key wrap"),
            &vk_ad(&unlocked.account_id, vault_id, 1),
            &key,
        );
        let sealed_attrs = vp_crypto::seal(&key, &attrs_ad(vault_id, 1), &vp_crypto::pad(attrs));
        let checkpoint = unlocked.checkpoint();
        let origin = unlocked.local.next_rev;
        unlocked.local.next_rev += 1;
        unlocked.vaults.insert(
            vault_id.to_string(),
            VaultState {
                key,
                generation: 1,
                sequence: 0,
                attrs_hash: h(&sealed_attrs),
                wrapped_hash: h(&wrapped),
                origin,
                revisions: BTreeMap::new(),
            },
        );
        let tx = self.conn.transaction()?;
        let result = tx
            .execute(
                "INSERT INTO vault VALUES (?1, 1, ?2, ?3, 0, x'', x'', ?4)",
                params![vault_id, wrapped, sealed_attrs, origin],
            )
            .map_err(Error::from)
            .and_then(|_| commit(&self.sequence_file, unlocked, &[vault_id], tx));
        if result.is_err() {
            unlocked.restore(checkpoint);
        }
        result
    }

    /// Vault IDs and their decrypted attributes.
    pub fn vaults(&self, unlocked: &Unlocked) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
        let mut out = Vec::new();
        let mut statement = self
            .conn
            .prepare("SELECT vault_id, attrs FROM vault ORDER BY vault_id")?;
        let rows: Vec<(String, Vec<u8>)> = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if rows.len() != unlocked.vaults.len() {
            return Err(tampered("vault list"));
        }
        for (vault_id, sealed) in rows {
            let state = unlocked
                .vault(&vault_id)
                .map_err(|_| tampered("vault list"))?;
            if h(&sealed) != state.attrs_hash {
                return Err(tampered("vault attributes"));
            }
            let padded =
                vp_crypto::open(&state.key, &attrs_ad(&vault_id, state.generation), &sealed)?;
            out.push((
                vault_id,
                Zeroizing::new(vp_crypto::unpad(&padded)?.to_vec()),
            ));
        }
        Ok(out)
    }

    /// The decrypted overview of every current revision in a vault, in item
    /// order. An item in conflict appears once per head.
    pub fn overviews(&self, unlocked: &Unlocked, vault_id: &str) -> Result<Vec<Overview>> {
        let state = unlocked.vault(vault_id)?;
        let mut statement = self.conn.prepare(
            "SELECT item_id, rev_device, rev_n, overview FROM revision WHERE vault_id = ?1 AND head = 1 ORDER BY item_id, rev_device, rev_n",
        )?;
        type Row = (String, Vec<u8>, u64, Option<Vec<u8>>);
        let rows: Vec<Row> = statement
            .query_map([vault_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        if rows.len() != state.revisions.values().filter(|s| s.head).count() {
            return Err(tampered("item count"));
        }
        rows.into_iter()
            .map(|(item_id, device, n, sealed)| {
                let rev = Rev {
                    device: device.try_into().map_err(|_| tampered("revision"))?,
                    n,
                };
                let sealed = sealed.ok_or_else(|| tampered("item overview"))?;
                match state.revisions.get(&(item_id.clone(), rev)) {
                    Some(s) if s.head && s.overview == Some(h(&sealed)) => {}
                    _ => return Err(tampered("item overview")),
                }
                let ad = item_ad(vault_id, state.generation, &item_id, "overview", &rev);
                let plaintext = open_item(&state.key, state.generation, &ad, &sealed)?;
                Ok(Overview {
                    item_id,
                    rev,
                    plaintext,
                })
            })
            .collect()
    }

    /// One revision's decrypted details, checked against the in-memory manifest (§7.4).
    pub fn details(
        &self,
        unlocked: &Unlocked,
        vault_id: &str,
        item_id: &str,
        rev: &Rev,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let state = unlocked.vault(vault_id)?;
        let expected = state
            .revisions
            .get(&(item_id.to_string(), *rev))
            .ok_or_else(|| Error(format!("No item with ID {item_id} in that vault")))?
            .details;
        let sealed: Vec<u8> = self
            .conn
            .query_row(
                "SELECT details FROM revision WHERE vault_id = ?1 AND item_id = ?2 AND rev_device = ?3 AND rev_n = ?4",
                params![vault_id, item_id, &rev.device[..], rev.n],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| tampered("missing item"))?;
        if h(&sealed) != expected {
            return Err(tampered("item details"));
        }
        let ad = item_ad(vault_id, state.generation, item_id, "details", rev);
        open_item(&state.key, state.generation, &ad, &sealed)
    }

    /// Writes one item. See [`Store::put_items`].
    pub fn put_item(
        &mut self,
        unlocked: &mut Unlocked,
        vault_id: &str,
        item_id: &str,
        overview: &[u8],
        details: &[u8],
        replaces: &[Rev],
    ) -> Result<Rev> {
        let revs = self.put_items(
            unlocked,
            vault_id,
            &[Write {
                item_id,
                overview,
                details,
                replaces,
            }],
        )?;
        Ok(revs[0])
    }

    /// Writes several items to one vault in one transaction under one manifest
    /// signature. All or nothing. Each write becomes a new revision replacing
    /// the heads it names, which stay as history (§7.3). Refused when a named
    /// revision is no longer current (it changed since it was read) or when a
    /// new item's ID is taken. Returns each new revision, in order.
    pub fn put_items(
        &mut self,
        unlocked: &mut Unlocked,
        vault_id: &str,
        writes: &[Write],
    ) -> Result<Vec<Rev>> {
        let checkpoint = unlocked.checkpoint();
        let tx = self.conn.transaction()?;
        let result = put_revisions(&tx, unlocked, vault_id, writes)
            .and_then(|revs| commit(&self.sequence_file, unlocked, &[vault_id], tx).map(|_| revs));
        if result.is_err() {
            unlocked.restore(checkpoint);
        }
        result
    }
}

fn put_revisions(
    tx: &Transaction,
    unlocked: &mut Unlocked,
    vault_id: &str,
    writes: &[Write],
) -> Result<Vec<Rev>> {
    let device = unlocked.local.device();
    let state = unlocked
        .vaults
        .get_mut(vault_id)
        .ok_or_else(|| Error(format!("No vault with ID {vault_id}")))?;
    let mut revs = Vec::with_capacity(writes.len());
    for write in writes {
        let item_id = write.item_id;
        let heads = heads_of(&state.revisions, item_id);
        if write.replaces.is_empty() && !heads.is_empty() {
            return Err(Error(format!("Item {item_id} already exists")));
        }
        if write.replaces.iter().any(|r| !heads.contains(r)) {
            return Err(Error(
                "The item changed since it was read (perhaps on another device); nothing was saved. Open it again and retry"
                    .into(),
            ));
        }
        let rev = Rev {
            device,
            n: unlocked.local.next_rev,
        };
        unlocked.local.next_rev += 1;
        let generation = state.generation;
        let sealed_overview = seal_item(
            &state.key,
            generation,
            &item_ad(vault_id, generation, item_id, "overview", &rev),
            write.overview,
        );
        let sealed_details = seal_item(
            &state.key,
            generation,
            &item_ad(vault_id, generation, item_id, "details", &rev),
            write.details,
        );
        insert_revision(
            tx,
            &mut state.revisions,
            vault_id,
            item_id,
            rev,
            write.replaces,
            Some(&sealed_overview),
            &sealed_details,
        )?;
        revs.push(rev);
    }
    Ok(revs)
}

/// Adds a revision: a head unless a known revision already replaces it, and
/// every head it replaces becomes history. The same rule for local writes and
/// for revisions sync brings in, in any order, so every device that has seen
/// the same revisions has the same heads.
#[allow(clippy::too_many_arguments)]
fn insert_revision(
    tx: &Transaction,
    revisions: &mut Revisions,
    vault_id: &str,
    item_id: &str,
    rev: Rev,
    parents: &[Rev],
    overview: Option<&[u8]>,
    details: &[u8],
) -> Result<()> {
    let head = !of_item(revisions, item_id).any(|(_, s)| s.parents.contains(&rev));
    for parent in parents {
        if let Some(s) = revisions.get_mut(&(item_id.to_string(), *parent))
            && s.head
        {
            s.head = false;
            tx.execute(
                "UPDATE revision SET head = 0 WHERE vault_id = ?1 AND item_id = ?2 AND rev_device = ?3 AND rev_n = ?4",
                params![vault_id, item_id, &parent.device[..], parent.n],
            )?;
        }
    }
    tx.execute(
        "INSERT INTO revision VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            vault_id,
            item_id,
            &rev.device[..],
            rev.n,
            encode_revs(parents),
            head as i64,
            overview,
            details
        ],
    )?;
    revisions.insert(
        (item_id.to_string(), rev),
        RevState {
            parents: parents.to_vec(),
            head,
            overview: overview.map(h),
            details: h(details),
        },
    );
    Ok(())
}

/// Bumps the sequence of each vault named and of the account, re-signs their
/// manifests, commits, then records the sequence (§7.4).
fn commit(
    sequence_file: &Path,
    unlocked: &mut Unlocked,
    vault_ids: &[&str],
    tx: Transaction,
) -> Result<()> {
    for vault_id in vault_ids {
        let state = unlocked
            .vaults
            .get_mut(*vault_id)
            .ok_or_else(|| tampered("vault"))?;
        state.sequence += 1;
        let bytes = vault_manifest(vault_id, state);
        let signature = sign_manifest(&unlocked.signing, &bytes);
        tx.execute(
            "UPDATE vault SET sequence = ?2, manifest = ?3, signature = ?4 WHERE vault_id = ?1",
            params![vault_id, state.sequence, bytes, &signature[..]],
        )?;
    }
    unlocked.sequence += 1;
    let bytes = account_manifest(unlocked);
    let signature = sign_manifest(&unlocked.signing, &bytes);
    tx.execute(
        "UPDATE account SET sequence = ?1, manifest = ?2, signature = ?3, device = ?4",
        params![
            unlocked.sequence,
            bytes,
            &signature[..],
            unlocked.local.encode()
        ],
    )?;
    tx.commit()?;
    SequenceWriter(sequence_file).write(unlocked.sequence)
}

/// The highest account sequence seen, kept outside the database. Written after
/// the transaction commits, so a crash leaves it behind, never ahead.
struct SequenceWriter<'a>(&'a Path);

impl SequenceWriter<'_> {
    fn write(&self, sequence: u64) -> Result<()> {
        use std::io::Write;
        let dir = self.0.parent().unwrap_or(Path::new("."));
        let temporary = dir.join(".sequence.tmp");
        let mut file = std::fs::File::create(&temporary)
            .map_err(|_| Error("Could not record the vault's sequence number".into()))?;
        file.write_all(sequence.to_string().as_bytes())
            .and_then(|_| file.sync_all())
            .and_then(|_| std::fs::rename(&temporary, self.0))
            .map_err(|_| Error("Could not record the vault's sequence number".into()))
    }
}
