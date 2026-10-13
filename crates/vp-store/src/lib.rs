//! The native vault on disk: one SQLite file per account, every row a ciphertext,
//! every vault and the account covered by a signed manifest. Implements
//! `docs/crypto-design.md` §4–§8 (section numbers below refer to it).
//!
//! The store knows nothing about items' contents: callers hand it plaintext
//! overview and details bytes, and get them back after the checks pass.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vp_crypto::{Error as CryptoError, KdfParams, Key, Part, SecretKey, SigningKey, ad, hash};
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

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS account(
  account_id BLOB PRIMARY KEY, format_version INTEGER NOT NULL, ak_generation INTEGER NOT NULL,
  salt BLOB NOT NULL, m_kib INTEGER NOT NULL, t INTEGER NOT NULL, p INTEGER NOT NULL,
  wrapped_ak BLOB NOT NULL, keyset BLOB NOT NULL,
  sequence INTEGER NOT NULL, manifest BLOB NOT NULL, signature BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS vault(
  vault_id TEXT PRIMARY KEY, vk_generation INTEGER NOT NULL, wrapped_vk BLOB NOT NULL,
  attrs BLOB NOT NULL, sequence INTEGER NOT NULL, manifest BLOB NOT NULL, signature BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS item(
  vault_id TEXT NOT NULL, item_id TEXT NOT NULL, item_version INTEGER NOT NULL,
  overview BLOB NOT NULL, details BLOB NOT NULL, PRIMARY KEY(vault_id, item_id));
CREATE TABLE IF NOT EXISTS history(
  vault_id TEXT NOT NULL, item_id TEXT NOT NULL, item_version INTEGER NOT NULL,
  details BLOB NOT NULL, PRIMARY KEY(vault_id, item_id, item_version));
";

// ---- Keys and manifests held while unlocked ----------------------------

struct VaultState {
    key: Key,
    generation: u64,
    sequence: u64,
    attrs_hash: [u8; 32],
    wrapped_hash: [u8; 32],
    /// item_id -> (version, H(overview), H(details))
    items: BTreeMap<String, (u64, [u8; 32], [u8; 32])>,
    /// (item_id, version) -> H(details)
    history: BTreeMap<(String, u64), [u8; 32]>,
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
}

impl Unlocked {
    pub fn vault_ids(&self) -> Vec<String> {
        self.vaults.keys().cloned().collect()
    }

    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.vaults.contains_key(vault_id)
    }

    pub fn has_item(&self, vault_id: &str, item_id: &str) -> bool {
        self.vaults
            .get(vault_id)
            .is_some_and(|v| v.items.contains_key(item_id))
    }

    fn vault(&self, vault_id: &str) -> Result<&VaultState> {
        self.vaults
            .get(vault_id)
            .ok_or_else(|| Error(format!("No vault with ID {vault_id}")))
    }

    fn derived(&self, label: &str) -> Key {
        self.ak.expand(&ad(
            label,
            &[
                Part::Bytes(&self.account_id),
                Part::Uint(self.ak_generation),
            ],
        ))
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
    let items = v
        .items
        .iter()
        .map(|(id, (version, ov, det))| {
            Part::List(vec![
                Part::Text(id),
                Part::Uint(*version),
                Part::Bytes(ov),
                Part::Bytes(det),
            ])
        })
        .collect();
    let history = v
        .history
        .iter()
        .map(|((id, version), det)| {
            Part::List(vec![Part::Text(id), Part::Uint(*version), Part::Bytes(det)])
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
            Part::List(items),
            Part::List(history),
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

fn item_ad(vault_id: &str, generation: u64, item_id: &str, part: &str, version: u64) -> Vec<u8> {
    ad(
        "VisiPass item",
        &[
            Part::Text(vault_id),
            Part::Uint(generation),
            Part::Text(item_id),
            Part::Text(part),
            Part::Uint(version),
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
        return Err(Error(
            "This vault was written by a newer VisiPass; update VisiPass to open it".into(),
        ));
    }
    if u32::from_be_bytes(sealed[3..7].try_into().unwrap()) as u64 != generation {
        return Err(tampered("key generation"));
    }
    let padded = vp_crypto::open(key, ad, &sealed[7..])?;
    Ok(Zeroizing::new(vp_crypto::unpad(&padded)?.to_vec()))
}

// ---- The store -----------------------------------------------------------

/// vault_id, vk_generation, wrapped_vk, attrs, sequence, manifest, signature
type VaultRow = (String, u64, Vec<u8>, Vec<u8>, u64, Vec<u8>, Vec<u8>);

pub struct Store {
    conn: Connection,
    sequence_file: PathBuf,
}

/// An overview as stored: its item ID, version and plaintext.
pub struct Overview {
    pub item_id: String,
    pub version: u64,
    pub plaintext: Zeroizing<Vec<u8>>,
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
        if path.exists() {
            return Err(Error(format!("{} already exists", path.display())));
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
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
        let mut unlocked = Unlocked {
            account_id,
            ak_generation: 1,
            ak,
            signing,
            sequence: 1,
            account_row_hash: [0; 32],
            vaults: BTreeMap::new(),
        };
        let keyset = vp_crypto::seal(
            &unlocked.derived("VisiPass keyset"),
            &keyset_ad(&account_id, 1),
            &*unlocked.signing.seed(),
        );
        unlocked.account_row_hash = account_row_hash(&wrapped_ak, &params, &salt, &keyset);
        let manifest = account_manifest(&unlocked);
        let signature = sign_manifest(&unlocked.signing, &manifest);
        conn.execute(
            "INSERT INTO account VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10)",
            params![
                &account_id[..],
                vp_crypto::FORMAT,
                &salt[..],
                params.m_kib,
                params.t,
                params.p,
                wrapped_ak,
                keyset,
                manifest,
                &signature[..]
            ],
        )?;
        let store = Store {
            conn,
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
    pub fn unlock(&self, password: &str, secret_key: &SecretKey) -> Result<Unlocked> {
        type AccountRow = (
            [u8; 16],
            u64,
            u64,
            Vec<u8>,
            KdfParams,
            Vec<u8>,
            Vec<u8>,
            u64,
            Vec<u8>,
            Vec<u8>,
        );
        let row: AccountRow = self
            .conn
            .query_row(
                "SELECT account_id, format_version, ak_generation, salt, m_kib, t, p, wrapped_ak, keyset, sequence, manifest, signature FROM account",
                [],
                |r| {
                    let id: Vec<u8> = r.get(0)?;
                    Ok((
                        id.try_into().unwrap_or([0; 16]),
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        KdfParams {
                            m_kib: r.get(4)?,
                            t: r.get(5)?,
                            p: r.get(6)?,
                        },
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| tampered("no account"))?;
        let (
            account_id,
            format,
            ak_generation,
            salt,
            params,
            wrapped_ak,
            keyset,
            sequence,
            manifest,
            signature,
        ) = row;
        if format != vp_crypto::FORMAT {
            return Err(Error(
                "This vault was written by a newer VisiPass; update VisiPass to open it".into(),
            ));
        }
        if sequence < self.recorded_sequence() {
            return Err(tampered("its sequence number went backwards"));
        }
        params.check()?;
        let salt: [u8; 16] = salt.as_slice().try_into().map_err(|_| tampered("salt"))?;
        let auk = vp_crypto::account_unlock_key(
            &vp_crypto::password_key(password, &salt, &params)?,
            secret_key,
            &account_id,
        );
        let ak = vp_crypto::unwrap(
            &auk,
            &ak_ad(&account_id, ak_generation, &params, &salt),
            &wrapped_ak,
        )
        .map_err(|_| Error("Wrong master password or Secret Key".into()))?;
        let mut unlocked = Unlocked {
            account_id,
            ak_generation,
            ak,
            signing: SigningKey::generate(),
            sequence,
            account_row_hash: account_row_hash(&wrapped_ak, &params, &salt, &keyset),
            vaults: BTreeMap::new(),
        };
        let seed = vp_crypto::open(
            &unlocked.derived("VisiPass keyset"),
            &keyset_ad(&account_id, ak_generation),
            &keyset,
        )
        .map_err(|_| tampered("keyset"))?;
        unlocked.signing = SigningKey::from_seed(&seed)?;

        let wrap_key = unlocked.derived("VisiPass vault key wrap");
        let mut statement = self.conn.prepare(
            "SELECT vault_id, vk_generation, wrapped_vk, attrs, sequence, manifest, signature FROM vault",
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
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        for (vault_id, generation, wrapped_vk, attrs, vault_sequence, stored, signature) in vaults {
            let key = vp_crypto::unwrap(
                &wrap_key,
                &vk_ad(&account_id, &vault_id, generation),
                &wrapped_vk,
            )
            .map_err(|_| tampered("vault key"))?;
            let mut state = VaultState {
                key,
                generation,
                sequence: vault_sequence,
                attrs_hash: h(&attrs),
                wrapped_hash: h(&wrapped_vk),
                items: BTreeMap::new(),
                history: BTreeMap::new(),
            };
            let mut items = self.conn.prepare(
                "SELECT item_id, item_version, overview, details FROM item WHERE vault_id = ?1",
            )?;
            for row in items.query_map([&vault_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })? {
                let (id, version, overview, details) = row?;
                state.items.insert(id, (version, h(&overview), h(&details)));
            }
            let mut history = self.conn.prepare(
                "SELECT item_id, item_version, details FROM history WHERE vault_id = ?1",
            )?;
            for row in history.query_map([&vault_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })? {
                let (id, version, details) = row?;
                state.history.insert((id, version), h(&details));
            }
            let expected = vault_manifest(&vault_id, &state);
            if expected != stored || !check_manifest(&unlocked.signing, &stored, &signature) {
                return Err(tampered(&format!("vault {vault_id}")));
            }
            unlocked.vaults.insert(vault_id, state);
        }
        if account_manifest(&unlocked) != manifest
            || !check_manifest(&unlocked.signing, &manifest, &signature)
        {
            return Err(tampered("account manifest"));
        }
        Ok(unlocked)
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
        let state = VaultState {
            key,
            generation: 1,
            sequence: 0,
            attrs_hash: h(&sealed_attrs),
            wrapped_hash: h(&wrapped),
            items: BTreeMap::new(),
            history: BTreeMap::new(),
        };
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO vault VALUES (?1, 1, ?2, ?3, 0, x'', x'')",
            params![vault_id, wrapped, sealed_attrs],
        )?;
        unlocked.vaults.insert(vault_id.to_string(), state);
        let result = Self::commit_with(&self.sequence_file, unlocked, vault_id, tx);
        if result.is_err() {
            unlocked.vaults.remove(vault_id);
        }
        result
    }

    /// Bumps the vault and account sequences, re-signs both manifests, commits,
    /// then records the sequence (§7.4).
    fn commit_with(
        sequence_file: &Path,
        unlocked: &mut Unlocked,
        vault_id: &str,
        tx: Transaction,
    ) -> Result<()> {
        let store_sequence = SequenceWriter(sequence_file);
        let state = unlocked
            .vaults
            .get_mut(vault_id)
            .ok_or_else(|| tampered("vault"))?;
        state.sequence += 1;
        let vault_bytes = vault_manifest(vault_id, state);
        let vault_signature = sign_manifest(&unlocked.signing, &vault_bytes);
        tx.execute(
            "UPDATE vault SET sequence = ?2, manifest = ?3, signature = ?4 WHERE vault_id = ?1",
            params![vault_id, state.sequence, vault_bytes, &vault_signature[..]],
        )?;
        unlocked.sequence += 1;
        let account_bytes = account_manifest(unlocked);
        let account_signature = sign_manifest(&unlocked.signing, &account_bytes);
        tx.execute(
            "UPDATE account SET sequence = ?1, manifest = ?2, signature = ?3",
            params![unlocked.sequence, account_bytes, &account_signature[..]],
        )?;
        tx.commit()?;
        store_sequence.write(unlocked.sequence)
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

    /// Every item's decrypted overview in a vault.
    pub fn overviews(&self, unlocked: &Unlocked, vault_id: &str) -> Result<Vec<Overview>> {
        let state = unlocked.vault(vault_id)?;
        let mut statement = self.conn.prepare(
            "SELECT item_id, item_version, overview FROM item WHERE vault_id = ?1 ORDER BY item_id",
        )?;
        let rows: Vec<(String, u64, Vec<u8>)> = statement
            .query_map([vault_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if rows.len() != state.items.len() {
            return Err(tampered("item count"));
        }
        rows.into_iter()
            .map(|(item_id, version, sealed)| {
                match state.items.get(&item_id) {
                    Some((v, ov, _)) if *v == version && *ov == h(&sealed) => {}
                    _ => return Err(tampered("item overview")),
                }
                let ad = item_ad(vault_id, state.generation, &item_id, "overview", version);
                let plaintext = open_item(&state.key, state.generation, &ad, &sealed)?;
                Ok(Overview {
                    item_id,
                    version,
                    plaintext,
                })
            })
            .collect()
    }

    /// One item's decrypted details, checked against the in-memory manifest (§7.4).
    pub fn details(
        &self,
        unlocked: &Unlocked,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let state = unlocked.vault(vault_id)?;
        let (version, _, expected) = state
            .items
            .get(item_id)
            .ok_or_else(|| Error(format!("No item with ID {item_id} in that vault")))?;
        let (stored_version, sealed): (u64, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT item_version, details FROM item WHERE vault_id = ?1 AND item_id = ?2",
                params![vault_id, item_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| tampered("missing item"))?;
        if stored_version != *version || h(&sealed) != *expected {
            return Err(tampered("item details"));
        }
        let ad = item_ad(vault_id, state.generation, item_id, "details", *version);
        open_item(&state.key, state.generation, &ad, &sealed)
    }

    /// Writes a new version of an item, keeping the previous details as history
    /// (§7.3). Returns the new version.
    pub fn put_item(
        &mut self,
        unlocked: &mut Unlocked,
        vault_id: &str,
        item_id: &str,
        overview: &[u8],
        details: &[u8],
    ) -> Result<u64> {
        let versions = self.put_items(
            unlocked,
            vault_id,
            &[Write {
                item_id,
                overview,
                details,
            }],
        )?;
        Ok(versions[0])
    }

    /// Writes several items to one vault in one transaction under one manifest
    /// signature. All or nothing. Returns each item's new version, in order.
    pub fn put_items(
        &mut self,
        unlocked: &mut Unlocked,
        vault_id: &str,
        writes: &[Write],
    ) -> Result<Vec<u64>> {
        let state = unlocked.vault(vault_id)?;
        let (key, generation) = (&state.key, state.generation);
        let mut items = state.items.clone();
        let mut history = state.history.clone();
        let tx = self.conn.transaction()?;
        let mut versions = Vec::with_capacity(writes.len());
        for write in writes {
            let item_id = write.item_id;
            let previous = items.get(item_id).copied();
            let version = previous.map_or(1, |(v, _, _)| v + 1);
            let sealed_overview = seal_item(
                key,
                generation,
                &item_ad(vault_id, generation, item_id, "overview", version),
                write.overview,
            );
            let sealed_details = seal_item(
                key,
                generation,
                &item_ad(vault_id, generation, item_id, "details", version),
                write.details,
            );
            if let Some((old_version, _, old_hash)) = previous {
                let old: Vec<u8> = tx
                    .query_row(
                        "SELECT details FROM item WHERE vault_id = ?1 AND item_id = ?2 AND item_version = ?3",
                        params![vault_id, item_id, old_version],
                        |r| r.get(0),
                    )
                    .map_err(|_| tampered("item being replaced"))?;
                if h(&old) != old_hash {
                    return Err(tampered("item being replaced"));
                }
                tx.execute(
                    "INSERT INTO history VALUES (?1, ?2, ?3, ?4)",
                    params![vault_id, item_id, old_version, old],
                )?;
                history.insert((item_id.to_string(), old_version), old_hash);
            }
            tx.execute(
                "INSERT OR REPLACE INTO item VALUES (?1, ?2, ?3, ?4, ?5)",
                params![vault_id, item_id, version, sealed_overview, sealed_details],
            )?;
            items.insert(
                item_id.to_string(),
                (version, h(&sealed_overview), h(&sealed_details)),
            );
            versions.push(version);
        }
        let state = unlocked.vaults.get_mut(vault_id).expect("checked above");
        let before_items = std::mem::replace(&mut state.items, items);
        let before_history = std::mem::replace(&mut state.history, history);
        let before_sequences = (state.sequence, unlocked.sequence);
        match Self::commit_with(&self.sequence_file, unlocked, vault_id, tx) {
            Ok(()) => Ok(versions),
            Err(e) => {
                unlocked.sequence = before_sequences.1;
                let state = unlocked.vaults.get_mut(vault_id).expect("checked above");
                state.items = before_items;
                state.history = before_history;
                state.sequence = before_sequences.0;
                Err(e)
            }
        }
    }
}

/// One item write for [`Store::put_items`].
pub struct Write<'a> {
    pub item_id: &'a str,
    pub overview: &'a [u8],
    pub details: &'a [u8],
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
